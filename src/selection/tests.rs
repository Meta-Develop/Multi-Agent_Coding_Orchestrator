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

fn base_input() -> SelectionInput {
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
        },
        debug_override: None,
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
    assert_eq!(decision.schema_version, 3);
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
fn built_in_data_is_dated_and_keeps_policy_in_data() {
    let priors = built_in_prior_dataset().expect("built-in priors");
    let _: &SelectorCalibration = &priors.objective_profiles[0];
    assert_eq!(priors.revision, "2026-08-26.1");
    assert_eq!(priors.published_on, "2026-08-26");
    assert_eq!(priors.schema_version, 2);
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

#[test]
fn configured_model_switch_cost_flips_stay_versus_switch() {
    let stay = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-sol".to_string(),
        effort: ReasoningEffort::High,
    };
    let switch = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-5.6-luna".to_string(),
        effort: ReasoningEffort::High,
    };

    let dominated = select(&codex_model_switch_input(40_000)).expect("dominating switch cost");
    assert_eq!(
        dominated.choice.as_ref().expect("stay choice").candidate,
        stay
    );
    let switch_runner_up = dominated
        .runner_up_scores
        .iter()
        .find(|score| score.candidate == switch)
        .expect("switch runner-up");
    assert_eq!(
        switch_runner_up.switch_transition,
        ContextSwitchTransition::ModelChangeSameRuntime
    );
    assert_eq!(switch_runner_up.configured_switch_cost_microunits, 40_000);
    assert!(switch_runner_up.switch_cost_microunits >= 40_000);

    for cost in [0, 20_000] {
        let decision = select(&codex_model_switch_input(cost)).expect("affordable switch");
        assert_eq!(
            decision.choice.as_ref().expect("switch choice").candidate,
            switch,
            "configured cost {cost} should stay below the candidate advantage"
        );
    }
}

#[test]
fn initial_stay_effort_model_and_runtime_transitions_are_typed_and_charged() {
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
    let model_quality = u128::from(model.posterior_quality_basis_points);
    let expected_model_switch_cost = u128::from(model.configured_switch_cost_microunits)
        .checked_mul(10_000)
        .and_then(|scaled| scaled.checked_add(model_quality.checked_sub(1)?))
        .expect("model switch normalization arithmetic")
        / model_quality;
    assert_eq!(
        u128::from(model.switch_cost_microunits),
        expected_model_switch_cost
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
    let runtime_quality = u128::from(runtime.posterior_quality_basis_points);
    let expected_runtime_switch_cost = u128::from(runtime.configured_switch_cost_microunits)
        .checked_mul(10_000)
        .and_then(|scaled| scaled.checked_add(runtime_quality.checked_sub(1)?))
        .expect("runtime switch normalization arithmetic")
        / runtime_quality;
    assert_eq!(
        u128::from(runtime.switch_cost_microunits),
        expected_runtime_switch_cost
    );
}

#[test]
fn zero_switch_cost_preserves_candidate_keyed_initial_total_scores_exactly() {
    let previous_choice = codex_model_switch_input(0);
    let mut initial = previous_choice.clone();
    initial.signals.previous_choice = None;

    let initial = select(&initial).expect("equivalent initial selection");
    let previous_choice = select(&previous_choice).expect("zero-cost previous-choice selection");
    assert_eq!(
        initial.candidate_set.len(),
        previous_choice.candidate_set.len()
    );

    for evaluation in &previous_choice.candidate_set {
        let previous_score = evaluation.score.as_ref().expect("previous-choice score");
        let initial_score = initial
            .candidate_set
            .iter()
            .find(|candidate| candidate.candidate == evaluation.candidate)
            .and_then(|candidate| candidate.score.as_ref())
            .expect("candidate-keyed initial score");
        assert_eq!(previous_score.configured_switch_cost_microunits, 0);
        assert_eq!(previous_score.switch_cost_microunits, 0);
        assert_eq!(initial_score.configured_switch_cost_microunits, 0);
        assert_eq!(initial_score.switch_cost_microunits, 0);
        assert_eq!(
            previous_score.total_score_microunits, initial_score.total_score_microunits,
            "candidate total changed despite a zero switch term: {:?}",
            evaluation.candidate
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
        selected.configured_switch_cost_microunits,
        selected_score.configured_switch_cost_microunits
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
        assert_eq!(
            runner_up.configured_switch_cost_microunits,
            score.configured_switch_cost_microunits
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
    assert_eq!(round_trip.schema_version, 3);
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
fn canonical_resolved_objective_switch_score_overflow_fails_closed() {
    let mut overflow = codex_model_switch_input(u64::MAX);
    let mut profile = crate::objective_profile::default_objective_profile();
    profile.switch_costs.model_change_same_runtime_microunits = u64::MAX;
    profile.switch_costs.runtime_change_microunits = u64::MAX;
    overflow.resolved_objective_profile = resolved_routing_profile(
        profile,
        crate::objective_profile::ObjectiveProfileSource::BuiltIn,
    );
    assert!(matches!(
        select(&overflow),
        Err(SelectionError::InvalidInput(message)) if message.contains("context-switch cost per accepted task overflowed")
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
    assert!(choice.switch_cost_microunits >= 10_000);

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
    assert_eq!(decoded.schema_version, 3);

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

#[test]
fn automatic_policy_and_bridge_contain_no_model_slug_constants() {
    let automatic_sources = [
        include_str!("selector.rs"),
        include_str!("../supervise/selection_bridge.rs"),
        include_str!("../optimizer/evaluation_fn.rs"),
        include_str!("../optimizer/seed_evidence.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("seed evidence production source"),
    ]
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
