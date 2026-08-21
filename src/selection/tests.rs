use std::collections::BTreeSet;

use super::*;

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
        entitlement_capacity_units: 100,
        entitlement_remaining_units: 100,
        pool_pressure_basis_points: pressure,
        observed_consumption_units: 0,
        marginal_cost_microunits: 0,
        observation_revision: format!("{runtime}-pool-r1"),
        admission_provenance: "deterministic fixture".to_string(),
        failover_provenance: None,
    }
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
        constraints: OperatorConstraints {
            allowed_runtimes: BTreeSet::new(),
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: false,
        },
        priors: built_in_prior_dataset().expect("built-in priors"),
        objective_profile: ObjectiveProfileRef {
            name: "accepted-task-total-cost".to_string(),
            version: 1,
            expected_digest: None,
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

#[test]
fn built_in_data_is_dated_and_keeps_policy_in_data() {
    let priors = built_in_prior_dataset().expect("built-in priors");
    assert_eq!(priors.published_on, "2026-08-21");
    assert!(priors.models.iter().any(|prior| prior.prohibited));
    assert!(priors
        .models
        .iter()
        .any(|prior| !prior.strong_gate_fallback_efforts.is_empty()));
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
}

#[test]
fn normalized_input_is_a_self_contained_replay_fixture() {
    let decision = select(&base_input()).expect("initial decision");
    let replay = select(&decision.normalized_input).expect("provenance replay");
    assert_eq!(replay, decision);
}

#[test]
fn automatic_policy_and_bridge_contain_no_model_slug_constants() {
    let automatic_sources = [
        include_str!("selector.rs"),
        include_str!("../supervise/selection_bridge.rs"),
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
