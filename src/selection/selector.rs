use std::{cmp::Ordering, collections::BTreeSet};

use crate::objective_profile::ObjectiveProfile as RoutingObjectiveProfile;
use serde::Serialize;

use crate::optimizer::quota_pools::{ConsumptionSource, ExhaustionBehavior};

use super::types::*;

const BUILT_IN_PRIORS: &str = include_str!("data/priors-2026-08-07.json");
const PRIOR_DATASET_SCHEMA_VERSION: u32 = 2;
const SELECTOR_CALIBRATION_VERSION: u32 = 3;
const SELECTION_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectionError {
    #[error("invalid selection input: {0}")]
    InvalidInput(String),
    #[error("selector data could not be decoded: {0}")]
    Data(String),
    #[error("selector input could not be normalized: {0}")]
    Serialization(String),
}

pub fn built_in_prior_dataset() -> Result<PriorDataset, SelectionError> {
    serde_json::from_str(BUILT_IN_PRIORS).map_err(|error| SelectionError::Data(error.to_string()))
}

/// Dated catalog/evidence eligibility for `model` under `authority`.
///
/// Unknown slugs return [`MeasuredAuthorityEligibility::NoDatedEvidence`] so a
/// static capability tier can still be used as fallback. Measured ineligibility
/// must fail closed and cannot be overridden by that table.
pub fn measured_authority_eligibility(
    model: &str,
    authority: AuthorityRole,
) -> Result<MeasuredAuthorityEligibility, SelectionError> {
    Ok(built_in_prior_dataset()?.measured_authority_eligibility(model, authority))
}

pub fn select(input: &SelectionInput) -> Result<SelectionProvenance, SelectionError> {
    let mut normalized = input.clone();
    normalize_input(&mut normalized);
    validate_input(&normalized)?;

    let calibration = normalized
        .priors
        .objective_profiles
        .iter()
        .find(|profile| {
            profile.name == normalized.objective_profile.name
                && profile.version == normalized.objective_profile.version
        })
        .ok_or_else(|| {
            SelectionError::InvalidInput(format!(
                "selector calibration '{}@{}' is absent from dataset '{}@{}'",
                normalized.objective_profile.name,
                normalized.objective_profile.version,
                normalized.priors.dataset_id,
                normalized.priors.revision
            ))
        })?;
    let input_digests = input_digests(&normalized)?;
    let profile_digest = digest(calibration)?;
    if normalized
        .objective_profile
        .expected_digest
        .as_ref()
        .is_some_and(|expected| expected != &profile_digest.value)
    {
        return Err(SelectionError::InvalidInput(format!(
            "selector calibration digest did not match calibration '{}@{}'",
            calibration.name, calibration.version
        )));
    }

    let mut candidate_set = Vec::new();
    for catalog in &normalized.catalogs {
        for model in &catalog.models {
            for effort in &model.supported_efforts {
                let candidate = CandidateKey {
                    runtime: catalog.runtime.clone(),
                    model: model.model.clone(),
                    effort: *effort,
                };
                candidate_set.push(evaluate_candidate(
                    &normalized,
                    calibration,
                    catalog,
                    model,
                    candidate,
                )?);
            }
        }
    }
    candidate_set.sort_by(|left, right| left.candidate.cmp(&right.candidate));

    let catalogs_digest = &input_digests.catalogs.value;
    let mut triggers = selection_triggers(&normalized, catalogs_digest);
    let quota_source = quota_source_pool(&normalized)?;
    let quota_exhausted = quota_source.is_some_and(|pool| pool.exhausted);
    if quota_exhausted {
        triggers.push(SelectionTrigger::QuotaExhaustion);
        triggers.sort();
        triggers.dedup();
    }
    let mut debug_override = None;
    let mut environment_fallback = None;
    let mut choice = None;
    let decision_reason;

    if quota_source.is_some_and(|pool| {
        pool.exhausted && pool.exhaustion_behavior == Some(ExhaustionBehavior::FailClosed)
    }) {
        if let Some(request) = &normalized.debug_override {
            debug_override = Some(DebugOverrideProvenance {
                request: request.clone(),
                disposition: DebugOverrideDisposition::Rejected,
                reason: "debug override cannot bypass configured quota fail-closed behavior"
                    .to_string(),
            });
        }
        decision_reason =
            "configured source quota pool is exhausted and requires fail-closed refusal"
                .to_string();
    } else if let Some(request) = &normalized.debug_override {
        let evaluation = candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == request.candidate);
        let applied = normalized.constraints.allow_debug_override
            && evaluation.is_some_and(|evaluation| evaluation.eligible);
        debug_override = Some(DebugOverrideProvenance {
            request: request.clone(),
            disposition: if applied {
                DebugOverrideDisposition::Applied
            } else {
                DebugOverrideDisposition::Rejected
            },
            reason: if !normalized.constraints.allow_debug_override {
                "operator constraints disable debug overrides".to_string()
            } else if evaluation.is_none() {
                "debug override is absent from the runtime-advertised candidate set".to_string()
            } else {
                "debug override failed one or more hard eligibility gates".to_string()
            },
        });
        if applied {
            let evaluation = evaluation.ok_or_else(|| {
                SelectionError::InvalidInput(
                    "eligible debug override disappeared during selection".to_string(),
                )
            })?;
            choice = Some(selected_choice(evaluation, ChoiceReason::DebugOverride)?);
            decision_reason =
                "eligible provenance-recorded debug override selected after all hard gates"
                    .to_string();
        } else {
            decision_reason =
                "debug override rejected; automatic fallback is forbidden for an explicit override"
                    .to_string();
        }
    } else if let Some((selected, transition)) =
        environment_fallback_choice(&normalized, &candidate_set)?
    {
        triggers.push(SelectionTrigger::EnvironmentFallback);
        triggers.sort();
        triggers.dedup();
        choice = Some(selected);
        environment_fallback = Some(transition);
        decision_reason =
            "one-shot data-declared environment fallback selected after an evidenced native rejection"
                .to_string();
    } else if let Some(mut selected) = automatic_choice(&normalized, &candidate_set)? {
        if quota_source.is_some_and(|pool| {
            pool.exhausted && pool.exhaustion_behavior == Some(ExhaustionBehavior::Degrade)
        }) {
            selected.reason = ChoiceReason::AuthorizedQuotaDegrade;
        }
        decision_reason = match selected.reason {
            ChoiceReason::StrongestNoEvidenceJudgmentFallback =>
                "no comparable exact judgment evidence was eligible; selected the strongest data-declared xhigh gate fallback"
                    .to_string(),
            ChoiceReason::AuthorizedQuotaDegrade =>
                "source quota pool is exhausted; selected the lowest-cost independently eligible operator-authorized alternative"
                    .to_string(),
            ChoiceReason::LowestLegacyBaselinePlusCostProxyAdjustments =>
                "selected the eligible runtime/model/effort candidate with the lowest legacy baseline plus explicit retry/rework and human-review cost-proxy adjustments"
                    .to_string(),
            _ =>
                "selected the eligible runtime/model/effort candidate with the lowest expected total cost per accepted task"
                    .to_string(),
        };
        choice = Some(selected);
    } else {
        decision_reason = if normalized
            .task
            .authority_role
            .requires_exact_judgment_evidence()
        {
            "no candidate satisfied fail-closed judgment authority and class-fit requirements"
                .to_string()
        } else {
            "no candidate satisfied runtime catalog, operator, task-fit, evidence, and pool gates"
                .to_string()
        };
    }

    let runner_up_scores = runner_ups(&candidate_set, choice.as_ref())?;
    let status = if choice.is_some() {
        DecisionStatus::Selected
    } else {
        DecisionStatus::FailClosed
    };
    let catalog_revisions = normalized
        .catalogs
        .iter()
        .map(|catalog| CatalogRevisionProvenance {
            runtime: catalog.runtime.clone(),
            revision: catalog.revision.clone(),
            advertised_at: catalog.advertised_at.clone(),
        })
        .collect();
    let quota = quota_decision_provenance(&normalized, &candidate_set, choice.as_ref())?;

    Ok(SelectionProvenance {
        schema_version: SELECTION_SCHEMA_VERSION,
        status,
        normalized_input: normalized.clone(),
        normalized_task: normalized.task,
        input_digests,
        objective_profile: SelectorCalibrationProvenance {
            dataset_id: normalized.priors.dataset_id,
            dataset_revision: normalized.priors.revision,
            dataset_published_on: normalized.priors.published_on,
            profile_name: calibration.name.clone(),
            profile_version: calibration.version,
            profile_effective_date: calibration.effective_date.clone(),
            profile_digest,
        },
        resolved_objective_profile: normalized.resolved_objective_profile.clone(),
        catalog_revisions,
        runtime_operations: normalized.pools,
        triggers,
        candidate_set,
        choice,
        runner_up_scores,
        decision_reason,
        debug_override,
        environment_fallback,
        quota,
    })
}

fn normalize_input(input: &mut SelectionInput) {
    input
        .catalogs
        .sort_by(|left, right| left.runtime.cmp(&right.runtime));
    for catalog in &mut input.catalogs {
        catalog
            .models
            .sort_by(|left, right| left.model.cmp(&right.model));
        for model in &mut catalog.models {
            // Runtime effort advertisements are set-valued capabilities. Canonicalizing repeated
            // tokens here keeps equivalent catalogs replay- and digest-identical.
            model.supported_efforts.sort();
            model.supported_efforts.dedup();
        }
    }
    input
        .pools
        .sort_by(|left, right| left.runtime.cmp(&right.runtime));
    for pool in &mut input.pools {
        pool.authorized_alternatives.sort();
        pool.authorized_alternatives.dedup();
    }
    input
        .priors
        .objective_profiles
        .sort_by(|left, right| (&left.name, left.version).cmp(&(&right.name, right.version)));
    input
        .priors
        .models
        .sort_by(|left, right| (&left.runtime, &left.model).cmp(&(&right.runtime, &right.model)));
    for prior in &mut input.priors.models {
        prior.class_fit.sort_by(|left, right| {
            (&left.task_class, left.effort).cmp(&(&right.task_class, right.effort))
        });
        prior.authority_evidence.sort_by(|left, right| {
            (&left.task_class, left.role, left.effort).cmp(&(
                &right.task_class,
                right.role,
                right.effort,
            ))
        });
        prior.one_shot_environment_fallbacks.sort_by(|left, right| {
            (
                &left.rejection_code,
                &left.target_runtime,
                &left.target_model,
                left.target_effort,
            )
                .cmp(&(
                    &right.rejection_code,
                    &right.target_runtime,
                    &right.target_model,
                    right.target_effort,
                ))
        });
        prior.limitations.sort();
        prior.limitations.dedup();
    }
    // A valid ledger has globally unique attempt IDs, so this is a total order over valid records.
    input
        .outcomes
        .sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
    input.signals.environment_rejections.sort_by(|left, right| {
        (&left.candidate, &left.rejection_code, &left.evidence_id).cmp(&(
            &right.candidate,
            &right.rejection_code,
            &right.evidence_id,
        ))
    });
}

fn validate_input(input: &SelectionInput) -> Result<(), SelectionError> {
    validate_identifier("task.task_class", &input.task.task_class)?;
    if input.task.risk == RiskLevel::Unknown {
        return invalid("task.risk must be known before candidate evaluation");
    }
    if input.task.boundedness == Boundedness::Unknown {
        return invalid("task.boundedness must be known before candidate evaluation");
    }
    if input.task.context == ContextSize::Unknown {
        return invalid("task.context must be known before candidate evaluation");
    }
    if input.task.horizon == TaskHorizon::Unknown {
        return invalid("task.horizon must be known before candidate evaluation");
    }
    validate_identifier("priors.dataset_id", &input.priors.dataset_id)?;
    validate_identifier("priors.revision", &input.priors.revision)?;
    if input.priors.schema_version != PRIOR_DATASET_SCHEMA_VERSION
        || input.objective_profile.version != SELECTOR_CALIBRATION_VERSION
    {
        return invalid(format!(
            "legacy selector wire is incompatible: expected prior schema {PRIOR_DATASET_SCHEMA_VERSION} and selector calibration {SELECTOR_CALIBRATION_VERSION}, got prior schema {} and selector calibration {}; calibration v2 embedded switch-cost objective semantics and cannot be safely replayed after the canonical resolved-objective split",
            input.priors.schema_version, input.objective_profile.version
        ));
    }
    validate_calendar_date("priors.published_on", &input.priors.published_on)?;
    validate_identifier("objective_profile.name", &input.objective_profile.name)?;
    if let Some(expected_digest) = &input.objective_profile.expected_digest {
        validate_sha256_digest("objective_profile.expected_digest", expected_digest)?;
    }
    validate_resolved_objective_profile(&input.resolved_objective_profile)?;
    if input.catalogs.is_empty() {
        return invalid("at least one runtime catalog is required");
    }
    if duplicate_by(&input.catalogs, |catalog| catalog.runtime.as_str()) {
        return invalid("runtime catalogs contain a duplicate runtime");
    }
    if duplicate_by(&input.pools, |pool| pool.runtime.as_str()) {
        return invalid("runtime pools contain a duplicate runtime");
    }
    for catalog in &input.catalogs {
        validate_identifier("catalog.runtime", &catalog.runtime)?;
        validate_identifier("catalog.revision", &catalog.revision)?;
        validate_identifier("catalog.advertised_at", &catalog.advertised_at)?;
        if duplicate_by(&catalog.models, |model| model.model.as_str()) {
            return invalid(format!(
                "runtime catalog '{}' contains a duplicate model",
                catalog.runtime
            ));
        }
        for model in &catalog.models {
            validate_identifier("catalog.model", &model.model)?;
            for task_class in &model.capabilities.task_classes {
                validate_identifier("catalog.capabilities.task_class", task_class)?;
            }
            if model
                .capabilities
                .boundedness
                .contains(&Boundedness::Unknown)
            {
                return invalid(format!(
                    "catalog model '{}:{}' capabilities.boundedness must not contain unknown",
                    catalog.runtime, model.model
                ));
            }
            if model.capabilities.maximum_risk == RiskLevel::Unknown {
                return invalid(format!(
                    "catalog model '{}:{}' capabilities.maximum_risk must be known",
                    catalog.runtime, model.model
                ));
            }
            if model.capabilities.maximum_context == ContextSize::Unknown {
                return invalid(format!(
                    "catalog model '{}:{}' capabilities.maximum_context must be known",
                    catalog.runtime, model.model
                ));
            }
            if model.capabilities.maximum_horizon == TaskHorizon::Unknown {
                return invalid(format!(
                    "catalog model '{}:{}' capabilities.maximum_horizon must be known",
                    catalog.runtime, model.model
                ));
            }
            if model.supported_efforts.is_empty() {
                return invalid(format!(
                    "catalog model '{}:{}' has no supported efforts",
                    catalog.runtime, model.model
                ));
            }
        }
    }
    for pool in &input.pools {
        validate_identifier("pool.runtime", &pool.runtime)?;
        validate_identifier("pool.observation_revision", &pool.observation_revision)?;
        validate_identifier("pool.admission_provenance", &pool.admission_provenance)?;
        if let Some(provenance) = &pool.failover_provenance {
            validate_identifier("pool.failover_provenance", provenance)?;
        }
        if pool.pool_pressure_basis_points > 10_000 {
            return invalid(format!(
                "pool '{}' pressure exceeds 10000 basis points",
                pool.runtime
            ));
        }
        if pool.entitlement_bounded
            && pool.entitlement_remaining_units > pool.entitlement_capacity_units
        {
            return invalid(format!(
                "pool '{}' remaining entitlement exceeds capacity",
                pool.runtime
            ));
        }
        if !pool.entitlement_bounded
            && (pool.entitlement_capacity_units != 0
                || pool.entitlement_remaining_units != 0
                || pool.exhausted)
        {
            return invalid(format!(
                "unbounded pool '{}' must use zero capacity/remaining units and cannot be exhausted",
                pool.runtime
            ));
        }
        let has_configured_field = pool.pool_reference.is_some()
            || pool.pool_kind.is_some()
            || pool.exhaustion_behavior.is_some()
            || pool.observation_source.is_some()
            || !pool.authorized_alternatives.is_empty();
        let has_complete_configured_fields = pool.pool_reference.is_some()
            && pool.pool_kind.is_some()
            && pool.exhaustion_behavior.is_some()
            && pool.observation_source.is_some();
        if has_configured_field && !has_complete_configured_fields {
            return invalid(format!(
                "configured quota pool '{}' is missing typed identity, kind, behavior, or observation source",
                pool.runtime
            ));
        }
        if let Some(reference) = &pool.pool_reference {
            if reference.runtime.as_str() != pool.runtime {
                return invalid(format!(
                    "quota pool '{}' runtime does not match its exact pool reference",
                    pool.runtime
                ));
            }
            if pool.observation_source != Some(ConsumptionSource::LocalObserved) {
                return invalid(format!(
                    "configured quota pool '{}' must use local observed consumption",
                    pool.runtime
                ));
            }
            if pool.entitlement_bounded {
                if pool.entitlement_capacity_units == 0 {
                    return invalid(format!(
                        "configured bounded quota pool '{}' must have positive capacity",
                        pool.runtime
                    ));
                }
                if pool.exhausted != (pool.entitlement_remaining_units == 0) {
                    return invalid(format!(
                        "configured quota pool '{}' exhaustion disagrees with remaining entitlement",
                        pool.runtime
                    ));
                }
            }
            match pool.exhaustion_behavior {
                Some(ExhaustionBehavior::FailClosed)
                    if !pool.authorized_alternatives.is_empty() =>
                {
                    return invalid(format!(
                        "fail-closed quota pool '{}' cannot authorize alternatives",
                        pool.runtime
                    ));
                }
                Some(ExhaustionBehavior::Degrade) if pool.authorized_alternatives.is_empty() => {
                    return invalid(format!(
                        "degrading quota pool '{}' requires an authorized alternative",
                        pool.runtime
                    ));
                }
                Some(ExhaustionBehavior::FailClosed | ExhaustionBehavior::Degrade) => {}
                None => {
                    return invalid(format!(
                        "configured quota pool '{}' is missing exhaustion behavior",
                        pool.runtime
                    ));
                }
            }
            if duplicate_semantic_key(&pool.authorized_alternatives, Clone::clone) {
                return invalid(format!(
                    "quota pool '{}' contains duplicate authorized alternatives",
                    pool.runtime
                ));
            }
            if pool
                .authorized_alternatives
                .iter()
                .any(|alternative| alternative == reference)
            {
                return invalid(format!(
                    "quota pool '{}' cannot authorize itself as an alternative",
                    pool.runtime
                ));
            }
        }
    }
    let configured_pools = input
        .pools
        .iter()
        .filter(|pool| pool.pool_reference.is_some())
        .collect::<Vec<_>>();
    match &input.quota_source {
        None if !configured_pools.is_empty() => {
            return invalid(
                "configured quota pools require an exact quota_source; catalog order is not authority",
            );
        }
        Some(source) => {
            let matches = configured_pools
                .iter()
                .filter(|pool| pool.pool_reference.as_ref() == Some(source))
                .count();
            if matches != 1 {
                return invalid(
                    "quota_source must exactly match one configured runtime pool reference",
                );
            }
            for pool in &configured_pools {
                for alternative in &pool.authorized_alternatives {
                    if !configured_pools
                        .iter()
                        .any(|candidate| candidate.pool_reference.as_ref() == Some(alternative))
                    {
                        return invalid(format!(
                            "quota pool '{}' authorizes an undeclared alternative",
                            pool.runtime
                        ));
                    }
                }
            }
        }
        None => {}
    }
    if duplicate_pair(&input.priors.models, |prior| {
        (prior.runtime.as_str(), prior.model.as_str())
    }) {
        return invalid("prior dataset contains a duplicate runtime/model entry");
    }
    if duplicate_semantic_key(&input.priors.objective_profiles, |profile| {
        (profile.name.clone(), profile.version)
    }) {
        return invalid("prior dataset contains a duplicate selector calibration name/version");
    }
    for profile in &input.priors.objective_profiles {
        validate_identifier("objective_profile.name", &profile.name)?;
        if profile.version != SELECTOR_CALIBRATION_VERSION {
            return invalid(format!(
                "selector calibration '{}@{}' is incompatible with calibration version {SELECTOR_CALIBRATION_VERSION}; calibration v2 embedded switch-cost objective semantics",
                profile.name, profile.version
            ));
        }
        validate_calendar_date("objective_profile.effective_date", &profile.effective_date)?;
        if profile.minimum_quality_basis_points > 10_000 {
            return invalid(format!(
                "selector calibration '{}@{}' quality bar exceeds 10000 basis points",
                profile.name, profile.version
            ));
        }
        if profile.minimum_class_fit_samples == 0 || profile.minimum_authority_samples == 0 {
            return invalid(format!(
                "selector calibration '{}@{}' requires nonzero evidence minima",
                profile.name, profile.version
            ));
        }
    }
    for prior in &input.priors.models {
        validate_identifier("prior.runtime", &prior.runtime)?;
        validate_identifier("prior.model", &prior.model)?;
        validate_calendar_date("prior.observed_on", &prior.observed_on)?;
        validate_identifier("prior.source_id", &prior.source_id)?;
        validate_identifier("prior.prior_scope", &prior.prior_scope)?;
        if let Some(reason) = &prior.prohibition_reason {
            validate_identifier("prior.prohibition_reason", reason)?;
        }
        if duplicate_semantic_key(&prior.class_fit, |class_fit| {
            (class_fit.task_class.clone(), class_fit.effort)
        }) {
            return invalid(format!(
                "prior '{}:{}' contains duplicate task-class/effort evidence",
                prior.runtime, prior.model
            ));
        }
        if duplicate_semantic_key(&prior.authority_evidence, |evidence| {
            (evidence.task_class.clone(), evidence.role, evidence.effort)
        }) {
            return invalid(format!(
                "prior '{}:{}' contains duplicate task-class/authority/effort evidence",
                prior.runtime, prior.model
            ));
        }
        if duplicate_semantic_key(&prior.one_shot_environment_fallbacks, |fallback| {
            fallback.rejection_code.clone()
        }) {
            return invalid(format!(
                "prior '{}:{}' contains duplicate environment fallback rejection codes",
                prior.runtime, prior.model
            ));
        }
        for class_fit in &prior.class_fit {
            validate_identifier("class_fit.task_class", &class_fit.task_class)?;
            if class_fit.quality_basis_points > 10_000 {
                return invalid(format!(
                    "class-fit prior '{}:{}' quality exceeds 10000 basis points",
                    prior.runtime, prior.model
                ));
            }
        }
        for authority in &prior.authority_evidence {
            validate_identifier("authority_evidence.task_class", &authority.task_class)?;
            if authority.quality_basis_points > 10_000 {
                return invalid(format!(
                    "authority prior '{}:{}' quality exceeds 10000 basis points",
                    prior.runtime, prior.model
                ));
            }
        }
        for fallback in &prior.one_shot_environment_fallbacks {
            validate_identifier(
                "environment_fallback.rejection_code",
                &fallback.rejection_code,
            )?;
            validate_identifier(
                "environment_fallback.target_runtime",
                &fallback.target_runtime,
            )?;
            validate_identifier("environment_fallback.target_model", &fallback.target_model)?;
        }
    }
    for candidate in &input.constraints.forbidden_candidates {
        validate_candidate_key("constraints.forbidden_candidate", candidate)?;
    }
    for outcome in &input.outcomes {
        validate_identifier("outcome.attempt_id", &outcome.attempt_id)?;
        validate_task_profile("outcome.task", &outcome.task)?;
        validate_candidate_key("outcome.candidate", &outcome.candidate)?;
        for failure in &outcome.environment_failures {
            validate_identifier("outcome.environment_failure.code", &failure.code)?;
            validate_identifier(
                "outcome.environment_failure.evidence_id",
                &failure.evidence_id,
            )?;
        }
        if let Some(relaunch) = &outcome.fixed_cause_relaunch {
            validate_identifier(
                "outcome.fixed_cause_relaunch.proven_failure_cause",
                &relaunch.proven_failure_cause,
            )?;
            validate_identifier(
                "outcome.fixed_cause_relaunch.exact_corrective_change",
                &relaunch.exact_corrective_change,
            )?;
            validate_identifier(
                "outcome.fixed_cause_relaunch.same_cause_fix_verification",
                &relaunch.same_cause_fix_verification,
            )?;
        }
    }
    if duplicate_by(&input.outcomes, |outcome| outcome.attempt_id.as_str()) {
        return invalid("outcome ledger contains a duplicate attempt_id");
    }
    if duplicate_semantic_key(&input.signals.environment_rejections, |rejection| {
        (
            rejection.candidate.clone(),
            rejection.rejection_code.clone(),
        )
    }) {
        return invalid("dynamic signals contain duplicate candidate/rejection-code evidence");
    }
    if let Some(previous_choice) = &input.signals.previous_choice {
        validate_candidate_key("signals.previous_choice", previous_choice)?;
    }
    if let Some(previous_digest) = &input.signals.previous_catalog_digest {
        validate_sha256_digest("signals.previous_catalog_digest", previous_digest)?;
    }
    for rejection in &input.signals.environment_rejections {
        validate_candidate_key(
            "signals.environment_rejection.candidate",
            &rejection.candidate,
        )?;
        validate_identifier(
            "signals.environment_rejection.rejection_code",
            &rejection.rejection_code,
        )?;
        validate_identifier(
            "signals.environment_rejection.evidence_id",
            &rejection.evidence_id,
        )?;
    }
    if let Some(debug_override) = &input.debug_override {
        validate_candidate_key("debug_override.candidate", &debug_override.candidate)?;
        validate_identifier("debug_override.requested_by", &debug_override.requested_by)?;
        validate_identifier("debug_override.reason", &debug_override.reason)?;
    }
    Ok(())
}

fn evaluate_candidate(
    input: &SelectionInput,
    profile: &SelectorCalibration,
    _catalog: &RuntimeCatalog,
    model: &CatalogModel,
    candidate: CandidateKey,
) -> Result<CandidateEvaluation, SelectionError> {
    let prior = input
        .priors
        .models
        .iter()
        .find(|prior| prior.runtime == candidate.runtime && prior.model == candidate.model);
    let pool = input
        .pools
        .iter()
        .find(|pool| pool.runtime == candidate.runtime);
    let quota = quota_candidate_provenance(input, &candidate)?;
    let ledger = ledger_summary(input, &candidate)?;
    let mut reasons = Vec::new();

    if !model.available {
        reject(
            &mut reasons,
            IneligibilityCode::CatalogUnavailable,
            "runtime catalog marks the model unavailable",
        );
    }
    let runtime_allowed = input.constraints.allowed_runtimes.is_empty()
        || input
            .constraints
            .allowed_runtimes
            .contains(&candidate.runtime);
    let model_allowed = input.constraints.allowed_models.is_empty()
        || input.constraints.allowed_models.contains(&candidate.model);
    if !runtime_allowed
        || !model_allowed
        || input
            .constraints
            .forbidden_runtimes
            .contains(&candidate.runtime)
        || input
            .constraints
            .forbidden_models
            .contains(&candidate.model)
        || input.constraints.forbidden_candidates.contains(&candidate)
    {
        reject(
            &mut reasons,
            IneligibilityCode::OperatorConstraint,
            "operator constraints exclude the candidate",
        );
    }
    match pool {
        None => reject(
            &mut reasons,
            IneligibilityCode::RuntimeAdmissionClosed,
            "runtime has no pool descriptor",
        ),
        Some(pool) if !pool.admission_open => reject(
            &mut reasons,
            IneligibilityCode::RuntimeAdmissionClosed,
            "runtime pool admission is closed",
        ),
        Some(pool)
            if pool.exhausted
                || (pool.pool_reference.is_none()
                    && pool.entitlement_bounded
                    && pool.entitlement_remaining_units == 0) =>
        {
            reject(
                &mut reasons,
                IneligibilityCode::EntitlementExhausted,
                "runtime pool entitlement is exhausted",
            )
        }
        Some(_) => {}
    }
    match quota.disposition {
        QuotaCandidateDisposition::FailClosed => reject(
            &mut reasons,
            IneligibilityCode::QuotaFailClosed,
            "configured exhausted source pool requires fail-closed refusal",
        ),
        QuotaCandidateDisposition::RejectedUnauthorizedAlternative => reject(
            &mut reasons,
            IneligibilityCode::QuotaAlternativeNotAuthorized,
            "candidate is not an exact operator-authorized alternative for the exhausted source pool",
        ),
        QuotaCandidateDisposition::LegacyUnconfigured
        | QuotaCandidateDisposition::SourceAvailable
        | QuotaCandidateDisposition::SourceExhausted
        | QuotaCandidateDisposition::AuthorizedAlternative => {}
    }
    if !model
        .capabilities
        .task_classes
        .contains(&input.task.task_class)
    {
        reject(
            &mut reasons,
            IneligibilityCode::TaskClassNotAdvertised,
            "task class is absent from advertised capabilities",
        );
    }
    if input.task.authority_role == AuthorityRole::UnknownJudgment {
        reject(
            &mut reasons,
            IneligibilityCode::UnknownJudgmentAuthority,
            "unknown judgment authority is never eligible for evidence fallback",
        );
    }
    if !model
        .capabilities
        .boundedness
        .contains(&input.task.boundedness)
        || input.task.risk > model.capabilities.maximum_risk
        || input.task.context > model.capabilities.maximum_context
        || input.task.horizon > model.capabilities.maximum_horizon
    {
        reject(
            &mut reasons,
            IneligibilityCode::TaskShapeNotAdvertised,
            "task shape exceeds advertised capability bounds",
        );
    }
    if input.task.context == ContextSize::Long && !model.capabilities.long_context {
        reject(
            &mut reasons,
            IneligibilityCode::LongContextProhibited,
            "candidate is not eligible for long context",
        );
    }
    if !model
        .capabilities
        .authority_roles
        .contains(&input.task.authority_role)
    {
        reject(
            &mut reasons,
            IneligibilityCode::AuthorityNotAdvertised,
            "required authority role is absent from advertised capabilities",
        );
    }
    if input
        .signals
        .environment_rejections
        .iter()
        .any(|rejection| rejection.candidate == candidate)
    {
        reject(
            &mut reasons,
            IneligibilityCode::EnvironmentRejected,
            "candidate has an evidenced environment rejection for this decision state",
        );
    }

    let mut strong_gate_fallback = false;
    let mut posterior_quality = 0u16;
    let mut authority_quality = None;
    let mut expected_cost = 0u64;
    let mut expected_retry_rework_cost = 0u64;
    let mut expected_human_review_cost = 0u64;
    let mut strength_rank = 0u16;
    match prior {
        None => reject(
            &mut reasons,
            IneligibilityCode::MissingDatedPrior,
            "candidate has no dated capability and benchmark prior",
        ),
        Some(prior) => {
            strength_rank = prior.strength_rank;
            if prior.prohibited
                || prior
                    .prohibited_authority_roles
                    .contains(&input.task.authority_role)
            {
                reject(
                    &mut reasons,
                    IneligibilityCode::PolicyProhibited,
                    prior.prohibition_reason.as_deref().unwrap_or(
                        "dated policy data prohibits this candidate for the requested authority",
                    ),
                );
            }
            if input.task.context == ContextSize::Long && !prior.long_context_eligible {
                reject(
                    &mut reasons,
                    IneligibilityCode::LongContextProhibited,
                    "dated prior does not establish long-context eligibility",
                );
            }
            let class_fit = prior.class_fit.iter().find(|class_fit| {
                class_fit.task_class == input.task.task_class
                    && class_fit.effort == candidate.effort
            });
            match class_fit {
                None => reject(
                    &mut reasons,
                    IneligibilityCode::MissingClassFitEvidence,
                    "no exact task-class and effort prior exists",
                ),
                Some(class_fit) => {
                    if class_fit.sample_size < profile.minimum_class_fit_samples {
                        reject(
                            &mut reasons,
                            IneligibilityCode::ClassFitEvidenceInsufficient,
                            "class-fit sample count is below the selector calibration minimum",
                        );
                    }
                    posterior_quality = posterior_quality_basis_points(class_fit, &ledger)?;
                    if posterior_quality < profile.minimum_quality_basis_points {
                        reject(
                            &mut reasons,
                            IneligibilityCode::QualityBarNotMet,
                            "posterior class-fit quality is below the hard quality bar",
                        );
                    }
                    expected_cost = expected_cost_per_accepted(class_fit, &ledger)?;
                    expected_retry_rework_cost = expected_cost_component_per_accepted(
                        class_fit.rework_cost_microunits,
                        ledger.rework_cost_microunits,
                        class_fit,
                        &ledger,
                        "expected retry/rework cost per accepted task",
                    )?;
                    let prior_human_review_cost = checked_sum_costs(
                        [
                            class_fit.review_cost_microunits,
                            class_fit.rereview_cost_microunits,
                        ],
                        "prior human-review cost",
                    )?;
                    let observed_human_review_cost = checked_sum_costs(
                        [
                            ledger.review_cost_microunits,
                            ledger.rereview_cost_microunits,
                        ],
                        "observed human-review cost",
                    )?;
                    expected_human_review_cost = expected_cost_component_per_accepted(
                        prior_human_review_cost,
                        observed_human_review_cost,
                        class_fit,
                        &ledger,
                        "expected human-review cost per accepted task",
                    )?;
                }
            }
            if input.task.authority_role.requires_exact_judgment_evidence()
                && input.task.authority_role != AuthorityRole::UnknownJudgment
            {
                let evidence = prior.authority_evidence.iter().find(|evidence| {
                    evidence.task_class == input.task.task_class
                        && evidence.role == input.task.authority_role
                        && evidence.effort == candidate.effort
                });
                strong_gate_fallback = evidence.is_none()
                    && candidate.effort == ReasoningEffort::Xhigh
                    && prior
                        .strong_gate_fallback_efforts
                        .contains(&candidate.effort)
                    && !prior
                        .prohibited_authority_roles
                        .contains(&input.task.authority_role);
                match evidence {
                    Some(evidence) => {
                        authority_quality = Some(evidence.quality_basis_points);
                        if evidence.sample_size < profile.minimum_authority_samples {
                            reject(
                                &mut reasons,
                                IneligibilityCode::AuthorityEvidenceInsufficient,
                                "authority sample count is below the selector calibration minimum",
                            );
                        }
                        if evidence.quality_basis_points < profile.minimum_quality_basis_points {
                            reject(
                                &mut reasons,
                                IneligibilityCode::AuthorityQualityBarNotMet,
                                "authority quality is below the hard quality bar",
                            );
                        }
                    }
                    None if !strong_gate_fallback => {
                        reject(&mut reasons, IneligibilityCode::MissingAuthorityEvidence, "no exact authority evidence or data-declared strong-gate fallback exists");
                        reject(
                            &mut reasons,
                            IneligibilityCode::UnknownJudgmentAuthority,
                            "judgment authority is unknown and therefore fails closed",
                        );
                    }
                    None => {}
                }
            }
        }
    }

    let score = if reasons.is_empty() {
        pool.map(|pool| {
            score_candidate(CandidateScoringInput {
                profile,
                routing_weights: &input.resolved_objective_profile.profile.tradeoffs,
                switch_costs: &input.resolved_objective_profile.profile.switch_costs,
                pool,
                candidate: &candidate,
                signals: &input.signals,
                posterior_quality_basis_points: posterior_quality,
                authority_quality_basis_points: authority_quality,
                expected_total_cost_per_accepted_task_microunits: expected_cost,
                expected_retry_rework_cost_per_accepted_task_microunits: expected_retry_rework_cost,
                expected_human_review_cost_per_accepted_task_microunits: expected_human_review_cost,
            })
        })
        .transpose()?
    } else {
        None
    };
    let _ = strength_rank;
    Ok(CandidateEvaluation {
        candidate,
        prior_source_id: prior.map(|prior| prior.source_id.clone()),
        prior_observed_on: prior.map(|prior| prior.observed_on.clone()),
        prior_scope: prior.map(|prior| prior.prior_scope.clone()),
        prior_limitations: prior
            .map(|prior| prior.limitations.clone())
            .unwrap_or_default(),
        strong_gate_fallback,
        eligible: reasons.is_empty() && score.is_some(),
        ineligibility_reasons: reasons,
        quota,
        ledger,
        score,
    })
}

fn quota_source_pool(input: &SelectionInput) -> Result<Option<&RuntimePoolState>, SelectionError> {
    let Some(source) = input.quota_source.as_ref() else {
        return Ok(None);
    };
    input
        .pools
        .iter()
        .find(|pool| pool.pool_reference.as_ref() == Some(source))
        .map(Some)
        .ok_or_else(|| {
            SelectionError::InvalidInput(
                "quota_source disappeared after validated input normalization".to_string(),
            )
        })
}

fn quota_candidate_provenance(
    input: &SelectionInput,
    candidate: &CandidateKey,
) -> Result<QuotaCandidateProvenance, SelectionError> {
    let target = input
        .pools
        .iter()
        .find(|pool| pool.runtime == candidate.runtime);
    let target_pool = target.and_then(|pool| pool.pool_reference.clone());
    let target_marginal_cost_microunits = target.map(|pool| pool.marginal_cost_microunits);
    let Some(source) = quota_source_pool(input)? else {
        return Ok(QuotaCandidateProvenance {
            source_pool: None,
            target_pool,
            source_exhausted: false,
            configured_behavior: None,
            authorized_alternative: false,
            disposition: QuotaCandidateDisposition::LegacyUnconfigured,
            source_observation_revision: None,
            source_observation: None,
            target_marginal_cost_microunits,
            reason: "no operator quota source was declared; legacy selector behavior applies"
                .to_string(),
        });
    };
    let source_pool = source.pool_reference.clone().ok_or_else(|| {
        SelectionError::InvalidInput("configured quota source has no pool reference".to_string())
    })?;
    let behavior = source.exhaustion_behavior.ok_or_else(|| {
        SelectionError::InvalidInput(
            "configured quota source has no exhaustion behavior".to_string(),
        )
    })?;
    let (authorized_alternative, disposition, reason) = if !source.exhausted {
        (
            false,
            QuotaCandidateDisposition::SourceAvailable,
            "configured source pool is available; exhaustion routing is inactive".to_string(),
        )
    } else {
        match behavior {
            ExhaustionBehavior::FailClosed => (
                false,
                QuotaCandidateDisposition::FailClosed,
                "configured source pool is exhausted and fail-closed behavior forbids every target"
                    .to_string(),
            ),
            ExhaustionBehavior::Degrade if target_pool.as_ref() == Some(&source_pool) => (
                false,
                QuotaCandidateDisposition::SourceExhausted,
                "source candidate belongs to the exhausted pool".to_string(),
            ),
            ExhaustionBehavior::Degrade
                if target_pool
                    .as_ref()
                    .is_some_and(|target| source.authorized_alternatives.contains(target)) =>
            {
                (
                    true,
                    QuotaCandidateDisposition::AuthorizedAlternative,
                    "target pool exactly matches an operator-authorized alternative; independent hard gates still apply"
                        .to_string(),
                )
            }
            ExhaustionBehavior::Degrade => (
                false,
                QuotaCandidateDisposition::RejectedUnauthorizedAlternative,
                "target pool does not exactly match an operator-authorized alternative"
                    .to_string(),
            ),
        }
    };
    Ok(QuotaCandidateProvenance {
        source_pool: Some(source_pool),
        target_pool,
        source_exhausted: source.exhausted,
        configured_behavior: Some(behavior),
        authorized_alternative,
        disposition,
        source_observation_revision: Some(source.observation_revision.clone()),
        source_observation: source.observation_source,
        target_marginal_cost_microunits,
        reason,
    })
}

fn quota_decision_provenance(
    input: &SelectionInput,
    candidates: &[CandidateEvaluation],
    choice: Option<&SelectedChoice>,
) -> Result<Option<QuotaDecisionProvenance>, SelectionError> {
    let Some(source) = quota_source_pool(input)? else {
        return Ok(None);
    };
    let source_pool = source.pool_reference.clone().ok_or_else(|| {
        SelectionError::InvalidInput("configured quota source has no pool reference".to_string())
    })?;
    let configured_behavior = source.exhaustion_behavior.ok_or_else(|| {
        SelectionError::InvalidInput(
            "configured quota source has no exhaustion behavior".to_string(),
        )
    })?;
    let observation_source = source.observation_source.ok_or_else(|| {
        SelectionError::InvalidInput(
            "configured quota source has no observation source".to_string(),
        )
    })?;

    let mut eligible_alternatives = Vec::new();
    let mut rejected_alternatives = Vec::new();
    if source.exhausted {
        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.candidate.runtime != source.runtime)
        {
            if candidate.quota.authorized_alternative && candidate.eligible {
                eligible_alternatives.push(candidate.candidate.clone());
            } else {
                rejected_alternatives.push(RejectedQuotaAlternative {
                    candidate: candidate.candidate.clone(),
                    reasons: candidate.ineligibility_reasons.clone(),
                });
            }
        }
    }
    eligible_alternatives.sort();
    rejected_alternatives.sort_by(|left, right| left.candidate.cmp(&right.candidate));

    let selected_alternative = choice
        .filter(|choice| choice.candidate.runtime != source.runtime)
        .map(|choice| choice.candidate.clone());
    if source.exhausted
        && configured_behavior == ExhaustionBehavior::Degrade
        && selected_alternative.as_ref().is_some_and(|selected| {
            !candidates.iter().any(|candidate| {
                candidate.candidate == *selected
                    && candidate.eligible
                    && candidate.quota.authorized_alternative
            })
        })
    {
        return invalid("quota degradation selected a target without exact authorization");
    }
    let (disposition, reason) = if !source.exhausted {
        (
            QuotaDecisionDisposition::SourceAvailable,
            "configured source pool remains available; ordinary selection applies".to_string(),
        )
    } else {
        match (
            configured_behavior,
            selected_alternative.is_some(),
            !eligible_alternatives.is_empty(),
            input.debug_override.is_some(),
        ) {
            (ExhaustionBehavior::FailClosed, _, _, _) => (
                QuotaDecisionDisposition::FailClosed,
                "configured fail-closed behavior refused the decision without considering unrelated alternatives"
                    .to_string(),
            ),
            (ExhaustionBehavior::Degrade, true, _, _) => (
                QuotaDecisionDisposition::Degraded,
                "selected an exact operator-authorized alternative that independently passed every hard gate"
                    .to_string(),
            ),
            (ExhaustionBehavior::Degrade, false, true, true) => (
                QuotaDecisionDisposition::RefusedByExplicitOverride,
                "an explicit debug override targeted an unauthorized or otherwise ineligible candidate; automatic fallback remained forbidden"
                    .to_string(),
            ),
            (ExhaustionBehavior::Degrade, false, _, _) => (
                QuotaDecisionDisposition::RefusedNoEligibleAlternative,
                "no exact operator-authorized alternative independently passed every hard gate"
                    .to_string(),
            ),
        }
    };

    Ok(Some(QuotaDecisionProvenance {
        source_pool,
        configured_behavior,
        source_exhausted: source.exhausted,
        local_observation_revision: source.observation_revision.clone(),
        observation_source,
        marginal_cost_assumption_microunits: source.marginal_cost_microunits,
        authorized_alternatives: source.authorized_alternatives.clone(),
        eligible_alternatives,
        rejected_alternatives,
        selected_alternative,
        disposition,
        reason,
    }))
}

struct CandidateScoringInput<'a> {
    profile: &'a SelectorCalibration,
    routing_weights: &'a crate::objective_profile::TradeoffWeights,
    switch_costs: &'a ContextSwitchCosts,
    pool: &'a RuntimePoolState,
    candidate: &'a CandidateKey,
    signals: &'a DynamicSignals,
    posterior_quality_basis_points: u16,
    authority_quality_basis_points: Option<u16>,
    expected_total_cost_per_accepted_task_microunits: u64,
    expected_retry_rework_cost_per_accepted_task_microunits: u64,
    expected_human_review_cost_per_accepted_task_microunits: u64,
}

fn score_candidate(input: CandidateScoringInput<'_>) -> Result<ScoreBreakdown, SelectionError> {
    let CandidateScoringInput {
        profile,
        routing_weights,
        switch_costs,
        pool,
        candidate,
        signals,
        posterior_quality_basis_points,
        authority_quality_basis_points,
        expected_total_cost_per_accepted_task_microunits,
        expected_retry_rework_cost_per_accepted_task_microunits,
        expected_human_review_cost_per_accepted_task_microunits,
    } = input;
    let pool_pressure_cost_microunits = normalize_cost_per_accepted(
        scale_basis_points(
            profile.pool_pressure_full_cost_microunits,
            pool.pool_pressure_basis_points,
            "pool-pressure score",
        )?,
        posterior_quality_basis_points,
        "pool-pressure cost per accepted task",
    )?;
    let entitlement_scarcity_bp = if !pool.entitlement_bounded {
        0
    } else if pool.entitlement_capacity_units == 0 {
        10_000
    } else {
        let used = pool
            .entitlement_capacity_units
            .checked_sub(pool.entitlement_remaining_units)
            .ok_or_else(|| {
                SelectionError::InvalidInput(
                    "remaining entitlement exceeds capacity while scoring".to_string(),
                )
            })?;
        ((u128::from(used) * 10_000) / u128::from(pool.entitlement_capacity_units)).min(10_000)
            as u16
    };
    let entitlement_scarcity_cost_microunits = normalize_cost_per_accepted(
        scale_basis_points(
            profile.entitlement_scarcity_full_cost_microunits,
            entitlement_scarcity_bp,
            "entitlement-scarcity score",
        )?,
        posterior_quality_basis_points,
        "entitlement-scarcity cost per accepted task",
    )?;
    let observed_consumption_cost_microunits = normalize_cost_per_accepted(
        u128_to_u64(
            u128::from(pool.observed_consumption_units)
                * u128::from(profile.observed_consumption_unit_cost_microunits),
            "observed-consumption score",
        )?,
        posterior_quality_basis_points,
        "observed-consumption cost per accepted task",
    )?;
    let marginal_cost_microunits = normalize_cost_per_accepted(
        pool.marginal_cost_microunits,
        posterior_quality_basis_points,
        "marginal cost per accepted task",
    )?;
    let retry_cost_microunits = if signals.previous_choice.as_ref() == Some(candidate) {
        normalize_cost_per_accepted(
            u128_to_u64(
                u128::from(signals.retry_count) * u128::from(profile.retry_penalty_microunits),
                "retry score",
            )?,
            posterior_quality_basis_points,
            "retry cost per accepted task",
        )?
    } else {
        0
    };
    let degrade_cost_microunits = if signals.budget_signal == BudgetSignal::Degrade {
        normalize_cost_per_accepted(
            u128_to_u64(
                u128::from(candidate.effort.rank())
                    * u128::from(profile.degrade_effort_rank_penalty_microunits),
                "budget-degrade score",
            )?,
            posterior_quality_basis_points,
            "budget-degrade cost per accepted task",
        )?
    } else {
        0
    };
    let switch_transition = context_switch_transition(signals.previous_choice.as_ref(), candidate);
    let configured_switch_cost_microunits = match switch_transition {
        ContextSwitchTransition::Initial
        | ContextSwitchTransition::Stay
        | ContextSwitchTransition::EffortChangeSameRuntimeModel => 0,
        ContextSwitchTransition::ModelChangeSameRuntime => {
            switch_costs.model_change_same_runtime_microunits
        }
        ContextSwitchTransition::RuntimeChange => switch_costs.runtime_change_microunits,
    };
    let switch_cost_microunits = normalize_cost_per_accepted(
        configured_switch_cost_microunits,
        posterior_quality_basis_points,
        "context-switch cost per accepted task",
    )?;
    let legacy_baseline_score_microunits = checked_sum_costs(
        [
            expected_total_cost_per_accepted_task_microunits,
            pool_pressure_cost_microunits,
            entitlement_scarcity_cost_microunits,
            observed_consumption_cost_microunits,
            marginal_cost_microunits,
            retry_cost_microunits,
            degrade_cost_microunits,
            switch_cost_microunits,
        ],
        "total candidate score",
    )?;
    let retry_rework_cost_proxy_microunits = checked_sum_costs(
        [
            expected_retry_rework_cost_per_accepted_task_microunits,
            retry_cost_microunits,
        ],
        "retry/rework cost proxy",
    )?;
    let human_review_cost_proxy_microunits =
        expected_human_review_cost_per_accepted_task_microunits;
    let retry_rework_adjustment_microunits = proportional_cost_proxy_adjustment(
        retry_rework_cost_proxy_microunits,
        routing_weights.retry_rework_percent,
        routing_weights.monetary_cost_percent,
        "retry/rework cost-proxy adjustment",
    )?;
    let human_review_adjustment_microunits = proportional_cost_proxy_adjustment(
        human_review_cost_proxy_microunits,
        routing_weights.human_review_percent,
        routing_weights.monetary_cost_percent,
        "human-review cost-proxy adjustment",
    )?;
    let total_adjustment_microunits = checked_sum_costs(
        [
            retry_rework_adjustment_microunits,
            human_review_adjustment_microunits,
        ],
        "total cost-proxy adjustment",
    )?;
    let total_score_microunits = checked_sum_costs(
        [
            legacy_baseline_score_microunits,
            total_adjustment_microunits,
        ],
        "legacy baseline plus cost-proxy adjustments",
    )?;
    Ok(ScoreBreakdown {
        posterior_quality_basis_points,
        authority_quality_basis_points,
        expected_total_cost_per_accepted_task_microunits,
        pool_pressure_cost_microunits,
        entitlement_scarcity_cost_microunits,
        observed_consumption_cost_microunits,
        marginal_cost_microunits,
        retry_cost_microunits,
        degrade_cost_microunits,
        switch_transition,
        configured_switch_cost_microunits,
        switch_cost_microunits,
        routing_score_semantics: RoutingScoreSemantics::LegacyBaselinePlusCostProxyAdjustmentsV1,
        routing_tradeoff_weights: routing_weights.clone(),
        legacy_baseline_score_microunits,
        retry_rework_cost_proxy_microunits,
        human_review_cost_proxy_microunits,
        retry_rework_adjustment_microunits,
        human_review_adjustment_microunits,
        total_adjustment_microunits,
        total_score_microunits,
    })
}

fn context_switch_transition(
    previous: Option<&CandidateKey>,
    candidate: &CandidateKey,
) -> ContextSwitchTransition {
    let Some(previous) = previous else {
        return ContextSwitchTransition::Initial;
    };
    if previous.runtime != candidate.runtime {
        ContextSwitchTransition::RuntimeChange
    } else if previous.model != candidate.model {
        ContextSwitchTransition::ModelChangeSameRuntime
    } else if previous.effort != candidate.effort {
        ContextSwitchTransition::EffortChangeSameRuntimeModel
    } else {
        ContextSwitchTransition::Stay
    }
}

fn automatic_choice(
    input: &SelectionInput,
    candidates: &[CandidateEvaluation],
) -> Result<Option<SelectedChoice>, SelectionError> {
    let eligible = candidates.iter().filter(|candidate| candidate.eligible);
    if input.task.authority_role.requires_exact_judgment_evidence() {
        if let Some(candidate) = eligible
            .clone()
            .filter(|candidate| !candidate.strong_gate_fallback)
            .min_by(candidate_score_order)
        {
            return selected_choice(candidate, automatic_score_choice_reason(input)).map(Some);
        }
        if let Some(candidate) = eligible
            .filter(|candidate| candidate.strong_gate_fallback)
            .max_by(|left, right| {
                prior_strength(input, left)
                    .cmp(&prior_strength(input, right))
                    .then_with(|| right.candidate.cmp(&left.candidate))
            })
        {
            return selected_choice(candidate, ChoiceReason::StrongestNoEvidenceJudgmentFallback)
                .map(Some);
        }
        return Ok(None);
    }
    eligible
        .min_by(candidate_score_order)
        .map(|candidate| selected_choice(candidate, automatic_score_choice_reason(input)))
        .transpose()
}

fn automatic_score_choice_reason(input: &SelectionInput) -> ChoiceReason {
    let weights = &input.resolved_objective_profile.profile.tradeoffs;
    if weights.monetary_cost_percent == 100
        && weights.quota_consumption_percent == 0
        && weights.latency_percent == 0
        && weights.retry_rework_percent == 0
        && weights.human_review_percent == 0
    {
        ChoiceReason::LowestExpectedTotalCostPerAcceptedTask
    } else {
        ChoiceReason::LowestLegacyBaselinePlusCostProxyAdjustments
    }
}

fn environment_fallback_choice(
    input: &SelectionInput,
    candidates: &[CandidateEvaluation],
) -> Result<Option<(SelectedChoice, EnvironmentFallbackTransition)>, SelectionError> {
    let Some(previous) = input.signals.previous_choice.as_ref() else {
        return Ok(None);
    };
    let rejection = input
        .signals
        .environment_rejections
        .iter()
        .find(|rejection| rejection.candidate == *previous && !rejection.fallback_transition_used);
    let Some(rejection) = rejection else {
        return Ok(None);
    };
    let prior = input
        .priors
        .models
        .iter()
        .find(|prior| prior.runtime == previous.runtime && prior.model == previous.model);
    let Some(fallback) = prior.and_then(|prior| {
        prior
            .one_shot_environment_fallbacks
            .iter()
            .find(|fallback| fallback.rejection_code == rejection.rejection_code)
    }) else {
        return Ok(None);
    };
    let target = CandidateKey {
        runtime: fallback.target_runtime.clone(),
        model: fallback.target_model.clone(),
        effort: fallback.target_effort,
    };
    let Some(evaluation) = candidates
        .iter()
        .find(|evaluation| evaluation.candidate == target && evaluation.eligible)
    else {
        return Ok(None);
    };
    Ok(Some((
        selected_choice(evaluation, ChoiceReason::OneShotEnvironmentFallback)?,
        EnvironmentFallbackTransition {
            source: previous.clone(),
            target,
            rejection_code: rejection.rejection_code.clone(),
            evidence_id: rejection.evidence_id.clone(),
            transition_ordinal: 1,
            maximum_transitions: 1,
        },
    )))
}

fn selected_choice(
    evaluation: &CandidateEvaluation,
    reason: ChoiceReason,
) -> Result<SelectedChoice, SelectionError> {
    let score = evaluation.score.as_ref().ok_or_else(|| {
        SelectionError::InvalidInput(format!(
            "eligible candidate '{}:{}:{:?}' has no score",
            evaluation.candidate.runtime, evaluation.candidate.model, evaluation.candidate.effort
        ))
    })?;
    Ok(SelectedChoice {
        candidate: evaluation.candidate.clone(),
        switch_transition: score.switch_transition,
        configured_switch_cost_microunits: score.configured_switch_cost_microunits,
        switch_cost_microunits: score.switch_cost_microunits,
        total_score_microunits: score.total_score_microunits,
        reason,
    })
}

fn runner_ups(
    candidates: &[CandidateEvaluation],
    choice: Option<&SelectedChoice>,
) -> Result<Vec<RankedScore>, SelectionError> {
    let mut scored = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .filter(|candidate| choice.is_none_or(|choice| choice.candidate != candidate.candidate))
        .filter_map(|candidate| {
            candidate
                .score
                .as_ref()
                .map(|score| (candidate.candidate.clone(), score))
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        left.1
            .total_score_microunits
            .cmp(&right.1.total_score_microunits)
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut ranked = Vec::with_capacity(scored.len());
    for (index, (candidate, score)) in scored.into_iter().enumerate() {
        let ordinal = index.checked_add(2).ok_or_else(|| {
            SelectionError::InvalidInput("runner-up rank overflowed usize".to_string())
        })?;
        ranked.push(RankedScore {
            rank: usize_to_u32(ordinal, "runner-up rank")?,
            candidate,
            switch_transition: score.switch_transition,
            configured_switch_cost_microunits: score.configured_switch_cost_microunits,
            switch_cost_microunits: score.switch_cost_microunits,
            total_score_microunits: score.total_score_microunits,
        });
    }
    Ok(ranked)
}

fn candidate_score_order(left: &&CandidateEvaluation, right: &&CandidateEvaluation) -> Ordering {
    evaluation_score(left)
        .cmp(&evaluation_score(right))
        .then_with(|| left.candidate.cmp(&right.candidate))
}

fn evaluation_score(candidate: &CandidateEvaluation) -> u64 {
    candidate
        .score
        .as_ref()
        .map(|score| score.total_score_microunits)
        .unwrap_or(u64::MAX)
}

fn prior_strength(input: &SelectionInput, candidate: &CandidateEvaluation) -> u16 {
    input
        .priors
        .models
        .iter()
        .find(|prior| {
            prior.runtime == candidate.candidate.runtime && prior.model == candidate.candidate.model
        })
        .map(|prior| prior.strength_rank)
        .unwrap_or_default()
}

fn ledger_summary(
    input: &SelectionInput,
    candidate: &CandidateKey,
) -> Result<LedgerSummary, SelectionError> {
    let matching = input
        .outcomes
        .iter()
        .filter(|record| record.task == input.task && record.candidate == *candidate)
        .collect::<Vec<_>>();
    let accepted = matching
        .iter()
        .filter(|record| record.result == OutcomeResult::Accepted)
        .count();
    let rejected = matching
        .iter()
        .filter(|record| record.result == OutcomeResult::Rejected)
        .count();
    let blocked = matching
        .iter()
        .filter(|record| record.result == OutcomeResult::Blocked)
        .count();
    let quality_attempts = matching
        .iter()
        .filter(|record| {
            record.result == OutcomeResult::Accepted
                || (record.result == OutcomeResult::Rejected
                    && record.failure_class == Some(FailureClass::ModelQuality))
        })
        .count();
    let environment_failure_count = matching
        .iter()
        .map(|record| record.environment_failures.len())
        .try_fold(0usize, |total, count| total.checked_add(count))
        .ok_or_else(|| {
            SelectionError::InvalidInput(
                "environment failure evidence count overflowed usize".to_string(),
            )
        })?;
    let execution = sum_cost(&matching, |record| record.execution_cost_microunits)?;
    let review = sum_cost(&matching, |record| record.review_cost_microunits)?;
    let rework = sum_cost(&matching, |record| record.rework_cost_microunits)?;
    let rereview = sum_cost(&matching, |record| record.rereview_cost_microunits)?;
    let environment = sum_cost(&matching, |record| record.environment_cost_microunits)?;
    Ok(LedgerSummary {
        matching_attempts: usize_to_u32(matching.len(), "matching attempt count")?,
        accepted: usize_to_u32(accepted, "accepted attempt count")?,
        rejected: usize_to_u32(rejected, "rejected attempt count")?,
        blocked: usize_to_u32(blocked, "blocked attempt count")?,
        quality_attempts: usize_to_u32(quality_attempts, "quality attempt count")?,
        environment_failure_count: usize_to_u32(
            environment_failure_count,
            "environment failure count",
        )?,
        execution_cost_microunits: execution,
        review_cost_microunits: review,
        rework_cost_microunits: rework,
        rereview_cost_microunits: rereview,
        environment_cost_microunits: environment,
        total_cycle_cost_microunits: checked_sum_costs(
            [execution, review, rework, rereview, environment],
            "outcome ledger total cycle cost",
        )?,
    })
}

fn posterior_quality_basis_points(
    class_fit: &ClassFitPrior,
    ledger: &LedgerSummary,
) -> Result<u16, SelectionError> {
    let accepted = u128::from(ledger.accepted);
    let local_quality_attempts = u128::from(ledger.quality_attempts);
    let prior_samples = u128::from(class_fit.sample_size);
    let denominator = prior_samples
        .checked_add(local_quality_attempts)
        .ok_or_else(|| {
            SelectionError::InvalidInput("quality denominator overflowed".to_string())
        })?;
    if denominator == 0 {
        return Ok(0);
    }
    let numerator = u128::from(class_fit.quality_basis_points)
        .checked_mul(prior_samples)
        .and_then(|prior| {
            accepted
                .checked_mul(10_000)
                .and_then(|local| prior.checked_add(local))
        })
        .ok_or_else(|| SelectionError::InvalidInput("quality numerator overflowed".to_string()))?;
    Ok((numerator / denominator).min(10_000) as u16)
}

fn expected_cost_per_accepted(
    class_fit: &ClassFitPrior,
    ledger: &LedgerSummary,
) -> Result<u64, SelectionError> {
    let prior_cycle_cost = checked_sum_costs(
        [
            class_fit.execution_cost_microunits,
            class_fit.review_cost_microunits,
            class_fit.rework_cost_microunits,
            class_fit.rereview_cost_microunits,
        ],
        "prior cycle cost",
    )?;
    let prior_samples = u128::from(class_fit.sample_size);
    let total_cost = u128::from(prior_cycle_cost)
        .checked_mul(prior_samples)
        .and_then(|prior| prior.checked_add(u128::from(ledger.total_cycle_cost_microunits)))
        .ok_or_else(|| {
            SelectionError::InvalidInput("weighted cycle cost overflowed".to_string())
        })?;
    let accepted_basis_units = u128::from(class_fit.quality_basis_points)
        .checked_mul(prior_samples)
        .and_then(|prior| {
            u128::from(ledger.accepted)
                .checked_mul(10_000)
                .and_then(|local| prior.checked_add(local))
        })
        .ok_or_else(|| {
            SelectionError::InvalidInput("accepted-basis units overflowed".to_string())
        })?;
    if accepted_basis_units == 0 {
        return Ok(u64::MAX);
    }
    let scaled = total_cost.checked_mul(10_000).ok_or_else(|| {
        SelectionError::InvalidInput("accepted-task cost scaling overflowed".to_string())
    })?;
    u128_to_u64(
        scaled / accepted_basis_units,
        "expected cost per accepted task",
    )
}

fn expected_cost_component_per_accepted(
    prior_component_cost_microunits: u64,
    observed_component_cost_microunits: u64,
    class_fit: &ClassFitPrior,
    ledger: &LedgerSummary,
    context: &str,
) -> Result<u64, SelectionError> {
    let prior_samples = u128::from(class_fit.sample_size);
    let total_cost = u128::from(prior_component_cost_microunits)
        .checked_mul(prior_samples)
        .and_then(|prior| prior.checked_add(u128::from(observed_component_cost_microunits)))
        .ok_or_else(|| SelectionError::InvalidInput(format!("{context} numerator overflowed")))?;
    let accepted_basis_units = u128::from(class_fit.quality_basis_points)
        .checked_mul(prior_samples)
        .and_then(|prior| {
            u128::from(ledger.accepted)
                .checked_mul(10_000)
                .and_then(|local| prior.checked_add(local))
        })
        .ok_or_else(|| SelectionError::InvalidInput(format!("{context} denominator overflowed")))?;
    if accepted_basis_units == 0 {
        return Ok(u64::MAX);
    }
    let scaled = total_cost
        .checked_mul(10_000)
        .ok_or_else(|| SelectionError::InvalidInput(format!("{context} scaling overflowed")))?;
    u128_to_u64(scaled / accepted_basis_units, context)
}

fn proportional_cost_proxy_adjustment(
    cost_proxy_microunits: u64,
    adjustment_weight_percent: u32,
    monetary_baseline_weight_percent: u32,
    context: &str,
) -> Result<u64, SelectionError> {
    if adjustment_weight_percent == 0 {
        return Ok(0);
    }
    if monetary_baseline_weight_percent == 0 {
        return invalid(format!(
            "{context} requires a nonzero monetary baseline weight"
        ));
    }
    let weighted = u128::from(cost_proxy_microunits)
        .checked_mul(u128::from(adjustment_weight_percent))
        .ok_or_else(|| SelectionError::InvalidInput(format!("{context} overflowed")))?;
    u128_to_u64(
        weighted / u128::from(monetary_baseline_weight_percent),
        context,
    )
}

fn sum_cost<F>(records: &[&OutcomeRecord], value: F) -> Result<u64, SelectionError>
where
    F: Fn(&OutcomeRecord) -> u64,
{
    checked_sum_costs(
        records.iter().map(|record| value(record)),
        "outcome ledger cost",
    )
}

fn selection_triggers(input: &SelectionInput, catalogs_digest: &str) -> Vec<SelectionTrigger> {
    let mut triggers = Vec::new();
    if input.signals.retry_count > 0 {
        triggers.push(SelectionTrigger::Retry);
    }
    if input.signals.budget_signal == BudgetSignal::Degrade {
        triggers.push(SelectionTrigger::BudgetDegrade);
    }
    if input
        .signals
        .previous_catalog_digest
        .as_ref()
        .is_some_and(|previous| previous != catalogs_digest)
    {
        triggers.push(SelectionTrigger::CatalogChange);
    }
    if input.debug_override.is_some() {
        triggers.push(SelectionTrigger::DebugOverride);
    }
    if triggers.is_empty() {
        triggers.push(SelectionTrigger::Initial);
    }
    triggers.sort();
    triggers.dedup();
    triggers
}

fn input_digests(input: &SelectionInput) -> Result<InputDigests, SelectionError> {
    Ok(InputDigests {
        normalized_input: digest(input)?,
        task: digest(&input.task)?,
        catalogs: digest(&input.catalogs)?,
        pools: digest(&input.pools)?,
        constraints: digest(&input.constraints)?,
        priors: digest(&input.priors)?,
        resolved_objective_profile: digest(&input.resolved_objective_profile)?,
        outcomes: digest(&input.outcomes)?,
        signals: digest(&input.signals)?,
    })
}

fn validate_resolved_objective_profile(
    resolved: &crate::objective_profile::ResolvedObjectiveProfile,
) -> Result<(), SelectionError> {
    let binding = &resolved.profile;
    validate_identifier("resolved_objective_profile.profile.id", &binding.id)?;
    validate_positive(
        "resolved_objective_profile.profile.version",
        binding.version,
    )?;
    validate_sha256_digest(
        "resolved_objective_profile.profile.content_hash",
        &binding.content_hash,
    )?;
    let reconstructed = RoutingObjectiveProfile {
        id: binding.id.clone(),
        version: binding.version,
        quality: binding.quality.clone(),
        tradeoffs: binding.tradeoffs.clone(),
        switch_costs: binding.switch_costs.clone(),
    };
    let expected = reconstructed.binding().map_err(|error| {
        SelectionError::InvalidInput(format!(
            "resolved objective profile binding is invalid: {error:#}"
        ))
    })?;
    if expected != *binding {
        return invalid(
            "resolved_objective_profile.profile content_hash does not match its effective weights",
        );
    }
    let weights = &binding.tradeoffs;
    if weights.quota_consumption_percent != 0 {
        return invalid(format!(
            "resolved objective profile requests quota_consumption_percent={} but typed contract-backed per-runtime quota evidence is unavailable",
            weights.quota_consumption_percent
        ));
    }
    if weights.latency_percent != 0 {
        return invalid(format!(
            "resolved objective profile requests latency_percent={} but typed per-candidate observed or predicted latency evidence is unavailable",
            weights.latency_percent
        ));
    }
    if weights.monetary_cost_percent == 0 {
        return invalid(
            "resolved objective profile baseline-plus-adjustment scoring requires monetary_cost_percent greater than zero",
        );
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<DigestRecord, SelectionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SelectionError::Serialization(error.to_string()))?;
    Ok(DigestRecord {
        algorithm: "sha256".to_string(),
        value: crate::artifacts::state_auth::sha256_hex(&bytes),
    })
}

fn reject(reasons: &mut Vec<IneligibilityReason>, code: IneligibilityCode, detail: &str) {
    reasons.push(IneligibilityReason {
        code,
        detail: detail.to_string(),
    });
}

fn invalid<T>(message: impl Into<String>) -> Result<T, SelectionError> {
    Err(SelectionError::InvalidInput(message.into()))
}

fn validate_identifier(name: &str, value: &str) -> Result<(), SelectionError> {
    if value.is_empty() || value.trim() != value {
        return invalid(format!("{name} must be non-empty and trimmed"));
    }
    Ok(())
}

fn validate_positive(name: &str, value: u32) -> Result<(), SelectionError> {
    if value == 0 {
        return invalid(format!("{name} must be greater than zero"));
    }
    Ok(())
}

fn validate_candidate_key(name: &str, candidate: &CandidateKey) -> Result<(), SelectionError> {
    validate_identifier(&format!("{name}.runtime"), &candidate.runtime)?;
    validate_identifier(&format!("{name}.model"), &candidate.model)
}

fn validate_task_profile(name: &str, task: &TaskProfile) -> Result<(), SelectionError> {
    validate_identifier(&format!("{name}.task_class"), &task.task_class)
}

fn validate_sha256_digest(name: &str, value: &str) -> Result<(), SelectionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!(
            "{name} must be a lowercase 64-character SHA-256 digest"
        ));
    }
    Ok(())
}

fn validate_calendar_date(name: &str, value: &str) -> Result<(), SelectionError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return invalid(format!("{name} must be a valid YYYY-MM-DD calendar date"));
    }
    let year = value[0..4]
        .parse::<u16>()
        .map_err(|_| SelectionError::InvalidInput(format!("{name} has an invalid year")))?;
    let month = value[5..7]
        .parse::<u8>()
        .map_err(|_| SelectionError::InvalidInput(format!("{name} has an invalid month")))?;
    let day = value[8..10]
        .parse::<u8>()
        .map_err(|_| SelectionError::InvalidInput(format!("{name} has an invalid day")))?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum_day {
        return invalid(format!("{name} must be a valid YYYY-MM-DD calendar date"));
    }
    Ok(())
}

fn duplicate_by<T, F>(values: &[T], key: F) -> bool
where
    F: Fn(&T) -> &str,
{
    values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1]))
}

fn duplicate_pair<'a, T, F>(values: &'a [T], key: F) -> bool
where
    F: Fn(&'a T) -> (&'a str, &'a str),
{
    values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1]))
}

fn duplicate_semantic_key<T, K, F>(values: &[T], key: F) -> bool
where
    K: Ord,
    F: Fn(&T) -> K,
{
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(key(value)))
}

fn scale_basis_points(full: u64, basis_points: u16, context: &str) -> Result<u64, SelectionError> {
    u128_to_u64(
        u128::from(full) * u128::from(basis_points) / 10_000,
        context,
    )
}

fn normalize_cost_per_accepted(
    cycle_cost_microunits: u64,
    posterior_quality_basis_points: u16,
    context: &str,
) -> Result<u64, SelectionError> {
    if cycle_cost_microunits == 0 {
        return Ok(0);
    }
    if posterior_quality_basis_points == 0 {
        return invalid(format!(
            "{context} cannot be normalized with zero acceptance probability"
        ));
    }
    let denominator = u128::from(posterior_quality_basis_points);
    let scaled = u128::from(cycle_cost_microunits)
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(denominator - 1))
        .ok_or_else(|| SelectionError::InvalidInput(format!("{context} overflowed")))?;
    u128_to_u64(scaled / denominator, context)
}

fn checked_sum_costs(
    values: impl IntoIterator<Item = u64>,
    context: &str,
) -> Result<u64, SelectionError> {
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| SelectionError::InvalidInput(format!("{context} overflowed u64")))
    })
}

fn u128_to_u64(value: u128, context: &str) -> Result<u64, SelectionError> {
    u64::try_from(value)
        .map_err(|_| SelectionError::InvalidInput(format!("{context} overflowed u64")))
}

fn usize_to_u32(value: usize, context: &str) -> Result<u32, SelectionError> {
    u32::try_from(value)
        .map_err(|_| SelectionError::InvalidInput(format!("{context} overflowed u32")))
}
