//! Fail-closed quota overlay for selector input (issue #151).
//!
//! The selector already consumes [`RuntimePoolState`]. This module is the
//! only path that may mint those rows from contract entitlements. Missing
//! local observations, provider-reported billing, or a pool that cannot be
//! represented without fabricating capacity fail closed. No network call is
//! made.

use std::collections::BTreeSet;

use crate::optimizer::quota_pools::{
    build_quota_selector_input, ConsumptionLedger, EntitlementDescriptor, NominalCapacity,
    QuotaSelectorInput,
};

use super::{RuntimePoolState, SelectionError, SelectionInput};

/// Build the fail-closed quota selector input from local observations only.
pub fn fail_closed_quota_selector_input(
    entitlements: &[EntitlementDescriptor],
    ledger: &ConsumptionLedger,
) -> Result<QuotaSelectorInput, SelectionError> {
    build_quota_selector_input(entitlements, ledger)
        .map_err(|error| SelectionError::InvalidInput(error.to_string()))
}

/// Project validated quota rows onto the current selector wire type.
///
/// Unknown capacity cannot be represented: remaining must not exceed
/// capacity, and remaining `0` is treated as entitlement exhaustion. Those
/// pools stay on [`QuotaSelectorInput`] until a later wire revision.
pub fn runtime_pool_states(
    input: &QuotaSelectorInput,
) -> Result<Vec<RuntimePoolState>, SelectionError> {
    let mut pools = Vec::with_capacity(input.pools.len());
    for pool in &input.pools {
        let NominalCapacity::Units(capacity) = pool.capacity else {
            return Err(SelectionError::InvalidInput(format!(
                "runtime pool '{}' has unknown capacity and cannot be projected without fabricating units",
                pool.runtime
            )));
        };
        let remaining = pool.remaining_units.ok_or_else(|| {
            SelectionError::InvalidInput(format!(
                "runtime pool '{}' is missing remaining units for a known capacity",
                pool.runtime
            ))
        })?;
        if remaining > capacity {
            return Err(SelectionError::InvalidInput(format!(
                "runtime pool '{}' remaining entitlement exceeds capacity",
                pool.runtime
            )));
        }
        pools.push(RuntimePoolState {
            runtime: pool.runtime.to_string(),
            admission_open: pool.admission_open,
            entitlement_capacity_units: capacity,
            entitlement_remaining_units: remaining,
            pool_pressure_basis_points: pool.pool_pressure_basis_points,
            observed_consumption_units: pool.observed_consumption_units,
            marginal_cost_microunits: pool.marginal_cost_microunits,
            observation_revision: pool.observation_revision.clone(),
            admission_provenance: pool.admission_provenance.clone(),
            failover_provenance: None,
        });
    }
    Ok(pools)
}

/// Replace `input.pools` with a fail-closed local quota projection.
///
/// Catalog runtimes and quota runtimes must match exactly. The returned
/// [`QuotaSelectorInput`] is the auditable source; fabricated billing is
/// never written into the selector input.
pub fn apply_fail_closed_quota_pools(
    input: &mut SelectionInput,
    entitlements: &[EntitlementDescriptor],
    ledger: &ConsumptionLedger,
) -> Result<QuotaSelectorInput, SelectionError> {
    let quota = fail_closed_quota_selector_input(entitlements, ledger)?;
    let pools = runtime_pool_states(&quota)?;
    let catalog_runtimes: BTreeSet<&str> = input
        .catalogs
        .iter()
        .map(|catalog| catalog.runtime.as_str())
        .collect();
    let pool_runtimes: BTreeSet<&str> = pools.iter().map(|pool| pool.runtime.as_str()).collect();
    if catalog_runtimes != pool_runtimes {
        return Err(SelectionError::InvalidInput(
            "quota selector input runtimes must match advertised catalogs exactly".to_string(),
        ));
    }
    let mut ordered = Vec::with_capacity(pools.len());
    for catalog in &input.catalogs {
        let pool = pools
            .iter()
            .find(|pool| pool.runtime == catalog.runtime)
            .ok_or_else(|| {
                SelectionError::InvalidInput(format!(
                    "quota selector input is missing catalog runtime '{}'",
                    catalog.runtime
                ))
            })?;
        ordered.push(pool.clone());
    }
    input.pools = ordered;
    Ok(quota)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::RuntimeSlug;
    use crate::optimizer::quota_pools::{
        AccountId, LedgerEntry, NominalCapacity, PoolKind, RateLimits, ResetWindow, SpillPolicy,
    };
    use crate::selection::{
        AuthorityRole, Boundedness, CandidateCapabilities, CatalogModel, ContextSize,
        OperatorConstraints, ReasoningEffort, RiskLevel, RuntimeCatalog, TaskHorizon, TaskProfile,
    };

    fn account() -> AccountId {
        AccountId::new("operator").expect("account")
    }

    fn runtime(name: &str) -> RuntimeSlug {
        RuntimeSlug::new(name).expect("runtime")
    }

    fn included(name: &str, capacity: u64) -> EntitlementDescriptor {
        EntitlementDescriptor {
            runtime: runtime(name),
            account: account(),
            pool_kind: PoolKind::SubscriptionIncluded,
            window: ResetWindow::CalendarMonth,
            nominal_capacity: NominalCapacity::Units(capacity),
            rate_limits: RateLimits::default(),
            priority_tier: None,
            spill: SpillPolicy::Stop,
            declared_list_price_microunits: None,
        }
    }

    fn metered(name: &str) -> EntitlementDescriptor {
        EntitlementDescriptor {
            runtime: runtime(name),
            account: account(),
            pool_kind: PoolKind::Metered,
            window: ResetWindow::None,
            nominal_capacity: NominalCapacity::Unknown,
            rate_limits: RateLimits::default(),
            priority_tier: None,
            spill: SpillPolicy::Stop,
            declared_list_price_microunits: Some(9_000),
        }
    }

    fn snapshot(
        entitlement: &EntitlementDescriptor,
        tokens: u64,
    ) -> (EntitlementDescriptor, ConsumptionLedger) {
        let mut ledger = ConsumptionLedger::new();
        ledger
            .insert_snapshot(
                entitlement.key(),
                LedgerEntry::local(tokens, 0, format!("{}-obs", entitlement.runtime.as_str())),
            )
            .expect("snapshot");
        (entitlement.clone(), ledger)
    }

    fn catalog(runtime: &str) -> RuntimeCatalog {
        RuntimeCatalog {
            runtime: runtime.to_string(),
            revision: format!("{runtime}-r1"),
            advertised_at: "2026-08-22".to_string(),
            models: vec![CatalogModel {
                model: "fixture-model".to_string(),
                available: true,
                supported_efforts: vec![ReasoningEffort::High],
                capabilities: CandidateCapabilities {
                    task_classes: ["localized_code_change".to_string()].into_iter().collect(),
                    authority_roles: [AuthorityRole::TerminalLeaf].into_iter().collect(),
                    boundedness: [Boundedness::Bounded].into_iter().collect(),
                    maximum_risk: RiskLevel::High,
                    maximum_context: ContextSize::Medium,
                    maximum_horizon: TaskHorizon::Medium,
                    long_context: false,
                },
            }],
        }
    }

    fn dummy_pool(runtime: &str) -> RuntimePoolState {
        RuntimePoolState {
            runtime: runtime.to_string(),
            admission_open: true,
            entitlement_capacity_units: 1,
            entitlement_remaining_units: 1,
            pool_pressure_basis_points: 0,
            observed_consumption_units: 0,
            marginal_cost_microunits: 0,
            observation_revision: format!("{runtime}-dummy"),
            admission_provenance: "placeholder before quota overlay".to_string(),
            failover_provenance: None,
        }
    }

    fn selection_shell(runtimes: &[&str]) -> SelectionInput {
        let priors = crate::selection::built_in_prior_dataset().expect("priors");
        let profile = priors.objective_profiles[0].clone();
        SelectionInput {
            task: TaskProfile {
                task_class: "localized_code_change".to_string(),
                risk: RiskLevel::Medium,
                boundedness: Boundedness::Bounded,
                context: ContextSize::Medium,
                horizon: TaskHorizon::Medium,
                authority_role: AuthorityRole::TerminalLeaf,
            },
            catalogs: runtimes.iter().copied().map(catalog).collect(),
            pools: runtimes.iter().copied().map(dummy_pool).collect(),
            constraints: OperatorConstraints {
                allowed_runtimes: runtimes
                    .iter()
                    .map(|runtime| (*runtime).to_string())
                    .collect(),
                allowed_models: Default::default(),
                forbidden_runtimes: Default::default(),
                forbidden_models: Default::default(),
                forbidden_candidates: Default::default(),
                allow_debug_override: false,
            },
            priors,
            objective_profile: crate::selection::ObjectiveProfileRef {
                name: profile.name,
                version: profile.version,
                expected_digest: None,
            },
            outcomes: Vec::new(),
            signals: crate::selection::DynamicSignals {
                retry_count: 0,
                budget_signal: crate::selection::BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
            },
            debug_override: None,
        }
    }

    #[test]
    fn fresh_included_pool_projects_onto_selector_wire() {
        let (entitlement, ledger) = snapshot(&included("codex", 100), 0);
        let quota = fail_closed_quota_selector_input(&[entitlement], &ledger).expect("quota");
        let pools = runtime_pool_states(&quota).expect("wire");
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].runtime, "codex");
        assert_eq!(pools[0].entitlement_capacity_units, 100);
        assert_eq!(pools[0].entitlement_remaining_units, 100);
        assert_eq!(pools[0].marginal_cost_microunits, 0);
        assert_eq!(pools[0].pool_pressure_basis_points, 0);
    }

    #[test]
    fn pressured_included_pool_projects_local_consumption() {
        let (entitlement, ledger) = snapshot(&included("codex", 100), 80);
        let quota = fail_closed_quota_selector_input(&[entitlement], &ledger).expect("quota");
        let pools = runtime_pool_states(&quota).expect("wire");
        assert_eq!(pools[0].observed_consumption_units, 80);
        assert_eq!(pools[0].entitlement_remaining_units, 20);
        assert_eq!(pools[0].pool_pressure_basis_points, 8_000);
        assert_eq!(pools[0].marginal_cost_microunits, 0);
    }

    #[test]
    fn unknown_metered_capacity_fails_closed_on_wire_projection() {
        let (entitlement, ledger) = snapshot(&metered("grok"), 3);
        let quota = fail_closed_quota_selector_input(&[entitlement], &ledger).expect("quota");
        assert_eq!(quota.pools[0].marginal_cost_microunits, 9_000);
        let error = runtime_pool_states(&quota).expect_err("unknown capacity");
        assert!(error.to_string().contains("unknown capacity"), "{error}");
    }

    #[test]
    fn missing_observation_fails_closed_before_selector_input() {
        let entitlement = included("codex", 100);
        let error = fail_closed_quota_selector_input(&[entitlement], &ConsumptionLedger::new())
            .expect_err("missing");
        assert!(error.to_string().contains("must match exactly"), "{error}");
    }

    #[test]
    fn apply_replaces_placeholder_pools_from_local_ledger() {
        let (entitlement, ledger) = snapshot(&included("codex", 50), 10);
        let mut input = selection_shell(&["codex"]);
        assert_eq!(input.pools[0].observation_revision, "codex-dummy");
        let quota =
            apply_fail_closed_quota_pools(&mut input, &[entitlement], &ledger).expect("apply");
        assert_eq!(quota.pools[0].observed_consumption_units, 10);
        assert_eq!(input.pools[0].observation_revision, "codex-obs");
        assert_eq!(input.pools[0].entitlement_remaining_units, 40);
        assert_eq!(input.pools[0].observed_consumption_units, 10);
        assert!(input.pools[0]
            .admission_provenance
            .contains("provider billing and rate-limit endpoints were not consulted"));
    }

    #[test]
    fn apply_fails_closed_when_catalog_runtime_is_unobserved() {
        let (entitlement, ledger) = snapshot(&included("codex", 50), 0);
        let mut input = selection_shell(&["codex", "grok"]);
        let error = apply_fail_closed_quota_pools(&mut input, &[entitlement], &ledger)
            .expect_err("unobserved catalog");
        assert!(error.to_string().contains("advertised catalogs"), "{error}");
        assert_eq!(input.pools[0].observation_revision, "codex-dummy");
    }
}
