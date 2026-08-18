//! Multi-dimensional resource accounting.
//!
//! Each provider pool is an independent constrained dimension. Collapsing
//! them into one nominal dollar is prohibited. Later provider adapters add
//! dimensions by key; they do not edit this module. Shadow prices modulate
//! the soft objective only and can never relax the quality constraint.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::error::OptimizerError;
use super::ids::{ResourceDimensionId, TimestampMillis};

/// Integer quantity in the dimension's native units (credits, basis points,
/// USD micros, seconds, minutes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Quantity(i64);

impl Quantity {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }

    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationKind {
    Measured,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub kind: ObservationKind,
    /// Confidence in basis points (10000 = 100%).
    pub confidence_bp: u16,
}

/// Sampled future consumption used for per-provider chance constraints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumptionForecast {
    pub samples: Vec<Quantity>,
}

impl ConsumptionForecast {
    pub fn exceedance_bp(&self, remaining: Quantity) -> Option<u16> {
        if self.samples.is_empty() {
            return None;
        }
        let exceedances = self
            .samples
            .iter()
            .filter(|sample| sample.as_i64() > remaining.as_i64())
            .count();
        let bp = (exceedances as u64)
            .saturating_mul(10_000)
            .saturating_div(self.samples.len() as u64);
        Some(bp.min(10_000) as u16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDimension {
    pub id: ResourceDimensionId,
    pub remaining: Quantity,
    pub reset_at: Option<TimestampMillis>,
    /// `Q_0.99(D_frontier,mandatory)`.
    pub frontier_reserve: Quantity,
    /// `M_emergency`.
    pub emergency_margin: Quantity,
    pub uncertainty: Quantity,
    /// Shadow price in milliprice units. Soft objective only.
    pub shadow_price: i64,
    pub observation: ResourceObservation,
    /// `ε_p` in basis points.
    pub chance_epsilon_bp: u16,
    /// Target usage curve value `u_p^target` in basis points.
    pub target_usage_bp: i64,
    /// Learning rate `η_p` in milliprice per 100% usage.
    pub learning_rate: i64,
}

impl ResourceDimension {
    /// `R_frontier = Q_0.99 + M_emergency`.
    pub fn frontier_requirement(&self) -> Quantity {
        self.frontier_reserve.saturating_add(self.emergency_margin)
    }

    /// `B_optional = B_remaining - R_frontier`.
    pub fn optional_budget(&self) -> Quantity {
        self.remaining.saturating_sub(self.frontier_requirement())
    }

    pub fn chance_feasible(&self, forecast: &ConsumptionForecast) -> bool {
        match forecast.exceedance_bp(self.remaining) {
            Some(p_bp) => p_bp <= self.chance_epsilon_bp,
            None => false,
        }
    }

    /// `λ_p(t+1) = max(0, λ_p(t) + η_p [u_p(t) - u_p^target(t)])`.
    pub fn update_shadow_price(&mut self, observed_usage_bp: i64) -> i64 {
        let delta = observed_usage_bp.saturating_sub(self.target_usage_bp);
        let adjustment = self.learning_rate.saturating_mul(delta) / 10_000;
        self.shadow_price = self.shadow_price.saturating_add(adjustment).max(0);
        self.shadow_price
    }
}

/// One key per constrained pool. Never collapsed into a scalar dollar.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceVector {
    dimensions: BTreeMap<ResourceDimensionId, ResourceDimension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchClass {
    MandatoryFrontier,
    OptionalWorker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchRequest {
    pub class: DispatchClass,
    pub pool: ResourceDimensionId,
    pub demand: Quantity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchDecision {
    Admit {
        pool: ResourceDimensionId,
    },
    Reject {
        pool: ResourceDimensionId,
        reason: String,
    },
}

impl DispatchDecision {
    pub fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }

    pub fn rejection_reason(&self) -> Option<&str> {
        match self {
            Self::Reject { reason, .. } => Some(reason.as_str()),
            Self::Admit { .. } => None,
        }
    }
}

impl ResourceVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, dimension: ResourceDimension) {
        self.dimensions.insert(dimension.id.clone(), dimension);
    }

    pub fn get(&self, id: &ResourceDimensionId) -> Option<&ResourceDimension> {
        self.dimensions.get(id)
    }

    pub fn get_mut(&mut self, id: &ResourceDimensionId) -> Option<&mut ResourceDimension> {
        self.dimensions.get_mut(id)
    }

    pub fn require(&self, id: &ResourceDimensionId) -> Result<&ResourceDimension, OptimizerError> {
        self.dimensions
            .get(id)
            .ok_or_else(|| OptimizerError::UnknownResourceDimension(id.to_string()))
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &ResourceDimension> {
        self.dimensions.values()
    }

    pub fn is_empty(&self) -> bool {
        self.dimensions.is_empty()
    }

    pub fn snapshot(&self, observed_at: TimestampMillis) -> ResourceSnapshot {
        ResourceSnapshot {
            observed_at,
            vector: self.clone(),
        }
    }

    pub fn optional_budget(&self, id: &ResourceDimensionId) -> Result<Quantity, OptimizerError> {
        Ok(self.require(id)?.optional_budget())
    }

    /// Optional worker dispatch is rejected when it would violate the
    /// configured frontier reserve, unless no other pool can host the work.
    pub fn admit_dispatch(
        &self,
        request: &DispatchRequest,
    ) -> Result<DispatchDecision, OptimizerError> {
        let dimension = self.require(&request.pool)?;
        match request.class {
            DispatchClass::MandatoryFrontier => {
                if dimension.remaining.as_i64() >= request.demand.as_i64() {
                    Ok(DispatchDecision::Admit {
                        pool: request.pool.clone(),
                    })
                } else {
                    Ok(DispatchDecision::Reject {
                        pool: request.pool.clone(),
                        reason: format!(
                            "mandatory frontier demand exceeds remaining balance on {}",
                            request.pool
                        ),
                    })
                }
            }
            DispatchClass::OptionalWorker => {
                if dimension.optional_budget().as_i64() >= request.demand.as_i64() {
                    return Ok(DispatchDecision::Admit {
                        pool: request.pool.clone(),
                    });
                }
                if self.other_pool_can_host(&request.pool, request.demand) {
                    return Ok(DispatchDecision::Reject {
                        pool: request.pool.clone(),
                        reason: format!(
                            "frontier reserve protection: optional worker dispatch on {} would starve mandatory frontier work",
                            request.pool
                        ),
                    });
                }
                if dimension.remaining.as_i64() >= request.demand.as_i64() {
                    Ok(DispatchDecision::Admit {
                        pool: request.pool.clone(),
                    })
                } else {
                    Ok(DispatchDecision::Reject {
                        pool: request.pool.clone(),
                        reason: format!(
                            "no remaining balance on {} and no feasible policy on any other pool",
                            request.pool
                        ),
                    })
                }
            }
        }
    }

    fn other_pool_can_host(&self, preferred: &ResourceDimensionId, demand: Quantity) -> bool {
        self.dimensions.values().any(|dimension| {
            &dimension.id != preferred && dimension.optional_budget().as_i64() >= demand.as_i64()
        })
    }

    /// Chance constraints are evaluated independently per provider.
    pub fn chance_feasibility(
        &self,
        forecasts: &BTreeMap<ResourceDimensionId, ConsumptionForecast>,
    ) -> Result<BTreeMap<ResourceDimensionId, bool>, OptimizerError> {
        let mut results = BTreeMap::new();
        for (id, forecast) in forecasts {
            let dimension = self.require(id)?;
            results.insert(id.clone(), dimension.chance_feasible(forecast));
        }
        Ok(results)
    }

    pub fn update_shadow_price(
        &mut self,
        id: &ResourceDimensionId,
        observed_usage_bp: i64,
    ) -> Result<i64, OptimizerError> {
        Ok(self
            .get_mut(id)
            .ok_or_else(|| OptimizerError::UnknownResourceDimension(id.to_string()))?
            .update_shadow_price(observed_usage_bp))
    }

    /// Soft surcharge only. Uncertified candidates are rejected rather than
    /// made cheaper by a shadow-price adjustment.
    pub fn modulate_objective(
        &self,
        certified: bool,
        base_cost_micros: i64,
        planned_usage: &BTreeMap<ResourceDimensionId, Quantity>,
    ) -> Result<i64, OptimizerError> {
        if !certified {
            return Err(OptimizerError::Infeasible(
                "shadow prices cannot relax the quality constraint".to_string(),
            ));
        }
        let mut total = base_cost_micros;
        for (id, usage) in planned_usage {
            let dimension = self.require(id)?;
            total = total.saturating_add(dimension.shadow_price.saturating_mul(usage.as_i64()));
        }
        Ok(total)
    }

    /// Re-estimate `Q_0.99` from mandatory-demand samples. Issue #170 owns cadence.
    pub fn recalibrate_frontier_reserve(
        &mut self,
        id: &ResourceDimensionId,
        mandatory_demand_samples: &[Quantity],
        quantile_bp: u16,
    ) -> Result<Quantity, OptimizerError> {
        let dimension = self
            .get_mut(id)
            .ok_or_else(|| OptimizerError::UnknownResourceDimension(id.to_string()))?;
        dimension.frontier_reserve = quantile(mandatory_demand_samples, quantile_bp);
        Ok(dimension.frontier_requirement())
    }
}

fn quantile(samples: &[Quantity], quantile_bp: u16) -> Quantity {
    if samples.is_empty() {
        return Quantity::ZERO;
    }
    let mut ordered = samples.to_vec();
    ordered.sort();
    let rank = u64::from(quantile_bp)
        .saturating_mul(ordered.len() as u64)
        .div_ceil(10_000);
    let index = rank.saturating_sub(1).min(ordered.len() as u64 - 1) as usize;
    ordered[index]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub observed_at: TimestampMillis,
    pub vector: ResourceVector,
}

impl ResourceSnapshot {
    pub fn balances_reserves_and_prices(
        &self,
    ) -> Vec<(ResourceDimensionId, Quantity, Quantity, i64)> {
        self.vector
            .dimensions()
            .map(|dimension| {
                (
                    dimension.id.clone(),
                    dimension.remaining,
                    dimension.frontier_requirement(),
                    dimension.shadow_price,
                )
            })
            .collect()
    }
}

/// Object-safe observer. #151 adapters implement this without editing core.
pub trait ResourceObserver {
    fn observe(&self) -> Result<ResourceSnapshot, OptimizerError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::explanation::DecisionExplanation;
    use crate::optimizer::ids::PolicyId;

    fn pool(name: &'static str, remaining: i64, reserve: i64, emergency: i64) -> ResourceDimension {
        ResourceDimension {
            id: ResourceDimensionId::well_known(name),
            remaining: Quantity::new(remaining),
            reset_at: Some(TimestampMillis::from_millis(10_000)),
            frontier_reserve: Quantity::new(reserve),
            emergency_margin: Quantity::new(emergency),
            uncertainty: Quantity::new(0),
            shadow_price: 0,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 1_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        }
    }

    fn two_pools() -> ResourceVector {
        let mut vector = ResourceVector::new();
        vector.insert(pool(ResourceDimensionId::CODEX_CREDITS, 20, 15, 5));
        vector.insert(pool(
            ResourceDimensionId::GROK_BASIS_POINTS,
            8_000,
            1_000,
            0,
        ));
        vector
    }

    #[test]
    fn optional_worker_dispatch_is_rejected_when_it_violates_frontier_reserve() {
        let vector = two_pools();
        let request = DispatchRequest {
            class: DispatchClass::OptionalWorker,
            pool: ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS),
            demand: Quantity::new(1),
        };
        let decision = vector.admit_dispatch(&request).expect("admit");
        assert!(!decision.is_admit());
        assert!(decision
            .rejection_reason()
            .expect("reason")
            .contains("frontier reserve protection"));

        let snapshot = vector.snapshot(TimestampMillis::from_millis(1));
        let mut explanation = DecisionExplanation {
            decided_at: TimestampMillis::from_millis(1),
            selected: None,
            candidate_ids: vec![PolicyId::new("p").expect("policy")],
            rejection_reasons: Vec::new(),
            resources: snapshot,
        };
        explanation.record_dispatch(&decision);
        assert_eq!(explanation.rejection_reasons.len(), 1);
        assert!(!explanation
            .resources
            .balances_reserves_and_prices()
            .is_empty());
    }

    #[test]
    fn exhausting_pool_a_leaves_pool_b_feasible() {
        let vector = two_pools();
        let mut forecasts = BTreeMap::new();
        forecasts.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS),
            ConsumptionForecast {
                samples: vec![Quantity::new(100), Quantity::new(120)],
            },
        );
        forecasts.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::GROK_BASIS_POINTS),
            ConsumptionForecast {
                samples: vec![Quantity::new(100), Quantity::new(200)],
            },
        );
        let feasibility = vector.chance_feasibility(&forecasts).expect("check");
        assert_eq!(
            feasibility.get(&ResourceDimensionId::well_known(
                ResourceDimensionId::CODEX_CREDITS
            )),
            Some(&false)
        );
        assert_eq!(
            feasibility.get(&ResourceDimensionId::well_known(
                ResourceDimensionId::GROK_BASIS_POINTS
            )),
            Some(&true)
        );

        let mut swapped = BTreeMap::new();
        swapped.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS),
            ConsumptionForecast {
                samples: vec![Quantity::new(1), Quantity::new(2)],
            },
        );
        swapped.insert(
            ResourceDimensionId::well_known(ResourceDimensionId::GROK_BASIS_POINTS),
            ConsumptionForecast {
                samples: vec![Quantity::new(20_000), Quantity::new(20_000)],
            },
        );
        let swapped_feasibility = vector.chance_feasibility(&swapped).expect("check");
        assert_eq!(
            swapped_feasibility.get(&ResourceDimensionId::well_known(
                ResourceDimensionId::CODEX_CREDITS
            )),
            Some(&true)
        );
        assert_eq!(
            swapped_feasibility.get(&ResourceDimensionId::well_known(
                ResourceDimensionId::GROK_BASIS_POINTS
            )),
            Some(&false)
        );
    }

    #[test]
    fn shadow_prices_rise_on_overspend_and_cannot_relax_quality() {
        let mut vector = two_pools();
        let id = ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS);
        let price = vector.update_shadow_price(&id, 8_000).expect("update");
        assert_eq!(price, 300);

        let mut usage = BTreeMap::new();
        usage.insert(id.clone(), Quantity::new(2));
        let scored = vector
            .modulate_objective(true, 1_000, &usage)
            .expect("score");
        assert_eq!(scored, 1_000 + 300 * 2);

        let error = vector
            .modulate_objective(false, 1, &usage)
            .expect_err("quality");
        assert!(matches!(error, OptimizerError::Infeasible(_)));
        assert!(error.to_string().contains("cannot relax"));
    }

    #[test]
    fn snapshots_include_balances_reserves_and_prices() {
        let mut vector = two_pools();
        let id = ResourceDimensionId::well_known(ResourceDimensionId::GROK_BASIS_POINTS);
        vector.update_shadow_price(&id, 9_000).expect("update");
        let snapshot = vector.snapshot(TimestampMillis::from_millis(42));
        let rows = snapshot.balances_reserves_and_prices();
        assert_eq!(rows.len(), 2);
        let grok = rows
            .iter()
            .find(|(row_id, _, _, _)| row_id.as_str() == ResourceDimensionId::GROK_BASIS_POINTS)
            .expect("grok");
        assert_eq!(grok.1, Quantity::new(8_000));
        assert_eq!(grok.2, Quantity::new(1_000));
        assert_eq!(grok.3, 400);
    }

    #[test]
    fn reserve_recalibration_uses_the_configured_quantile() {
        let mut vector = two_pools();
        let id = ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS);
        let samples = [
            Quantity::new(1),
            Quantity::new(2),
            Quantity::new(3),
            Quantity::new(10),
        ];
        let requirement = vector
            .recalibrate_frontier_reserve(&id, &samples, 9_900)
            .expect("recal");
        assert_eq!(
            vector.get(&id).expect("dim").frontier_reserve,
            Quantity::new(10)
        );
        assert_eq!(requirement, Quantity::new(15));
    }

    #[test]
    fn weekly_basis_point_pools_label_measured_or_inferred() {
        let inferred = pool(ResourceDimensionId::GROK_BASIS_POINTS, 4_000, 500, 0);
        let mut grok = inferred;
        grok.observation = ResourceObservation {
            kind: ObservationKind::Inferred,
            confidence_bp: 6_000,
        };
        assert_eq!(grok.remaining.as_i64(), 4_000);
        assert_eq!(grok.observation.kind, ObservationKind::Inferred);
        assert_eq!(grok.observation.confidence_bp, 6_000);
    }
}
