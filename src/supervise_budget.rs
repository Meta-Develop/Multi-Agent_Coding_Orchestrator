//! Atomically synchronized budget accounting for one supervise run.
//!
//! Reservations are admitted before dispatch and reconciled after provider usage is available.
//! The ledger deliberately treats missing prices and unreliable usage as unknown accounting, not
//! as zero cost. This module is kept private to `supervise` so the run lifecycle remains the single
//! owner of both usage accounting and enforcement.

use crate::supervise::AgentRole;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Soft ceilings are advisory degradation thresholds: reaching one does not by itself stop new
/// dispatch. Hard ceilings are admission gates, and reaching one exhausts further dispatch.
pub struct RunBudgetLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_tokens: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_tokens: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_cost_usd: Option<f64>,
}

impl RunBudgetLimits {
    pub(super) fn validate(self) -> Result<Self> {
        validate_token_limit(self.soft_tokens, "soft token")?;
        validate_token_limit(self.hard_tokens, "hard token")?;
        validate_cost_limit(self.soft_cost_usd, "soft cost")?;
        validate_cost_limit(self.hard_cost_usd, "hard cost")?;
        if matches!(
            (self.soft_tokens, self.hard_tokens),
            (Some(soft), Some(hard)) if soft > hard
        ) {
            return Err(BudgetError::InvalidLimitOrder { resource: "token" });
        }
        if matches!(
            (self.soft_cost_usd, self.hard_cost_usd),
            (Some(soft), Some(hard)) if soft > hard
        ) {
            return Err(BudgetError::InvalidLimitOrder { resource: "cost" });
        }
        Ok(self)
    }

    pub(super) fn has_cost_ceiling(self) -> bool {
        self.soft_cost_usd.is_some() || self.hard_cost_usd.is_some()
    }

    pub(super) fn has_any_ceiling(self) -> bool {
        self.soft_tokens.is_some()
            || self.hard_tokens.is_some()
            || self.soft_cost_usd.is_some()
            || self.hard_cost_usd.is_some()
    }

    pub(super) fn is_unconfigured(&self) -> bool {
        !self.has_any_ceiling()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub(super) struct BudgetReservationId(u64);

impl BudgetReservationId {
    pub(super) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetReservationRequest {
    pub(super) role: AgentRole,
    pub(super) tokens: usize,
    /// `None` means the selected model has no trustworthy pricing entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetReservation {
    pub(super) id: BudgetReservationId,
    pub(super) role: AgentRole,
    pub(super) tokens: usize,
    /// `None` is preserved as unavailable pricing and never converted to public zero cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetAmount {
    pub tokens: usize,
    /// `None` means cost accounting is unavailable or unreliable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRemaining {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_tokens: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_tokens: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetReason {
    SoftTokenCeilingReached,
    HardTokenCeilingReached,
    SoftCostCeilingReached,
    HardCostCeilingReached,
    MissingPricing,
    EstimatedProviderUsage,
    MissingProviderUsage,
    MissingActualCost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetAction {
    Continue,
    Degrade,
    OwnerEscalation,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBudgetReport {
    pub role: AgentRole,
    pub consumed: BudgetAmount,
    pub reserved: BudgetAmount,
    pub active_reservations: usize,
    pub usage_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudgetReport {
    pub limits: RunBudgetLimits,
    pub consumed: BudgetAmount,
    pub reserved: BudgetAmount,
    pub committed: BudgetAmount,
    pub remaining: BudgetRemaining,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleBudgetReport>,
    pub active_reservations: usize,
    pub usage_complete: bool,
    pub action: BudgetAction,
    pub new_dispatch_allowed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<BudgetReason>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "reason", rename_all = "snake_case")]
pub(super) enum BudgetAdmissionRefusal {
    NewDispatchStopped,
    MissingCostEstimate,
    HardTokenCeiling {
        limit: usize,
        committed: usize,
        requested: usize,
    },
    HardCostCeiling {
        limit_usd: f64,
        committed_usd: f64,
        requested_usd: f64,
    },
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "snake_case")]
pub(super) enum BudgetAdmission {
    Admitted {
        reservation: BudgetReservation,
        report: RunBudgetReport,
    },
    Refused {
        refusal: BudgetAdmissionRefusal,
        report: RunBudgetReport,
    },
}

#[cfg(test)]
impl BudgetAdmission {
    pub(super) fn reservation(&self) -> Option<&BudgetReservation> {
        match self {
            Self::Admitted { reservation, .. } => Some(reservation),
            Self::Refused { .. } => None,
        }
    }

    pub(super) fn report(&self) -> &RunBudgetReport {
        match self {
            Self::Admitted { report, .. } | Self::Refused { report, .. } => report,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "reliability", rename_all = "snake_case")]
pub(super) enum UsageMeasurement {
    Reliable {
        tokens: usize,
        /// `None` records that provider usage was available but pricing was not.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
    Estimated {
        tokens: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetReconciliation {
    pub(super) reservation: BudgetReservation,
    /// Conservative charge applied to enforcement. Cost remains hidden when it is not trustworthy.
    pub(super) charged: BudgetAmount,
    pub(super) report: RunBudgetReport,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetRelease {
    pub(super) reservation: BudgetReservation,
    pub(super) report: RunBudgetReport,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum BudgetError {
    #[error("{name} ceiling must be greater than zero")]
    ZeroLimit { name: &'static str },
    #[error("{name} ceiling must be finite and greater than zero")]
    InvalidCostLimit { name: &'static str },
    #[error("soft {resource} ceiling cannot exceed its hard ceiling")]
    InvalidLimitOrder { resource: &'static str },
    #[error("a budget reservation must reserve at least one token")]
    EmptyReservation,
    #[error("budget reservation cost must be finite and non-negative")]
    InvalidReservationCost,
    #[error("provider usage cost must be finite and non-negative")]
    InvalidUsageCost,
    #[error("budget reservation id space is exhausted")]
    ReservationIdExhausted,
    #[error("budget reservation is not active: {0}")]
    UnknownReservation(u64),
    #[error("token accounting overflowed")]
    TokenOverflow,
    #[error("cost accounting overflowed")]
    CostOverflow,
    #[error("budget ledger state is inconsistent")]
    InconsistentState,
    #[error("budget ledger lock is poisoned")]
    Poisoned,
}

pub(super) type Result<T> = std::result::Result<T, BudgetError>;

#[derive(Debug, Clone)]
pub(super) struct RunBudgetLedger {
    limits: RunBudgetLimits,
    inner: Arc<Mutex<LedgerState>>,
}

#[derive(Debug, Clone)]
struct LedgerState {
    next_reservation_id: u64,
    active: BTreeMap<BudgetReservationId, BudgetReservation>,
    consumed_tokens: usize,
    consumed_cost_usd: f64,
    reserved_tokens: usize,
    reserved_cost_usd: f64,
    unknown_reserved_costs: usize,
    usage_complete: bool,
    cost_complete: bool,
    force_stop: bool,
    persistent_reasons: BTreeSet<BudgetReason>,
    roles: BTreeMap<AgentRole, RoleState>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self {
            next_reservation_id: 1,
            active: BTreeMap::new(),
            consumed_tokens: 0,
            consumed_cost_usd: 0.0,
            reserved_tokens: 0,
            reserved_cost_usd: 0.0,
            unknown_reserved_costs: 0,
            usage_complete: true,
            cost_complete: true,
            force_stop: false,
            persistent_reasons: BTreeSet::new(),
            roles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct RoleState {
    consumed_tokens: usize,
    consumed_cost_usd: f64,
    reserved_tokens: usize,
    reserved_cost_usd: f64,
    unknown_reserved_costs: usize,
    active_reservations: usize,
    usage_complete: bool,
    cost_complete: bool,
}

impl Default for RoleState {
    fn default() -> Self {
        Self {
            consumed_tokens: 0,
            consumed_cost_usd: 0.0,
            reserved_tokens: 0,
            reserved_cost_usd: 0.0,
            unknown_reserved_costs: 0,
            active_reservations: 0,
            usage_complete: true,
            cost_complete: true,
        }
    }
}

#[derive(Debug)]
struct ReconciliationCharge {
    tokens: usize,
    cost_usd: f64,
    usage_complete: bool,
    cost_complete: bool,
    reason: Option<BudgetReason>,
    stop_for_uncertainty: bool,
}

impl RunBudgetLedger {
    pub(super) fn new(limits: RunBudgetLimits) -> Result<Self> {
        Ok(Self {
            limits: limits.validate()?,
            inner: Arc::new(Mutex::new(LedgerState::default())),
        })
    }

    /// Atomically checks the current commitments and reserves budget before dispatch.
    pub(super) fn reserve(&self, request: BudgetReservationRequest) -> Result<BudgetAdmission> {
        validate_reservation_request(&request)?;
        let mut state = self.lock_state()?;
        let current_report = report_for(self.limits, &state)?;
        if !current_report.new_dispatch_allowed {
            return Ok(BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::NewDispatchStopped,
                report: current_report,
            });
        }
        if request.cost_usd.is_none() && self.limits.has_cost_ceiling() {
            let mut next = state.clone();
            next.force_stop = true;
            next.persistent_reasons.insert(BudgetReason::MissingPricing);
            let report = report_for(self.limits, &next)?;
            *state = next;
            return Ok(BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::MissingCostEstimate,
                report,
            });
        }

        let committed_tokens = state
            .consumed_tokens
            .checked_add(state.reserved_tokens)
            .ok_or(BudgetError::TokenOverflow)?;
        let projected_tokens = committed_tokens
            .checked_add(request.tokens)
            .ok_or(BudgetError::TokenOverflow)?;
        if let Some(limit) = self
            .limits
            .hard_tokens
            .filter(|limit| projected_tokens > *limit)
        {
            let mut next = state.clone();
            next.force_stop = true;
            next.persistent_reasons
                .insert(BudgetReason::HardTokenCeilingReached);
            let report = report_for(self.limits, &next)?;
            *state = next;
            return Ok(BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling {
                    limit,
                    committed: committed_tokens,
                    requested: request.tokens,
                },
                report,
            });
        }

        let committed_cost_usd =
            checked_cost_add(state.consumed_cost_usd, state.reserved_cost_usd)?;
        if let (Some(requested_usd), Some(limit_usd)) =
            (request.cost_usd, self.limits.hard_cost_usd)
        {
            let projected_cost_usd = checked_cost_add(committed_cost_usd, requested_usd)?;
            if projected_cost_usd > limit_usd {
                let mut next = state.clone();
                next.force_stop = true;
                next.persistent_reasons
                    .insert(BudgetReason::HardCostCeilingReached);
                let report = report_for(self.limits, &next)?;
                *state = next;
                return Ok(BudgetAdmission::Refused {
                    refusal: BudgetAdmissionRefusal::HardCostCeiling {
                        limit_usd,
                        committed_usd: committed_cost_usd,
                        requested_usd,
                    },
                    report,
                });
            }
        }

        let id = BudgetReservationId(state.next_reservation_id);
        let next_id = state
            .next_reservation_id
            .checked_add(1)
            .ok_or(BudgetError::ReservationIdExhausted)?;
        let reservation = BudgetReservation {
            id,
            role: request.role,
            tokens: request.tokens,
            cost_usd: request.cost_usd,
        };
        let mut next = state.clone();
        next.next_reservation_id = next_id;
        add_reservation(&mut next, reservation.clone())?;
        let report = report_for(self.limits, &next)?;
        *state = next;
        Ok(BudgetAdmission::Admitted {
            reservation,
            report,
        })
    }

    /// Replaces an active reservation with conservative consumed usage in one transaction.
    pub(super) fn reconcile(
        &self,
        id: BudgetReservationId,
        measurement: UsageMeasurement,
    ) -> Result<BudgetReconciliation> {
        validate_measurement(&measurement)?;
        let mut state = self.lock_state()?;
        let reservation = state
            .active
            .get(&id)
            .cloned()
            .ok_or(BudgetError::UnknownReservation(id.get()))?;
        let charge = reconciliation_charge(&reservation, &measurement)?;
        let mut next = state.clone();
        remove_reservation(&mut next, id)?;
        apply_charge(&mut next, reservation.role, &charge, self.limits)?;
        let report = report_for(self.limits, &next)?;
        *state = next;
        Ok(BudgetReconciliation {
            reservation,
            charged: BudgetAmount {
                tokens: charge.tokens,
                cost_usd: charge.cost_complete.then_some(charge.cost_usd),
            },
            report,
        })
    }

    /// Releases budget when a dispatch did not start and therefore consumed no provider usage.
    pub(super) fn release(&self, id: BudgetReservationId) -> Result<BudgetRelease> {
        let mut state = self.lock_state()?;
        let mut next = state.clone();
        let reservation = remove_reservation(&mut next, id)?;
        let report = report_for(self.limits, &next)?;
        *state = next;
        Ok(BudgetRelease {
            reservation,
            report,
        })
    }

    pub(super) fn report(&self) -> Result<RunBudgetReport> {
        let state = self.lock_state()?;
        report_for(self.limits, &state)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, LedgerState>> {
        self.inner.lock().map_err(|_| BudgetError::Poisoned)
    }
}

fn validate_token_limit(value: Option<usize>, name: &'static str) -> Result<()> {
    if value == Some(0) {
        return Err(BudgetError::ZeroLimit { name });
    }
    Ok(())
}

fn validate_cost_limit(value: Option<f64>, name: &'static str) -> Result<()> {
    if value.is_some_and(|limit| !limit.is_finite() || limit <= 0.0) {
        return Err(BudgetError::InvalidCostLimit { name });
    }
    Ok(())
}

fn validate_reservation_request(request: &BudgetReservationRequest) -> Result<()> {
    if request.tokens == 0 {
        return Err(BudgetError::EmptyReservation);
    }
    if request
        .cost_usd
        .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
    {
        return Err(BudgetError::InvalidReservationCost);
    }
    Ok(())
}

fn validate_measurement(measurement: &UsageMeasurement) -> Result<()> {
    let cost_usd = match measurement {
        UsageMeasurement::Reliable { cost_usd, .. }
        | UsageMeasurement::Estimated { cost_usd, .. } => *cost_usd,
        UsageMeasurement::Missing => None,
    };
    if cost_usd.is_some_and(|cost| !cost.is_finite() || cost < 0.0) {
        return Err(BudgetError::InvalidUsageCost);
    }
    Ok(())
}

fn add_reservation(state: &mut LedgerState, reservation: BudgetReservation) -> Result<()> {
    state.reserved_tokens = state
        .reserved_tokens
        .checked_add(reservation.tokens)
        .ok_or(BudgetError::TokenOverflow)?;
    match reservation.cost_usd {
        Some(cost_usd) => {
            state.reserved_cost_usd = checked_cost_add(state.reserved_cost_usd, cost_usd)?;
        }
        None => {
            state.unknown_reserved_costs = state
                .unknown_reserved_costs
                .checked_add(1)
                .ok_or(BudgetError::TokenOverflow)?;
            state
                .persistent_reasons
                .insert(BudgetReason::MissingPricing);
        }
    }
    let role = state.roles.entry(reservation.role).or_default();
    role.reserved_tokens = role
        .reserved_tokens
        .checked_add(reservation.tokens)
        .ok_or(BudgetError::TokenOverflow)?;
    match reservation.cost_usd {
        Some(cost_usd) => {
            role.reserved_cost_usd = checked_cost_add(role.reserved_cost_usd, cost_usd)?;
        }
        None => {
            role.unknown_reserved_costs = role
                .unknown_reserved_costs
                .checked_add(1)
                .ok_or(BudgetError::TokenOverflow)?;
        }
    }
    role.active_reservations = role
        .active_reservations
        .checked_add(1)
        .ok_or(BudgetError::TokenOverflow)?;
    if state.active.insert(reservation.id, reservation).is_some() {
        return Err(BudgetError::InconsistentState);
    }
    Ok(())
}

fn remove_reservation(
    state: &mut LedgerState,
    id: BudgetReservationId,
) -> Result<BudgetReservation> {
    let reservation = state
        .active
        .remove(&id)
        .ok_or(BudgetError::UnknownReservation(id.get()))?;
    state.reserved_tokens = state
        .reserved_tokens
        .checked_sub(reservation.tokens)
        .ok_or(BudgetError::InconsistentState)?;
    match reservation.cost_usd {
        Some(cost_usd) => {
            state.reserved_cost_usd = checked_cost_sub(state.reserved_cost_usd, cost_usd)?;
        }
        None => {
            state.unknown_reserved_costs = state
                .unknown_reserved_costs
                .checked_sub(1)
                .ok_or(BudgetError::InconsistentState)?;
        }
    }
    let role = state
        .roles
        .get_mut(&reservation.role)
        .ok_or(BudgetError::InconsistentState)?;
    role.reserved_tokens = role
        .reserved_tokens
        .checked_sub(reservation.tokens)
        .ok_or(BudgetError::InconsistentState)?;
    match reservation.cost_usd {
        Some(cost_usd) => {
            role.reserved_cost_usd = checked_cost_sub(role.reserved_cost_usd, cost_usd)?;
        }
        None => {
            role.unknown_reserved_costs = role
                .unknown_reserved_costs
                .checked_sub(1)
                .ok_or(BudgetError::InconsistentState)?;
        }
    }
    role.active_reservations = role
        .active_reservations
        .checked_sub(1)
        .ok_or(BudgetError::InconsistentState)?;
    Ok(reservation)
}

fn reconciliation_charge(
    reservation: &BudgetReservation,
    measurement: &UsageMeasurement,
) -> Result<ReconciliationCharge> {
    let charge = match measurement {
        UsageMeasurement::Reliable { tokens, cost_usd } => ReconciliationCharge {
            tokens: *tokens,
            cost_usd: observed_cost_or_reserved(*cost_usd, reservation.cost_usd),
            usage_complete: true,
            cost_complete: cost_usd.is_some(),
            reason: cost_usd
                .is_none()
                .then_some(BudgetReason::MissingActualCost),
            stop_for_uncertainty: cost_usd.is_none(),
        },
        UsageMeasurement::Estimated { tokens, cost_usd } => ReconciliationCharge {
            tokens: (*tokens).max(reservation.tokens),
            cost_usd: conservative_cost(*cost_usd, reservation.cost_usd),
            usage_complete: false,
            cost_complete: false,
            reason: Some(BudgetReason::EstimatedProviderUsage),
            stop_for_uncertainty: true,
        },
        UsageMeasurement::Missing => ReconciliationCharge {
            tokens: reservation.tokens,
            cost_usd: reservation.cost_usd.map_or(0.0, |cost_usd| cost_usd),
            usage_complete: false,
            cost_complete: false,
            reason: Some(BudgetReason::MissingProviderUsage),
            stop_for_uncertainty: true,
        },
    };
    if !charge.cost_usd.is_finite() {
        return Err(BudgetError::CostOverflow);
    }
    Ok(charge)
}

fn conservative_cost(observed: Option<f64>, reserved: Option<f64>) -> f64 {
    match (observed, reserved) {
        (Some(observed), Some(reserved)) => observed.max(reserved),
        (Some(observed), None) => observed,
        (None, Some(reserved)) => reserved,
        (None, None) => 0.0,
    }
}

fn observed_cost_or_reserved(observed: Option<f64>, reserved: Option<f64>) -> f64 {
    match (observed, reserved) {
        (Some(observed), _) => observed,
        (None, Some(reserved)) => reserved,
        (None, None) => 0.0,
    }
}

fn apply_charge(
    state: &mut LedgerState,
    role: AgentRole,
    charge: &ReconciliationCharge,
    limits: RunBudgetLimits,
) -> Result<()> {
    state.consumed_tokens = state
        .consumed_tokens
        .checked_add(charge.tokens)
        .ok_or(BudgetError::TokenOverflow)?;
    state.consumed_cost_usd = checked_cost_add(state.consumed_cost_usd, charge.cost_usd)?;
    state.usage_complete &= charge.usage_complete;
    state.cost_complete &= charge.cost_complete;
    if let Some(reason) = charge.reason {
        state.persistent_reasons.insert(reason);
    }
    let uncertainty_affects_enforcement = match charge.reason {
        Some(BudgetReason::MissingActualCost) => limits.has_cost_ceiling(),
        Some(BudgetReason::EstimatedProviderUsage | BudgetReason::MissingProviderUsage) => {
            limits.has_any_ceiling()
        }
        _ => false,
    };
    if charge.stop_for_uncertainty && uncertainty_affects_enforcement {
        state.force_stop = true;
    }

    let role = state.roles.entry(role).or_default();
    role.consumed_tokens = role
        .consumed_tokens
        .checked_add(charge.tokens)
        .ok_or(BudgetError::TokenOverflow)?;
    role.consumed_cost_usd = checked_cost_add(role.consumed_cost_usd, charge.cost_usd)?;
    role.usage_complete &= charge.usage_complete;
    role.cost_complete &= charge.cost_complete;
    Ok(())
}

fn report_for(limits: RunBudgetLimits, state: &LedgerState) -> Result<RunBudgetReport> {
    let committed_tokens = state
        .consumed_tokens
        .checked_add(state.reserved_tokens)
        .ok_or(BudgetError::TokenOverflow)?;
    let reserved_cost_complete = state.unknown_reserved_costs == 0;
    let committed_cost_complete = state.cost_complete && reserved_cost_complete;
    let committed_cost_usd = checked_cost_add(state.consumed_cost_usd, state.reserved_cost_usd)?;
    let mut reasons = state.persistent_reasons.clone();

    let soft_tokens_reached = limits
        .soft_tokens
        .is_some_and(|limit| committed_tokens >= limit);
    if soft_tokens_reached {
        reasons.insert(BudgetReason::SoftTokenCeilingReached);
    }
    let hard_tokens_reached = limits
        .hard_tokens
        .is_some_and(|limit| committed_tokens >= limit);
    if hard_tokens_reached {
        reasons.insert(BudgetReason::HardTokenCeilingReached);
    }
    let soft_cost_reached = committed_cost_complete
        && limits
            .soft_cost_usd
            .is_some_and(|limit| committed_cost_usd >= limit);
    if soft_cost_reached {
        reasons.insert(BudgetReason::SoftCostCeilingReached);
    }
    let hard_cost_reached = committed_cost_complete
        && limits
            .hard_cost_usd
            .is_some_and(|limit| committed_cost_usd >= limit);
    if hard_cost_reached {
        reasons.insert(BudgetReason::HardCostCeilingReached);
    }
    let cost_ceiling_unenforceable = limits.has_cost_ceiling() && !committed_cost_complete;
    let new_dispatch_allowed = !state.force_stop
        && !hard_tokens_reached
        && !hard_cost_reached
        && !cost_ceiling_unenforceable;
    let action = if !new_dispatch_allowed {
        BudgetAction::OwnerEscalation
    } else if reasons.is_empty() {
        BudgetAction::Continue
    } else {
        BudgetAction::Degrade
    };

    let roles = state
        .roles
        .iter()
        .map(|(role, role_state)| RoleBudgetReport {
            role: *role,
            consumed: BudgetAmount {
                tokens: role_state.consumed_tokens,
                cost_usd: role_state
                    .cost_complete
                    .then_some(role_state.consumed_cost_usd),
            },
            reserved: BudgetAmount {
                tokens: role_state.reserved_tokens,
                cost_usd: (role_state.unknown_reserved_costs == 0)
                    .then_some(role_state.reserved_cost_usd),
            },
            active_reservations: role_state.active_reservations,
            usage_complete: role_state.usage_complete,
        })
        .collect();

    Ok(RunBudgetReport {
        limits,
        consumed: BudgetAmount {
            tokens: state.consumed_tokens,
            cost_usd: state.cost_complete.then_some(state.consumed_cost_usd),
        },
        reserved: BudgetAmount {
            tokens: state.reserved_tokens,
            cost_usd: reserved_cost_complete.then_some(state.reserved_cost_usd),
        },
        committed: BudgetAmount {
            tokens: committed_tokens,
            cost_usd: committed_cost_complete.then_some(committed_cost_usd),
        },
        remaining: BudgetRemaining {
            soft_tokens: limits
                .soft_tokens
                .map(|limit| limit.saturating_sub(committed_tokens)),
            hard_tokens: limits
                .hard_tokens
                .map(|limit| limit.saturating_sub(committed_tokens)),
            soft_cost_usd: committed_cost_complete
                .then(|| {
                    limits
                        .soft_cost_usd
                        .map(|limit| (limit - committed_cost_usd).max(0.0))
                })
                .flatten(),
            hard_cost_usd: committed_cost_complete
                .then(|| {
                    limits
                        .hard_cost_usd
                        .map(|limit| (limit - committed_cost_usd).max(0.0))
                })
                .flatten(),
        },
        roles,
        active_reservations: state.active.len(),
        usage_complete: state.usage_complete,
        action,
        new_dispatch_allowed,
        reasons: reasons.into_iter().collect(),
    })
}

fn checked_cost_add(left: f64, right: f64) -> Result<f64> {
    let total = left + right;
    if total.is_finite() {
        Ok(total)
    } else {
        Err(BudgetError::CostOverflow)
    }
}

fn checked_cost_sub(total: f64, amount: f64) -> Result<f64> {
    let remaining = total - amount;
    if !remaining.is_finite() {
        return Err(BudgetError::CostOverflow);
    }
    let tolerance = f64::EPSILON * total.abs().max(amount.abs()).max(1.0) * 8.0;
    if remaining < -tolerance {
        return Err(BudgetError::InconsistentState);
    }
    Ok(remaining.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    fn token_limits(soft_tokens: usize, hard_tokens: usize) -> RunBudgetLimits {
        RunBudgetLimits {
            soft_tokens: Some(soft_tokens),
            hard_tokens: Some(hard_tokens),
            soft_cost_usd: None,
            hard_cost_usd: None,
        }
    }

    fn cost_limits(soft_cost_usd: f64, hard_cost_usd: f64) -> RunBudgetLimits {
        RunBudgetLimits {
            soft_tokens: None,
            hard_tokens: None,
            soft_cost_usd: Some(soft_cost_usd),
            hard_cost_usd: Some(hard_cost_usd),
        }
    }

    fn request(tokens: usize, cost_usd: Option<f64>) -> BudgetReservationRequest {
        BudgetReservationRequest {
            role: AgentRole::Worker,
            tokens,
            cost_usd,
        }
    }

    fn admitted_reservation(admission: BudgetAdmission) -> BudgetReservation {
        match admission {
            BudgetAdmission::Admitted { reservation, .. } => reservation,
            BudgetAdmission::Refused { refusal, .. } => {
                panic!("expected admitted reservation, got {refusal:?}")
            }
        }
    }

    #[test]
    fn limits_are_strict_and_ordered() {
        let unknown = serde_json::from_str::<RunBudgetLimits>(
            r#"{"soft_tokens":10,"hard_tokens":20,"extra":1}"#,
        );
        assert!(unknown.is_err());
        assert_eq!(
            RunBudgetLedger::new(token_limits(20, 10)).expect_err("invalid limit order"),
            BudgetError::InvalidLimitOrder { resource: "token" }
        );
        assert_eq!(
            RunBudgetLedger::new(RunBudgetLimits {
                soft_tokens: None,
                hard_tokens: Some(0),
                soft_cost_usd: None,
                hard_cost_usd: None,
            })
            .expect_err("zero limit"),
            BudgetError::ZeroLimit { name: "hard token" }
        );
    }

    #[test]
    fn soft_ceiling_degrades_and_hard_ceiling_stops_new_dispatch() {
        let ledger = RunBudgetLedger::new(token_limits(50, 100)).expect("ledger");
        let first = ledger.reserve(request(60, None)).expect("reserve");
        assert!(first.reservation().is_some());
        assert_eq!(first.report().action, BudgetAction::Degrade);
        assert!(first.report().new_dispatch_allowed);

        let second = ledger.reserve(request(40, None)).expect("reserve");
        assert_eq!(second.report().committed.tokens, 100);
        assert_eq!(second.report().action, BudgetAction::OwnerEscalation);
        assert!(!second.report().new_dispatch_allowed);

        let refused = ledger.reserve(request(1, None)).expect("refusal");
        assert!(matches!(
            refused,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::NewDispatchStopped,
                ..
            }
        ));
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe_the_hard_ceiling() {
        let ledger =
            Arc::new(RunBudgetLedger::new(token_limits(90, 100)).expect("concurrent ledger"));
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let ledger = Arc::clone(&ledger);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    ledger.reserve(request(60, None))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();

        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation thread").expect("ledger"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, BudgetAdmission::Admitted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        BudgetAdmission::Refused {
                            refusal: BudgetAdmissionRefusal::HardTokenCeiling { .. },
                            ..
                        }
                    )
                })
                .count(),
            1
        );
        assert_eq!(ledger.report().expect("report").reserved.tokens, 60);
    }

    #[test]
    fn soft_and_exact_hard_cost_boundaries_degrade_then_stop() {
        let ledger = RunBudgetLedger::new(cost_limits(0.5, 1.0)).expect("cost ledger");
        let first = ledger
            .reserve(request(100, Some(0.5)))
            .expect("soft-boundary reservation");
        assert!(first.reservation().is_some());
        assert_eq!(first.report().action, BudgetAction::Degrade);
        assert!(first.report().new_dispatch_allowed);
        assert!(first
            .report()
            .reasons
            .contains(&BudgetReason::SoftCostCeilingReached));

        let exact = ledger
            .reserve(request(100, Some(0.5)))
            .expect("exact hard-boundary reservation");
        assert!(exact.reservation().is_some());
        assert_eq!(exact.report().committed.cost_usd, Some(1.0));
        assert_eq!(exact.report().remaining.hard_cost_usd, Some(0.0));
        assert_eq!(exact.report().action, BudgetAction::OwnerEscalation);
        assert!(!exact.report().new_dispatch_allowed);
        assert!(exact
            .report()
            .reasons
            .contains(&BudgetReason::HardCostCeilingReached));
    }

    #[test]
    fn over_hard_cost_boundary_is_refused_without_mutating_commitments() {
        let ledger = RunBudgetLedger::new(cost_limits(0.5, 1.0)).expect("cost ledger");
        let first = ledger
            .reserve(request(100, Some(0.6)))
            .expect("first reservation");
        assert!(first.reservation().is_some());

        let over = ledger
            .reserve(request(100, Some(0.400_001)))
            .expect("over-boundary refusal");
        assert!(matches!(
            over,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardCostCeiling { .. },
                ..
            }
        ));
        let report = ledger.report().expect("stable report");
        assert_eq!(report.reserved.cost_usd, Some(0.6));
        assert_eq!(report.active_reservations, 1);
        assert!(!report.new_dispatch_allowed);
        assert!(report
            .reasons
            .contains(&BudgetReason::HardCostCeilingReached));
    }

    #[test]
    fn concurrent_cost_reservations_cannot_oversubscribe_hard_ceiling() {
        let ledger =
            Arc::new(RunBudgetLedger::new(cost_limits(0.9, 1.0)).expect("concurrent cost ledger"));
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let ledger = Arc::clone(&ledger);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    ledger.reserve(request(100, Some(0.6)))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();

        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation thread").expect("ledger"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, BudgetAdmission::Admitted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        BudgetAdmission::Refused {
                            refusal: BudgetAdmissionRefusal::HardCostCeiling { .. },
                            ..
                        }
                    )
                })
                .count(),
            1
        );
        assert_eq!(
            ledger.report().expect("report").reserved.cost_usd,
            Some(0.6)
        );
    }

    #[test]
    fn reliable_usage_reconciles_reservation_to_actual_consumption() {
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: Some(80),
            hard_tokens: Some(100),
            soft_cost_usd: Some(0.8),
            hard_cost_usd: Some(1.0),
        })
        .expect("ledger");
        let reservation =
            admitted_reservation(ledger.reserve(request(60, Some(0.6))).expect("reserve"));
        let reconciliation = ledger
            .reconcile(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 35,
                    cost_usd: Some(0.35),
                },
            )
            .expect("reconcile");

        assert_eq!(
            reconciliation.charged,
            BudgetAmount {
                tokens: 35,
                cost_usd: Some(0.35),
            }
        );
        assert_eq!(reconciliation.report.consumed.tokens, 35);
        assert_eq!(reconciliation.report.reserved.tokens, 0);
        assert_eq!(reconciliation.report.active_reservations, 0);
        assert!(reconciliation.report.usage_complete);
        assert!(reconciliation.report.new_dispatch_allowed);
    }

    #[test]
    fn report_attributes_active_reservations_by_role() {
        let ledger = RunBudgetLedger::new(token_limits(800, 1_000)).expect("ledger");
        ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 100,
                cost_usd: Some(1.0),
            })
            .expect("worker reservation");
        let admission = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Auditor,
                tokens: 200,
                cost_usd: Some(2.0),
            })
            .expect("auditor reservation");

        let report = admission.report();
        let worker = report
            .roles
            .iter()
            .find(|role| role.role == AgentRole::Worker)
            .expect("worker report");
        let auditor = report
            .roles
            .iter()
            .find(|role| role.role == AgentRole::Auditor)
            .expect("auditor report");
        assert_eq!(worker.reserved.tokens, 100);
        assert_eq!(worker.active_reservations, 1);
        assert_eq!(auditor.reserved.tokens, 200);
        assert_eq!(auditor.active_reservations, 1);
        assert_eq!(report.reserved.tokens, 300);
    }

    #[test]
    fn estimated_usage_charges_at_least_the_reservation_and_latches_stop() {
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: Some(500),
            hard_tokens: Some(1_000),
            soft_cost_usd: Some(5.0),
            hard_cost_usd: Some(10.0),
        })
        .expect("ledger");
        let reservation =
            admitted_reservation(ledger.reserve(request(200, Some(2.0))).expect("reserve"));
        let reconciliation = ledger
            .reconcile(
                reservation.id,
                UsageMeasurement::Estimated {
                    tokens: 100,
                    cost_usd: Some(1.0),
                },
            )
            .expect("reconcile");

        assert_eq!(reconciliation.charged.tokens, 200);
        assert_eq!(reconciliation.charged.cost_usd, None);
        assert_eq!(reconciliation.report.consumed.cost_usd, None);
        assert!(!reconciliation.report.usage_complete);
        assert!(!reconciliation.report.new_dispatch_allowed);
        assert_eq!(reconciliation.report.action, BudgetAction::OwnerEscalation);
        assert!(reconciliation
            .report
            .reasons
            .contains(&BudgetReason::EstimatedProviderUsage));
    }

    #[test]
    fn reliable_tokens_with_missing_actual_cost_stop_cost_enforcement() {
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: Some(500),
            hard_tokens: Some(1_000),
            soft_cost_usd: Some(5.0),
            hard_cost_usd: Some(10.0),
        })
        .expect("ledger");
        let reservation =
            admitted_reservation(ledger.reserve(request(200, Some(2.0))).expect("reserve"));
        let reconciliation = ledger
            .reconcile(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 150,
                    cost_usd: None,
                },
            )
            .expect("reconcile");

        assert_eq!(reconciliation.charged.tokens, 150);
        assert_eq!(reconciliation.charged.cost_usd, None);
        assert_eq!(reconciliation.report.consumed.cost_usd, None);
        assert_eq!(reconciliation.report.committed.cost_usd, None);
        assert_eq!(reconciliation.report.remaining.hard_cost_usd, None);
        assert!(reconciliation.report.usage_complete);
        assert!(!reconciliation.report.new_dispatch_allowed);
        assert_eq!(reconciliation.report.action, BudgetAction::OwnerEscalation);
        assert!(reconciliation
            .report
            .reasons
            .contains(&BudgetReason::MissingActualCost));
    }

    #[test]
    fn missing_usage_preserves_the_reserved_charge_without_claiming_known_cost() {
        let ledger = RunBudgetLedger::new(token_limits(500, 1_000)).expect("ledger");
        let reservation =
            admitted_reservation(ledger.reserve(request(250, Some(2.5))).expect("reserve"));
        let reconciliation = ledger
            .reconcile(reservation.id, UsageMeasurement::Missing)
            .expect("reconcile");

        assert_eq!(reconciliation.charged.tokens, 250);
        assert_eq!(reconciliation.charged.cost_usd, None);
        assert_eq!(reconciliation.report.consumed.tokens, 250);
        assert_eq!(reconciliation.report.consumed.cost_usd, None);
        assert!(reconciliation
            .report
            .reasons
            .contains(&BudgetReason::MissingProviderUsage));
        assert!(!reconciliation.report.new_dispatch_allowed);
    }

    #[test]
    fn missing_pricing_is_refused_when_cost_is_enforced_and_explicit_otherwise() {
        let cost_ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: None,
            hard_tokens: Some(1_000),
            soft_cost_usd: Some(1.0),
            hard_cost_usd: Some(2.0),
        })
        .expect("cost ledger");
        let refusal = cost_ledger.reserve(request(100, None)).expect("refusal");
        assert!(matches!(
            refusal,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::MissingCostEstimate,
                ..
            }
        ));
        assert_eq!(cost_ledger.report().expect("report").reserved.tokens, 0);
        assert!(
            !cost_ledger
                .report()
                .expect("latched pricing refusal")
                .new_dispatch_allowed
        );

        let token_ledger = RunBudgetLedger::new(token_limits(500, 1_000)).expect("token ledger");
        let admission = token_ledger
            .reserve(request(100, None))
            .expect("token-only admission");
        assert_eq!(admission.report().reserved.cost_usd, None);
        assert_eq!(admission.report().action, BudgetAction::Degrade);
        assert!(admission
            .report()
            .reasons
            .contains(&BudgetReason::MissingPricing));
    }

    #[test]
    fn release_restores_reserved_capacity_without_consumption() {
        let ledger = RunBudgetLedger::new(token_limits(70, 100)).expect("ledger");
        let reservation =
            admitted_reservation(ledger.reserve(request(70, Some(0.7))).expect("reserve"));
        let release = ledger.release(reservation.id).expect("release");

        assert_eq!(release.reservation, reservation);
        assert_eq!(release.report.consumed.tokens, 0);
        assert_eq!(release.report.reserved.tokens, 0);
        assert!(release.report.new_dispatch_allowed);
    }
}
