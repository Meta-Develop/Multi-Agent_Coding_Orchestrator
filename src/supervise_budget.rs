//! Atomically synchronized budget accounting for one supervise run.
//!
//! Reservations are admitted before dispatch and reconciled after provider usage is available.
//! The ledger deliberately treats missing prices and unreliable usage as unknown accounting, not
//! as zero cost. This module is kept private to `supervise` so the run lifecycle remains the single
//! owner of both usage accounting and enforcement.

use crate::{
    artifacts::state_auth::random_identifier,
    budget_ledger::{
        current_rolling_binding, provider_error_is_rate_limited, unix_now,
        CompletedPoolConsumption, DurableBudgetReconciliation, DurableBudgetReservation,
        RollingBudgetQuota, WorkspaceBudgetLedger,
    },
    llm::ProviderError,
    optimizer::quota_pools::{ConsumptionLedger, PoolKey, QuotaConfig},
    supervise::AgentRole,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
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
            (Some(soft), Some(hard)) if cost_exceeds(soft, hard)
        ) {
            return Err(BudgetError::InvalidLimitOrder { resource: "cost" });
        }
        Ok(self)
    }

    pub(crate) fn strictest(self, other: Self) -> Result<Self> {
        fn min_optional<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
            match (left, right) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            }
        }
        fn min_cost(left: Option<f64>, right: Option<f64>) -> Option<f64> {
            match (left, right) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            }
        }
        self.validate()?;
        other.validate()?;
        let hard_tokens = min_optional(self.hard_tokens, other.hard_tokens);
        let hard_cost_usd = min_cost(self.hard_cost_usd, other.hard_cost_usd);
        let soft_tokens = min_optional(
            min_optional(self.soft_tokens, other.soft_tokens),
            hard_tokens,
        );
        let soft_cost_usd = min_cost(
            min_cost(self.soft_cost_usd, other.soft_cost_usd),
            hard_cost_usd,
        );
        Self {
            soft_tokens,
            hard_tokens,
            soft_cost_usd,
            hard_cost_usd,
        }
        .validate()
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetReason {
    SoftTokenCeilingReached,
    HardTokenCeilingReached,
    SoftCostCeilingReached,
    HardCostCeilingReached,
    MaxDurationReached,
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
pub struct RunBudgetSource {
    pub limits: RunBudgetLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudgetSources {
    pub plan: RunBudgetSource,
    pub cli: RunBudgetSource,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudgetReport {
    pub limits: RunBudgetLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    /// Original plan and CLI ceilings before strictest-wins composition.
    /// Present only when a CLI flag actually set a token, cost, or duration bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<RunBudgetSources>,
    pub consumed: BudgetAmount,
    pub reserved: BudgetAmount,
    pub committed: BudgetAmount,
    pub remaining: BudgetRemaining,
    #[serde(default)]
    pub elapsed_seconds: u64,
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
    #[error("workspace rolling budget ledger is unavailable or corrupt: {0}")]
    RollingLedgerUnavailable(String),
    #[error("operator quota config is invalid: {0}")]
    QuotaConfigInvalid(String),
    #[error("operator quota pool is unavailable for runtime '{0}'")]
    QuotaPoolUnavailable(String),
    #[error("failed to create a unique run-budget ledger session: {0}")]
    SessionIdentityUnavailable(String),
}

pub(super) type Result<T> = std::result::Result<T, BudgetError>;

#[derive(Debug, Clone)]
pub(super) struct RunBudgetLedger {
    limits: RunBudgetLimits,
    max_duration_seconds: Option<u64>,
    sources: Option<RunBudgetSources>,
    started_at: Instant,
    session_id: String,
    inner: Arc<Mutex<LedgerState>>,
    rolling: Option<Arc<Mutex<AttachedRollingBudget>>>,
}

#[derive(Debug)]
struct AttachedRollingBudget {
    ledger: WorkspaceBudgetLedger,
    quota: Option<RollingBudgetQuota>,
    repo: PathBuf,
    run_id: String,
    quota_pools: BTreeMap<String, PoolKey>,
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

fn rolling_binding_matches_supervisor_run(binding_run_id: &str, supervisor_run_id: &str) -> bool {
    binding_run_id == supervisor_run_id
        || supervisor_run_id
            .strip_suffix("-supervise")
            .is_some_and(|parent| parent == binding_run_id)
}

impl RunBudgetLedger {
    #[cfg(test)]
    pub(super) fn new(limits: RunBudgetLimits) -> Result<Self> {
        Self::new_with_duration(limits, None)
    }

    #[cfg(test)]
    pub(super) fn new_with_duration(
        limits: RunBudgetLimits,
        max_duration_seconds: Option<u64>,
    ) -> Result<Self> {
        Self::new_composed(
            limits,
            RunBudgetLimits::default(),
            max_duration_seconds,
            None,
        )
    }

    /// Compose plan and CLI ceilings by taking the strictest bound of each
    /// resource, and retain both inputs on the ledger when the CLI set any.
    pub(super) fn new_composed(
        plan_limits: RunBudgetLimits,
        cli_limits: RunBudgetLimits,
        plan_max_duration_seconds: Option<u64>,
        cli_max_duration_seconds: Option<u64>,
    ) -> Result<Self> {
        validate_duration(plan_max_duration_seconds)?;
        validate_duration(cli_max_duration_seconds)?;
        let limits = plan_limits.strictest(cli_limits)?;
        let max_duration_seconds = match (plan_max_duration_seconds, cli_max_duration_seconds) {
            (Some(plan), Some(cli)) => Some(plan.min(cli)),
            (plan, cli) => plan.or(cli),
        };
        let sources = (cli_limits.has_any_ceiling() || cli_max_duration_seconds.is_some())
            .then_some(RunBudgetSources {
                plan: RunBudgetSource {
                    limits: plan_limits,
                    max_duration_seconds: plan_max_duration_seconds,
                },
                cli: RunBudgetSource {
                    limits: cli_limits,
                    max_duration_seconds: cli_max_duration_seconds,
                },
            });
        let mut ledger = Self {
            limits,
            max_duration_seconds,
            sources,
            started_at: Instant::now(),
            session_id: random_identifier()
                .map_err(|error| BudgetError::SessionIdentityUnavailable(format!("{error:#}")))?,
            inner: Arc::new(Mutex::new(LedgerState::default())),
            rolling: None,
        };
        ledger.attach_rolling_budget()?;
        Ok(ledger)
    }

    fn attach_rolling_budget(&mut self) -> Result<()> {
        let Some(binding) = current_rolling_binding() else {
            return Ok(());
        };
        let ledger =
            WorkspaceBudgetLedger::open_or_create(&binding.repo).map_err(rolling_ledger_error)?;
        let attached = AttachedRollingBudget {
            ledger,
            quota: Some(binding.quota),
            repo: binding.repo,
            run_id: binding.run_id,
            quota_pools: BTreeMap::new(),
        };
        let now = unix_now().map_err(rolling_ledger_error)?;
        if let Some(reasons) = attached.admission_block_reasons(now)? {
            let mut state = self.lock_state()?;
            state.force_stop = true;
            state.persistent_reasons.extend(reasons);
        }
        self.rolling = Some(Arc::new(Mutex::new(attached)));
        Ok(())
    }

    /// Attach the validated operator quota config to this run ledger before
    /// scheduler threads begin. The runtime map is immutable after attachment.
    pub(super) fn attach_quota_config(
        &mut self,
        repo: &Path,
        run_id: &str,
        config: &QuotaConfig,
    ) -> Result<()> {
        config
            .validate()
            .map_err(|error| BudgetError::QuotaConfigInvalid(error.to_string()))?;
        if run_id.is_empty() {
            return Err(BudgetError::QuotaConfigInvalid(
                "workspace quota run id cannot be empty".to_string(),
            ));
        }
        let quota_pools = config
            .pools
            .iter()
            .map(|pool| (pool.runtime.as_str().to_string(), pool.key()))
            .collect::<BTreeMap<_, _>>();
        if let Some(rolling) = &self.rolling {
            if Arc::strong_count(rolling) != 1 {
                return Err(BudgetError::QuotaConfigInvalid(
                    "operator quota config must be attached before the run ledger is shared"
                        .to_string(),
                ));
            }
            let mut attached = rolling.lock().map_err(|_| BudgetError::Poisoned)?;
            if attached.repo != repo
                || !rolling_binding_matches_supervisor_run(&attached.run_id, run_id)
            {
                return Err(BudgetError::QuotaConfigInvalid(
                    "operator quota config repository/run binding does not match the rolling budget ledger"
                        .to_string(),
                ));
            }
            attached.quota_pools = quota_pools;
            return Ok(());
        }

        let ledger = WorkspaceBudgetLedger::open_or_create(repo).map_err(rolling_ledger_error)?;
        self.rolling = Some(Arc::new(Mutex::new(AttachedRollingBudget {
            ledger,
            quota: None,
            repo: repo.to_path_buf(),
            run_id: run_id.to_string(),
            quota_pools,
        })));
        Ok(())
    }

    pub(super) fn effective_limits(&self) -> RunBudgetLimits {
        self.limits
    }

    #[cfg(test)]
    fn new_with_elapsed(
        limits: RunBudgetLimits,
        max_duration_seconds: Option<u64>,
        elapsed: Duration,
    ) -> Result<Self> {
        let mut ledger = Self::new_with_duration(limits, max_duration_seconds)?;
        ledger.started_at = Instant::now() - elapsed;
        Ok(ledger)
    }

    /// Atomically checks the current commitments and reserves budget before dispatch.
    pub(super) fn reserve(&self, request: BudgetReservationRequest) -> Result<BudgetAdmission> {
        validate_reservation_request(&request)?;
        let mut state = self.lock_state()?;
        let current_report = self.report_for_state(&state)?;
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
            let report = self.report_for_state(&next)?;
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
            let report = self.report_for_state(&next)?;
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
            if cost_exceeds(projected_cost_usd, limit_usd) {
                let mut next = state.clone();
                next.force_stop = true;
                next.persistent_reasons
                    .insert(BudgetReason::HardCostCeilingReached);
                let report = self.report_for_state(&next)?;
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

        if let Some(refusal) = self.rolling_admission_refusal(&state, &request)? {
            let mut next = state.clone();
            next.force_stop = true;
            match &refusal {
                BudgetAdmissionRefusal::HardTokenCeiling { .. } => {
                    next.persistent_reasons
                        .insert(BudgetReason::HardTokenCeilingReached);
                }
                BudgetAdmissionRefusal::HardCostCeiling { .. } => {
                    next.persistent_reasons
                        .insert(BudgetReason::HardCostCeilingReached);
                }
                BudgetAdmissionRefusal::MissingCostEstimate => {
                    next.persistent_reasons.insert(BudgetReason::MissingPricing);
                }
                BudgetAdmissionRefusal::NewDispatchStopped => {}
            }
            let report = self.report_for_state(&next)?;
            *state = next;
            return Ok(BudgetAdmission::Refused { refusal, report });
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
        let report = self.report_for_state(&next)?;
        self.persist_rolling_reservation(&reservation)?;
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
        self.reconcile_with_pool(id, measurement, None)
    }

    /// Reconcile a completed dispatch into both the run budget and the unique
    /// configured quota pool for `runtime`.
    pub(super) fn reconcile_quota_runtime(
        &self,
        id: BudgetReservationId,
        measurement: UsageMeasurement,
        runtime: &str,
    ) -> Result<BudgetReconciliation> {
        let pool = {
            let rolling = self
                .lock_rolling()?
                .ok_or_else(|| BudgetError::QuotaPoolUnavailable(runtime.to_string()))?;
            rolling
                .quota_pools
                .get(runtime)
                .cloned()
                .ok_or_else(|| BudgetError::QuotaPoolUnavailable(runtime.to_string()))?
        };
        self.reconcile_with_pool(id, measurement, Some(pool))
    }

    /// Reconcile through the configured per-runtime pool when a quota config
    /// was attached, otherwise preserve the legacy aggregate-only behavior.
    pub(super) fn reconcile_for_runtime_if_configured(
        &self,
        id: BudgetReservationId,
        measurement: UsageMeasurement,
        runtime: Option<&str>,
    ) -> Result<BudgetReconciliation> {
        let quota_configured = self
            .lock_rolling()?
            .is_some_and(|rolling| !rolling.quota_pools.is_empty());
        if quota_configured {
            let runtime = runtime.ok_or_else(|| {
                BudgetError::QuotaPoolUnavailable("<missing-runtime>".to_string())
            })?;
            self.reconcile_quota_runtime(id, measurement, runtime)
        } else {
            self.reconcile(id, measurement)
        }
    }

    /// Read a fresh selector projection through the same held authenticated
    /// ledger instance used for completed reconciliation writes.
    pub(super) fn quota_consumption_ledger(
        &self,
        config: &QuotaConfig,
        now_unix_seconds: u64,
    ) -> Result<ConsumptionLedger> {
        let attached = self.lock_rolling()?.ok_or_else(|| {
            BudgetError::QuotaConfigInvalid(
                "operator quota config is not attached to the run ledger".to_string(),
            )
        })?;
        if attached.quota_pools.is_empty() {
            return Err(BudgetError::QuotaConfigInvalid(
                "operator quota config is not attached to the run ledger".to_string(),
            ));
        }
        attached
            .ledger
            .quota_consumption_ledger(config, now_unix_seconds)
            .map_err(rolling_ledger_error)
    }

    fn reconcile_with_pool(
        &self,
        id: BudgetReservationId,
        measurement: UsageMeasurement,
        pool: Option<PoolKey>,
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
        let rolling_reasons = self.persist_rolling_consumption(id, &charge, pool.as_ref())?;
        if !rolling_reasons.is_empty() {
            next.persistent_reasons.extend(rolling_reasons);
            next.force_stop = true;
        }
        let report = self.report_for_state(&next)?;
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

    /// Releases this run's in-memory reservation.
    ///
    /// When an aggregate rolling quota is attached, the durable reservation is
    /// conservatively charged in full: callers do not currently provide an
    /// authenticated pre-invocation state that would make a zero-use release
    /// safe after a process crash.
    pub(super) fn release(&self, id: BudgetReservationId) -> Result<BudgetRelease> {
        let mut state = self.lock_state()?;
        let mut next = state.clone();
        let reservation = remove_reservation(&mut next, id)?;
        let rolling_reasons = self.persist_conservative_rolling_abandonment(&reservation)?;
        if !rolling_reasons.is_empty() {
            next.persistent_reasons.extend(rolling_reasons);
            next.force_stop = true;
        }
        let report = self.report_for_state(&next)?;
        *state = next;
        Ok(BudgetRelease {
            reservation,
            report,
        })
    }

    pub(super) fn report(&self) -> Result<RunBudgetReport> {
        let state = self.lock_state()?;
        self.report_for_state(&state)
    }

    fn report_for_state(&self, state: &LedgerState) -> Result<RunBudgetReport> {
        report_for(
            self.limits,
            self.max_duration_seconds,
            self.sources.clone(),
            state,
            self.started_at.elapsed(),
        )
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, LedgerState>> {
        self.inner.lock().map_err(|_| BudgetError::Poisoned)
    }

    fn lock_rolling(&self) -> Result<Option<MutexGuard<'_, AttachedRollingBudget>>> {
        self.rolling
            .as_ref()
            .map(|rolling| rolling.lock().map_err(|_| BudgetError::Poisoned))
            .transpose()
    }

    fn rolling_admission_refusal(
        &self,
        state: &LedgerState,
        request: &BudgetReservationRequest,
    ) -> Result<Option<BudgetAdmissionRefusal>> {
        let Some(rolling) = self.lock_rolling()? else {
            return Ok(None);
        };
        let Some(quota) = rolling.quota else {
            return Ok(None);
        };
        let now = unix_now().map_err(rolling_ledger_error)?;
        if rolling.ledger.any_active_rate_limit(now).is_some() {
            return Ok(Some(BudgetAdmissionRefusal::NewDispatchStopped));
        }
        if request.cost_usd.is_none() && quota.max_cost_usd.is_some() {
            return Ok(Some(BudgetAdmissionRefusal::MissingCostEstimate));
        }
        let current_reservations = state
            .active
            .keys()
            .map(|id| durable_reservation_id(&rolling.run_id, &self.session_id, *id))
            .collect::<BTreeSet<_>>();
        let usage = rolling
            .ledger
            .usage_in_window_excluding(quota.window_seconds, now, &current_reservations)
            .map_err(rolling_ledger_error)?;
        let projected_tokens = usage
            .tokens
            .checked_add(state.reserved_tokens)
            .and_then(|tokens| tokens.checked_add(request.tokens))
            .ok_or(BudgetError::TokenOverflow)?;
        if let Some(limit) = quota.max_tokens.filter(|limit| projected_tokens > *limit) {
            return Ok(Some(BudgetAdmissionRefusal::HardTokenCeiling {
                limit,
                committed: usage
                    .tokens
                    .checked_add(state.reserved_tokens)
                    .ok_or(BudgetError::TokenOverflow)?,
                requested: request.tokens,
            }));
        }
        if let (Some(requested_usd), Some(limit_usd)) = (request.cost_usd, quota.max_cost_usd) {
            let Some(window_cost) = usage.cost_usd else {
                return Ok(Some(BudgetAdmissionRefusal::MissingCostEstimate));
            };
            let committed_usd = checked_cost_add(window_cost, state.reserved_cost_usd)?;
            let projected_cost_usd = checked_cost_add(committed_usd, requested_usd)?;
            if crate::budget_ledger::rolling_cost_exceeds(projected_cost_usd, limit_usd) {
                return Ok(Some(BudgetAdmissionRefusal::HardCostCeiling {
                    limit_usd,
                    committed_usd,
                    requested_usd,
                }));
            }
        }
        Ok(None)
    }

    fn persist_rolling_consumption(
        &self,
        reservation_id: BudgetReservationId,
        charge: &ReconciliationCharge,
        pool: Option<&PoolKey>,
    ) -> Result<Vec<BudgetReason>> {
        let Some(mut rolling) = self.lock_rolling()? else {
            return Ok(Vec::new());
        };
        let now = unix_now().map_err(rolling_ledger_error)?;
        let run_id = rolling.run_id.clone();
        let durable_id = durable_reservation_id(&run_id, &self.session_id, reservation_id);
        if rolling.quota.is_some() {
            rolling
                .ledger
                .reconcile_reservation(DurableBudgetReconciliation {
                    reservation_id: durable_id,
                    tokens: charge.tokens,
                    requests: if pool.is_some() { 1 } else { 0 },
                    cost_usd: charge.cost_complete.then_some(charge.cost_usd),
                    pool: pool.cloned(),
                    unix_seconds: now,
                })
                .map_err(rolling_ledger_error)?;
        } else if let Some(pool) = pool {
            let tokens = u64::try_from(charge.tokens).map_err(|_| BudgetError::TokenOverflow)?;
            rolling
                .ledger
                .record_completed_pool_consumption(CompletedPoolConsumption {
                    completion_id: format!(
                        "{run_id}/session/{}/reservation/{}",
                        self.session_id,
                        reservation_id.get()
                    ),
                    pool: pool.clone(),
                    tokens,
                    requests: 1,
                    cost_usd: charge.cost_complete.then_some(charge.cost_usd),
                    unix_seconds: now,
                })
                .map_err(rolling_ledger_error)?;
        }
        Ok(rolling.admission_block_reasons(now)?.unwrap_or_default())
    }

    fn persist_rolling_reservation(&self, reservation: &BudgetReservation) -> Result<()> {
        let Some(mut rolling) = self.lock_rolling()? else {
            return Ok(());
        };
        if rolling.quota.is_none() {
            return Ok(());
        }
        let now = unix_now().map_err(rolling_ledger_error)?;
        let reservation_id =
            durable_reservation_id(&rolling.run_id, &self.session_id, reservation.id);
        rolling
            .ledger
            .record_reservation(DurableBudgetReservation {
                reservation_id,
                tokens: reservation.tokens,
                cost_usd: reservation.cost_usd,
                unix_seconds: now,
            })
            .map_err(rolling_ledger_error)?;
        Ok(())
    }

    fn persist_conservative_rolling_abandonment(
        &self,
        reservation: &BudgetReservation,
    ) -> Result<Vec<BudgetReason>> {
        let Some(mut rolling) = self.lock_rolling()? else {
            return Ok(Vec::new());
        };
        if rolling.quota.is_none() {
            return Ok(Vec::new());
        }
        let now = unix_now().map_err(rolling_ledger_error)?;
        let reservation_id =
            durable_reservation_id(&rolling.run_id, &self.session_id, reservation.id);
        rolling
            .ledger
            .reconcile_reservation(DurableBudgetReconciliation {
                reservation_id,
                tokens: reservation.tokens,
                requests: 0,
                cost_usd: reservation.cost_usd,
                pool: None,
                unix_seconds: now,
            })
            .map_err(rolling_ledger_error)?;
        Ok(rolling.admission_block_reasons(now)?.unwrap_or_default())
    }

    /// Records a runtime provider error on the workspace rolling ledger.
    ///
    /// `ProviderError::RateLimited` latches the default pool for the configured
    /// window and stops new admission. Other errors are ignored. The runtime
    /// attachment seam lives here so dispatch paths can fail closed without
    /// this module depending on forbidden callers.
    #[allow(dead_code)]
    pub(super) fn record_provider_error(&self, error: &ProviderError) -> Result<()> {
        if !provider_error_is_rate_limited(error) {
            return Ok(());
        }
        let ProviderError::RateLimited(detail) = error else {
            return Ok(());
        };
        let mut state = self.lock_state()?;
        let Some(mut rolling) = self.lock_rolling()? else {
            return Err(BudgetError::RollingLedgerUnavailable(
                "provider rate limit reported without a bound rolling budget ledger".to_string(),
            ));
        };
        let now = unix_now().map_err(rolling_ledger_error)?;
        let window_seconds = rolling
            .quota
            .ok_or_else(|| {
                BudgetError::RollingLedgerUnavailable(
                    "provider rate-limit latching requires an aggregate rolling quota".to_string(),
                )
            })?
            .window_seconds;
        rolling
            .ledger
            .record_rate_limited(
                crate::budget_ledger::DEFAULT_RATE_LIMIT_POOL,
                detail,
                window_seconds,
                now,
            )
            .map_err(rolling_ledger_error)?;
        state.force_stop = true;
        state
            .persistent_reasons
            .insert(BudgetReason::MissingProviderUsage);
        Ok(())
    }
}

fn durable_reservation_id(
    run_id: &str,
    session_id: &str,
    reservation_id: BudgetReservationId,
) -> String {
    format!(
        "{run_id}/session/{session_id}/reservation/{}",
        reservation_id.get()
    )
}

impl AttachedRollingBudget {
    fn admission_block_reasons(&self, now: u64) -> Result<Option<Vec<BudgetReason>>> {
        let Some(quota) = self.quota else {
            return Ok(None);
        };
        if self.ledger.any_active_rate_limit(now).is_some() {
            return Ok(Some(vec![BudgetReason::MissingProviderUsage]));
        }
        let usage = self
            .ledger
            .usage_in_window(quota.window_seconds, now)
            .map_err(rolling_ledger_error)?;
        let mut reasons = Vec::new();
        if quota.max_tokens.is_some_and(|limit| usage.tokens >= limit) {
            reasons.push(BudgetReason::HardTokenCeilingReached);
        }
        if let Some(limit) = quota.max_cost_usd {
            match usage.cost_usd {
                Some(cost)
                    if crate::budget_ledger::rolling_cost_exceeds(cost, limit) || cost >= limit =>
                {
                    reasons.push(BudgetReason::HardCostCeilingReached);
                }
                None => reasons.push(BudgetReason::MissingPricing),
                Some(_) => {}
            }
        }
        if reasons.is_empty() {
            Ok(None)
        } else {
            Ok(Some(reasons))
        }
    }
}

fn rolling_ledger_error(error: anyhow::Error) -> BudgetError {
    BudgetError::RollingLedgerUnavailable(format!("{error:#}"))
}

fn validate_duration(value: Option<u64>) -> Result<()> {
    if value == Some(0) {
        return Err(BudgetError::ZeroLimit {
            name: "maximum duration",
        });
    }
    Ok(())
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

fn report_for(
    limits: RunBudgetLimits,
    max_duration_seconds: Option<u64>,
    sources: Option<RunBudgetSources>,
    state: &LedgerState,
    elapsed: Duration,
) -> Result<RunBudgetReport> {
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
            .is_some_and(|limit| cost_reaches(committed_cost_usd, limit));
    if soft_cost_reached {
        reasons.insert(BudgetReason::SoftCostCeilingReached);
    }
    let hard_cost_reached = committed_cost_complete
        && limits
            .hard_cost_usd
            .is_some_and(|limit| cost_reaches(committed_cost_usd, limit));
    if hard_cost_reached {
        reasons.insert(BudgetReason::HardCostCeilingReached);
    }
    let max_duration_reached =
        max_duration_seconds.is_some_and(|limit| elapsed >= Duration::from_secs(limit));
    if max_duration_reached {
        reasons.insert(BudgetReason::MaxDurationReached);
    }
    let cost_ceiling_unenforceable = limits.has_cost_ceiling() && !committed_cost_complete;
    let new_dispatch_allowed = !state.force_stop
        && !hard_tokens_reached
        && !hard_cost_reached
        && !max_duration_reached
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
        max_duration_seconds,
        sources,
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
                        .map(|limit| cost_remaining(limit, committed_cost_usd))
                        .transpose()
                })
                .transpose()?
                .flatten(),
            hard_cost_usd: committed_cost_complete
                .then(|| {
                    limits
                        .hard_cost_usd
                        .map(|limit| cost_remaining(limit, committed_cost_usd))
                        .transpose()
                })
                .transpose()?
                .flatten(),
            max_duration_seconds: max_duration_seconds
                .map(|limit| limit.saturating_sub(elapsed.as_secs())),
        },
        elapsed_seconds: elapsed.as_secs(),
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

fn cost_tolerance(left: f64, right: f64) -> f64 {
    f64::EPSILON * left.abs().max(right.abs()) * 8.0
}

fn cost_exceeds(value: f64, limit: f64) -> bool {
    value - limit > cost_tolerance(value, limit)
}

fn cost_reaches(value: f64, limit: f64) -> bool {
    !cost_exceeds(limit, value)
}

fn cost_remaining(limit: f64, committed: f64) -> Result<f64> {
    if cost_reaches(committed, limit) {
        Ok(0.0)
    } else {
        checked_cost_sub(limit, committed)
    }
}

fn checked_cost_sub(total: f64, amount: f64) -> Result<f64> {
    let remaining = total - amount;
    if !remaining.is_finite() {
        return Err(BudgetError::CostOverflow);
    }
    if remaining < -cost_tolerance(total, amount) {
        return Err(BudgetError::InconsistentState);
    }
    Ok(remaining.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        process::{Command, Stdio},
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
    fn cli_hard_limits_tighten_plan_limits_and_clamp_soft_thresholds() {
        let plan = RunBudgetLimits {
            soft_tokens: Some(100),
            hard_tokens: Some(200),
            soft_cost_usd: Some(0.5),
            hard_cost_usd: Some(1.0),
        };
        let cli = RunBudgetLimits {
            hard_tokens: Some(50),
            hard_cost_usd: Some(0.4),
            ..RunBudgetLimits::default()
        };

        assert_eq!(
            plan.strictest(cli).expect("compose strictest limits"),
            RunBudgetLimits {
                soft_tokens: Some(50),
                hard_tokens: Some(50),
                soft_cost_usd: Some(0.4),
                hard_cost_usd: Some(0.4),
            }
        );
    }

    #[test]
    fn composed_cli_overrides_persist_plan_and_cli_sources_on_the_ledger() {
        let plan = RunBudgetLimits {
            soft_tokens: Some(100),
            hard_tokens: Some(200),
            soft_cost_usd: Some(0.5),
            hard_cost_usd: Some(1.0),
        };
        let cli = RunBudgetLimits {
            hard_tokens: Some(50),
            hard_cost_usd: Some(0.4),
            ..RunBudgetLimits::default()
        };
        let ledger = RunBudgetLedger::new_composed(plan, cli, Some(600), Some(300))
            .expect("composed ledger");
        let report = ledger.report().expect("composed report");

        assert_eq!(
            report.limits,
            RunBudgetLimits {
                soft_tokens: Some(50),
                hard_tokens: Some(50),
                soft_cost_usd: Some(0.4),
                hard_cost_usd: Some(0.4),
            }
        );
        assert_eq!(report.max_duration_seconds, Some(300));
        assert_eq!(
            report.sources,
            Some(RunBudgetSources {
                plan: RunBudgetSource {
                    limits: plan,
                    max_duration_seconds: Some(600),
                },
                cli: RunBudgetSource {
                    limits: cli,
                    max_duration_seconds: Some(300),
                },
            })
        );

        let plan_only = RunBudgetLedger::new_with_duration(plan, Some(600)).expect("plan ledger");
        assert!(plan_only
            .report()
            .expect("plan-only report")
            .sources
            .is_none());
    }

    #[test]
    fn elapsed_duration_stops_new_dispatch_and_is_reported() {
        let ledger = RunBudgetLedger::new_with_elapsed(
            RunBudgetLimits::default(),
            Some(5),
            Duration::from_secs(6),
        )
        .expect("duration ledger");

        let report = ledger.report().expect("duration report");
        assert_eq!(report.max_duration_seconds, Some(5));
        assert!(report.elapsed_seconds >= 6);
        assert_eq!(report.remaining.max_duration_seconds, Some(0));
        assert!(!report.new_dispatch_allowed);
        assert_eq!(report.action, BudgetAction::OwnerEscalation);
        assert!(report.reasons.contains(&BudgetReason::MaxDurationReached));
        assert!(matches!(
            ledger.reserve(request(1, None)).expect("duration refusal"),
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::NewDispatchStopped,
                ..
            }
        ));

        assert_eq!(
            RunBudgetLedger::new_with_duration(RunBudgetLimits::default(), Some(0))
                .expect_err("zero duration must fail"),
            BudgetError::ZeroLimit {
                name: "maximum duration"
            }
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
    fn decimal_exact_hard_cost_boundary_is_admitted_with_zero_remaining() {
        let ledger = RunBudgetLedger::new(cost_limits(0.1, 0.3)).expect("decimal cost ledger");
        admitted_reservation(
            ledger
                .reserve(request(100, Some(0.1)))
                .expect("first decimal reservation"),
        );

        let exact = ledger
            .reserve(request(100, Some(0.2)))
            .expect("decimal exact-boundary reservation");
        assert!(exact.reservation().is_some());
        assert_eq!(exact.report().remaining.hard_cost_usd, Some(0.0));
        assert_eq!(exact.report().action, BudgetAction::OwnerEscalation);
        assert!(!exact.report().new_dispatch_allowed);
        assert!(exact
            .report()
            .reasons
            .contains(&BudgetReason::HardCostCeilingReached));

        let over_ledger =
            RunBudgetLedger::new(cost_limits(0.1, 0.3)).expect("near-over cost ledger");
        admitted_reservation(
            over_ledger
                .reserve(request(100, Some(0.1)))
                .expect("near-over first reservation"),
        );
        assert!(matches!(
            over_ledger
                .reserve(request(100, Some(0.200_001)))
                .expect("near-over boundary refusal"),
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardCostCeiling { .. },
                ..
            }
        ));
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
        let state = ledger
            .lock_state()
            .expect("inspect conservative estimated charge");
        assert_eq!(state.consumed_cost_usd, 2.0);
    }

    #[test]
    fn uncertain_settlement_latch_survives_later_success_of_already_admitted_dispatch() {
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: Some(500),
            hard_tokens: Some(1_000),
            soft_cost_usd: Some(5.0),
            hard_cost_usd: Some(10.0),
        })
        .expect("ledger");
        let uncertain =
            admitted_reservation(ledger.reserve(request(200, Some(2.0))).expect("reserve A"));
        let later_success =
            admitted_reservation(ledger.reserve(request(200, Some(2.0))).expect("reserve B"));

        let uncertain_reconciliation = ledger
            .reconcile(
                uncertain.id,
                UsageMeasurement::Estimated {
                    tokens: 100,
                    cost_usd: Some(1.0),
                },
            )
            .expect("reconcile A");
        assert!(!uncertain_reconciliation.report.new_dispatch_allowed);
        assert_eq!(
            uncertain_reconciliation.report.action,
            BudgetAction::OwnerEscalation
        );

        let successful_reconciliation = ledger
            .reconcile(
                later_success.id,
                UsageMeasurement::Reliable {
                    tokens: 100,
                    cost_usd: Some(1.0),
                },
            )
            .expect("reconcile B");
        assert_eq!(successful_reconciliation.report.active_reservations, 0);
        assert_eq!(
            successful_reconciliation.report.reserved,
            BudgetAmount {
                tokens: 0,
                cost_usd: Some(0.0),
            }
        );
        assert!(!successful_reconciliation.report.new_dispatch_allowed);
        assert_eq!(
            successful_reconciliation.report.action,
            BudgetAction::OwnerEscalation
        );
        assert!(successful_reconciliation
            .report
            .reasons
            .contains(&BudgetReason::EstimatedProviderUsage));

        assert!(matches!(
            ledger.reserve(request(1, Some(0.01))).expect("refuse C"),
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::NewDispatchStopped,
                ..
            }
        ));
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

    fn rolling_repo() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::TempDir::new().expect("temporary directory");
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo).expect("initialize repository");
        (temp, repo)
    }

    fn rolling_quota(max_tokens: usize) -> crate::budget_ledger::RollingBudgetQuota {
        crate::budget_ledger::RollingBudgetQuota {
            max_tokens: Some(max_tokens),
            max_cost_usd: None,
            window_seconds: crate::budget_ledger::DEFAULT_ROLLING_WINDOW_SECONDS,
        }
    }

    fn quota_config(runtime: &str) -> QuotaConfig {
        QuotaConfig {
            version: crate::optimizer::quota_pools::QUOTA_CONFIG_VERSION,
            pools: vec![crate::optimizer::quota_pools::EntitlementDescriptor {
                runtime: crate::optimizer::ids::RuntimeSlug::new(runtime).expect("runtime"),
                account: crate::optimizer::quota_pools::AccountId::new("operator")
                    .expect("account"),
                pool_kind: crate::optimizer::quota_pools::PoolKind::Metered,
                window: crate::optimizer::quota_pools::ResetWindow::None,
                nominal_capacity: crate::optimizer::quota_pools::NominalCapacity::Unknown,
                rate_limits: crate::optimizer::quota_pools::RateLimits::default(),
                priority_tier: None,
                exhaustion_behavior: crate::optimizer::quota_pools::ExhaustionBehavior::FailClosed,
                authorized_alternatives: Vec::new(),
                declared_list_price_microunits: Some(1),
            }],
        }
    }

    #[test]
    fn quota_config_attachment_routes_completed_reconciliation_to_pool() {
        let (_temp, repo) = rolling_repo();
        let config = quota_config("gpt-5.6-sol");
        let mut ledger = RunBudgetLedger::new(RunBudgetLimits::default()).expect("run ledger");
        ledger
            .attach_quota_config(&repo, "quota-run", &config)
            .expect("attach config");
        let reservation =
            admitted_reservation(ledger.reserve(request(20, Some(0.2))).expect("reserve"));
        ledger
            .reconcile_for_runtime_if_configured(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 12,
                    cost_usd: Some(0.12),
                },
                Some("gpt-5.6-sol"),
            )
            .expect("reconcile pool");

        drop(ledger);
        let workspace = WorkspaceBudgetLedger::open_or_create(&repo).expect("workspace ledger");
        let usage = workspace
            .pool_usage(
                &config.pools[0].key(),
                crate::budget_ledger::unix_now().expect("now"),
            )
            .expect("pool usage");
        assert_eq!(usage.tokens, 12);
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.cost_usd, Some(0.12));
    }

    #[test]
    fn autopilot_outer_rolling_binding_composes_only_with_exact_nested_supervise_identity() {
        let (_temp, repo) = rolling_repo();
        let _guard =
            crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(100), "autopilot-run")
                .expect("bind outer Autopilot rolling budget");
        let config = quota_config("codex");
        let mut nested =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("nested supervisor run ledger");
        nested
            .attach_quota_config(&repo, "autopilot-run-supervise", &config)
            .expect("exact nested supervise identity composes with outer binding");
        let reservation = admitted_reservation(
            nested
                .reserve(request(9, None))
                .expect("combined rolling and quota reservation"),
        );
        nested
            .reconcile_for_runtime_if_configured(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 9,
                    cost_usd: None,
                },
                Some("codex"),
            )
            .expect("combined rolling and exact quota reconciliation");
        drop(nested);

        let mut unrelated =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("unrelated supervisor ledger");
        assert!(matches!(
            unrelated.attach_quota_config(&repo, "autopilot-run-worker", &config),
            Err(BudgetError::QuotaConfigInvalid(message))
                if message.contains("repository/run binding")
        ));
        drop(unrelated);
        drop(_guard);

        let workspace = WorkspaceBudgetLedger::open_or_create(&repo).expect("reopen workspace");
        let usage = workspace
            .pool_usage(
                &config.pools[0].key(),
                crate::budget_ledger::unix_now().expect("now"),
            )
            .expect("nested quota usage");
        assert_eq!(usage.tokens, 9);
        assert_eq!(usage.requests, 1);
    }

    #[test]
    fn runtime_aware_reconcile_preserves_no_config_behavior_and_refuses_unknown_configured_pool() {
        let legacy = RunBudgetLedger::new(RunBudgetLimits::default()).expect("legacy ledger");
        let reservation =
            admitted_reservation(legacy.reserve(request(10, None)).expect("legacy reserve"));
        legacy
            .reconcile_for_runtime_if_configured(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 8,
                    cost_usd: None,
                },
                Some("unconfigured-runtime"),
            )
            .expect("legacy reconcile ignores quota runtime without config");
        assert_eq!(legacy.report().expect("legacy report").consumed.tokens, 8);

        let (_temp, repo) = rolling_repo();
        let mut configured =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("configured ledger");
        configured
            .attach_quota_config(&repo, "configured-run", &quota_config("configured"))
            .expect("attach config");
        let reservation = admitted_reservation(
            configured
                .reserve(request(10, None))
                .expect("configured reserve"),
        );
        assert!(matches!(
            configured.reconcile_for_runtime_if_configured(
                reservation.id,
                UsageMeasurement::Reliable {
                    tokens: 8,
                    cost_usd: None,
                },
                Some("unknown"),
            ),
            Err(BudgetError::QuotaPoolUnavailable(runtime)) if runtime == "unknown"
        ));
        configured
            .release(reservation.id)
            .expect("unknown runtime did not consume reservation");
    }

    #[test]
    fn resumed_run_session_does_not_alias_a_new_reservation_one_completion() {
        let (_temp, repo) = rolling_repo();
        let config = quota_config("gpt-5.6-sol");
        for tokens in [11, 13] {
            let mut ledger =
                RunBudgetLedger::new(RunBudgetLimits::default()).expect("run ledger session");
            ledger
                .attach_quota_config(&repo, "same-run-id", &config)
                .expect("attach same run id");
            let reservation = admitted_reservation(
                ledger
                    .reserve(request(tokens, None))
                    .expect("reservation one"),
            );
            assert_eq!(reservation.id.get(), 1);
            ledger
                .reconcile_for_runtime_if_configured(
                    reservation.id,
                    UsageMeasurement::Reliable {
                        tokens,
                        cost_usd: None,
                    },
                    Some("gpt-5.6-sol"),
                )
                .expect("record distinct session completion");
        }
        let workspace = WorkspaceBudgetLedger::open_or_create(&repo).expect("workspace ledger");
        let usage = workspace
            .pool_usage(
                &config.pools[0].key(),
                crate::budget_ledger::unix_now().expect("now"),
            )
            .expect("combined pool usage");
        assert_eq!(usage.tokens, 24);
        assert_eq!(usage.requests, 2);
    }

    #[test]
    fn rolling_quota_refuses_when_the_workspace_window_is_exhausted() {
        let (_temp, repo) = rolling_repo();
        let _guard = crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(50), "run-a")
            .expect("bind rolling quota");
        let ledger = RunBudgetLedger::new(RunBudgetLimits::default()).expect("rolling ledger");
        let first = admitted_reservation(ledger.reserve(request(40, None)).expect("reserve"));
        ledger
            .reconcile(
                first.id,
                UsageMeasurement::Reliable {
                    tokens: 40,
                    cost_usd: None,
                },
            )
            .expect("reconcile");

        let refused = ledger.reserve(request(20, None)).expect("rolling refusal");
        assert!(matches!(
            refused,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling { limit: 50, .. },
                ..
            }
        ));
        assert!(!refused.report().new_dispatch_allowed);
    }

    #[test]
    fn second_run_sees_first_run_rolling_consumption() {
        let (_temp, repo) = rolling_repo();
        let _guard = crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(100), "run-1")
            .expect("bind rolling quota");
        {
            let first = RunBudgetLedger::new(RunBudgetLimits::default()).expect("first run");
            let reservation =
                admitted_reservation(first.reserve(request(80, None)).expect("first reserve"));
            first
                .reconcile(
                    reservation.id,
                    UsageMeasurement::Reliable {
                        tokens: 80,
                        cost_usd: None,
                    },
                )
                .expect("first reconcile");
            assert_eq!(first.report().expect("first report").consumed.tokens, 80);
        }

        let second = RunBudgetLedger::new(RunBudgetLimits::default()).expect("second run");
        assert!(second.report().expect("second report").new_dispatch_allowed);
        let remaining = admitted_reservation(
            second
                .reserve(request(20, None))
                .expect("remaining reserve"),
        );
        assert_eq!(remaining.tokens, 20);
        assert!(matches!(
            second
                .reserve(request(1, None))
                .expect("over-window refusal"),
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling {
                    limit: 100,
                    committed: 100,
                    requested: 1,
                },
                ..
            }
        ));
    }

    #[test]
    fn aggregate_release_is_conservatively_charged_across_runs() {
        let (_temp, repo) = rolling_repo();
        let _guard =
            crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(100), "release-run")
                .expect("bind rolling quota");
        {
            let first = RunBudgetLedger::new(RunBudgetLimits::default()).expect("first run");
            let reservation =
                admitted_reservation(first.reserve(request(60, None)).expect("reserve"));
            let released = first.release(reservation.id).expect("release locally");
            assert_eq!(released.report.consumed.tokens, 0);
            assert_eq!(released.report.committed.tokens, 0);
        }

        let second = RunBudgetLedger::new(RunBudgetLimits::default()).expect("second run");
        let refused = second
            .reserve(request(50, None))
            .expect("aggregate refusal");
        assert!(matches!(
            refused,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling {
                    limit: 100,
                    committed: 60,
                    requested: 50,
                },
                ..
            }
        ));
    }

    #[test]
    fn aggregate_reconciliation_replaces_reservation_without_double_counting() {
        let (_temp, repo) = rolling_repo();
        let _guard =
            crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(100), "reconcile-run")
                .expect("bind rolling quota");
        {
            let first = RunBudgetLedger::new(RunBudgetLimits::default()).expect("first run");
            let reservation =
                admitted_reservation(first.reserve(request(80, None)).expect("reserve"));
            first
                .reconcile(
                    reservation.id,
                    UsageMeasurement::Reliable {
                        tokens: 20,
                        cost_usd: None,
                    },
                )
                .expect("reconcile actual usage");
        }

        let second = RunBudgetLedger::new(RunBudgetLimits::default()).expect("second run");
        let remaining = admitted_reservation(second.reserve(request(80, None)).expect("reserve"));
        assert_eq!(remaining.tokens, 80);
        assert!(matches!(
            second.reserve(request(1, None)).expect("aggregate refusal"),
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling {
                    limit: 100,
                    committed: 100,
                    requested: 1,
                },
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn midflight_process_death_recovers_reserved_aggregate_usage() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_REPO_ENV: &str = "MACO_TEST_BUDGET_CRASH_REPO";
        const CHILD_READY_ENV: &str = "MACO_TEST_BUDGET_CRASH_READY";

        if let (Ok(repo), Ok(ready)) = (
            std::env::var(CHILD_REPO_ENV),
            std::env::var(CHILD_READY_ENV),
        ) {
            let _guard =
                crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(50), "killed-run")
                    .expect("bind child rolling quota");
            let ledger =
                RunBudgetLedger::new(RunBudgetLimits::default()).expect("open child run ledger");
            let reservation = admitted_reservation(
                ledger
                    .reserve(request(40, None))
                    .expect("persist child reservation"),
            );
            assert_eq!(reservation.tokens, 40);

            let program = std::path::Path::new(&repo).join("fake-codex");
            std::fs::write(
                &program,
                "#!/usr/bin/env sh\nwhile IFS= read -r _line; do :; done\nprintf 'invoked\\n' > provider-invoked\nprintf '{\"type\":\"done\"}\\n'\n",
            )
            .expect("write fake external provider");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("make fake external provider executable");
            let prompt = std::path::Path::new(&repo).join("prompt.md");
            std::fs::write(&prompt, "exercise durable budget crash recovery\n")
                .expect("write fake provider prompt");
            for control_root in [".maco", ".maco-cache", ".codex", ".agents"] {
                std::fs::create_dir_all(std::path::Path::new(&repo).join(control_root))
                    .expect("create mandatory external-agent control root");
            }
            let provider_output = std::path::Path::new(&repo).join("provider-output");
            std::fs::create_dir(&provider_output).expect("create provider output directory");
            std::fs::set_permissions(&provider_output, std::fs::Permissions::from_mode(0o700))
                .expect("make provider output directory private");
            let command = crate::external_agent::ExternalAgentCommand::codex(
                &program,
                &repo,
                &prompt,
                provider_output.join("provider-events.jsonl"),
                provider_output.join("provider-last-message.txt"),
                Duration::from_secs(10),
            );
            let run = crate::external_agent::run_external_agent_nonpublishable_simulation(&command);
            assert_eq!(
                run.exit_code,
                Some(0),
                "fake external provider failed: {run:?}"
            );
            assert_eq!(run.error, None, "fake external provider failed: {run:?}");
            assert!(
                std::path::Path::new(&repo)
                    .join("provider-invoked")
                    .is_file(),
                "fake external provider did not reach invocation boundary: {run:?}"
            );
            std::fs::write(&ready, b"provider invocation completed")
                .expect("signal completed fake provider invocation");
            loop {
                thread::park();
            }
        }

        let (_temp, repo) = rolling_repo();
        let ready = repo.join("provider-runner-ready");
        let executable = std::env::current_exe().expect("resolve test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("supervise_budget::tests::midflight_process_death_recovers_reserved_aggregate_usage")
            .arg("--nocapture")
            .env(CHILD_REPO_ENV, &repo)
            .env(CHILD_READY_ENV, &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn reservation child");

        let mut ready_seen = false;
        for _ in 0..1_000 {
            if ready.is_file() {
                ready_seen = true;
                break;
            }
            if let Some(status) = child.try_wait().expect("poll reservation child") {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_string(&mut stdout)
                        .expect("read failed child stdout");
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_string(&mut stderr)
                        .expect("read failed child stderr");
                }
                panic!(
                    "reservation child exited before kill with {status}; stdout={stdout:?}; stderr={stderr:?}"
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !ready_seen {
            child.kill().expect("kill timed-out reservation child");
            panic!("reservation child did not durably reserve before timeout");
        }
        child.kill().expect("kill child mid-flight");
        let output = child
            .wait_with_output()
            .expect("collect killed reservation child");
        assert!(
            !output.status.success(),
            "killed child unexpectedly succeeded"
        );

        let _guard =
            crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(50), "recovery-run")
                .expect("bind recovery rolling quota");
        let recovery =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("recover workspace ledger");
        let admission = recovery
            .reserve(request(20, None))
            .expect("evaluate post-crash aggregate admission");
        assert!(matches!(
            admission,
            BudgetAdmission::Refused {
                refusal: BudgetAdmissionRefusal::HardTokenCeiling {
                    limit: 50,
                    committed: 40,
                    requested: 20,
                },
                ..
            }
        ));
    }

    #[test]
    fn provider_rate_limit_latches_the_workspace_pool_across_runs() {
        let (_temp, repo) = rolling_repo();
        let _guard =
            crate::budget_ledger::bind_rolling_budget(&repo, rolling_quota(10_000), "run-rl")
                .expect("bind rolling quota");
        {
            let first = RunBudgetLedger::new(RunBudgetLimits::default()).expect("rate-limit run");
            first
                .record_provider_error(&crate::llm::ProviderError::RateLimited(
                    "tokens per minute".to_string(),
                ))
                .expect("record rate limit");
            assert!(matches!(
                first.reserve(request(1, None)).expect("latched refusal"),
                BudgetAdmission::Refused {
                    refusal: BudgetAdmissionRefusal::NewDispatchStopped,
                    ..
                }
            ));
        }

        let second = RunBudgetLedger::new(RunBudgetLimits::default()).expect("next run");
        assert!(
            !second
                .report()
                .expect("latched report")
                .new_dispatch_allowed
        );
        assert!(second
            .report()
            .expect("latched report")
            .reasons
            .contains(&BudgetReason::MissingProviderUsage));
    }
}
