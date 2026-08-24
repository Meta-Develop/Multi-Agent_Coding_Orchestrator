//! Contract quota pools as a local-first selection input (issue #151).
//!
//! This slice declares a strict operator quota configuration and projects the
//! authenticated workspace budget ledger into a selector input.
//! Provider billing endpoints, rate-limit headers, and live quotes are not
//! consulted. A later slice can score assignments and fail over runtimes;
//! it should not need to edit these types to do that.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::error::OptimizerError;
use super::ids::RuntimeSlug;

pub const QUOTA_CONFIG_VERSION: u32 = 1;
pub const CONSUMPTION_LEDGER_VERSION: u32 = 1;
pub const QUOTA_SELECTOR_INPUT_VERSION: u32 = 1;

const MAX_QUOTA_CONFIG_BYTES: usize = 256 * 1024;
const MAX_QUOTA_POOLS: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 128;

const LOCAL_ADMISSION_PROVENANCE: &str = "local entitlement descriptor and consumption ledger; provider billing and rate-limit endpoints were not consulted";

/// Operator account that owns a contract pool. Distinct from a runtime slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
        parse_identifier(&value.into()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn parse_identifier(value: &str) -> Result<String, OptimizerError> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(OptimizerError::EmptyIdentifier);
    }
    Ok(value.to_string())
}

/// How an operator's contract bills remaining work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    SubscriptionIncluded,
    Metered,
    PrepaidCredits,
}

/// Reset window declared on the entitlement. The ledger is keyed by this
/// window; the selector does not consult a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetWindow {
    None,
    RollingHours { hours: u32 },
    CalendarMonth,
}

/// Provider-stated capacity, or an explicit unknown. Unknown is not treated
/// as unlimited except on a metered pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NominalCapacity {
    Unknown,
    Units(u64),
}

/// Per-account rate limits that later feed admission. Zero is rejected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_sessions: Option<u32>,
}

/// What to do when a bounded pool is exhausted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustionBehavior {
    #[default]
    FailClosed,
    Degrade,
}

/// Exact operator-authorized alternative for an exhausted pool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolReference {
    pub runtime: RuntimeSlug,
    pub account: AccountId,
    pub window: ResetWindow,
}

/// Accepted consumption sources. Provider-reported rows fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumptionSource {
    LocalObserved,
    ProviderReported,
}

/// Local entitlement descriptor for one `(runtime, account)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementDescriptor {
    pub runtime: RuntimeSlug,
    pub account: AccountId,
    pub pool_kind: PoolKind,
    pub window: ResetWindow,
    pub nominal_capacity: NominalCapacity,
    pub rate_limits: RateLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_tier: Option<String>,
    pub exhaustion_behavior: ExhaustionBehavior,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_alternatives: Vec<PoolReference>,
    /// Declared next-unit list price. Not a live quote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_list_price_microunits: Option<u64>,
}

impl EntitlementDescriptor {
    pub fn validate(&self) -> Result<(), OptimizerError> {
        self.key().validate()?;
        if let ResetWindow::RollingHours { hours } = self.window {
            if hours == 0 {
                return Err(OptimizerError::invalid(
                    "rolling quota window hours must be greater than zero",
                ));
            }
        }
        validate_optional_positive(self.rate_limits.requests_per_minute, "requests_per_minute")?;
        validate_optional_positive(self.rate_limits.tokens_per_minute, "tokens_per_minute")?;
        validate_optional_positive(
            self.rate_limits.max_concurrent_sessions,
            "max_concurrent_sessions",
        )?;
        match (self.pool_kind, self.nominal_capacity) {
            (
                PoolKind::SubscriptionIncluded | PoolKind::PrepaidCredits,
                NominalCapacity::Unknown,
            ) => {
                return Err(OptimizerError::invalid(format!(
                    "included or prepaid quota pool '{}' requires a known nominal capacity",
                    self.runtime
                )));
            }
            (_, NominalCapacity::Units(0)) => {
                return Err(OptimizerError::invalid(format!(
                    "quota pool '{}' nominal capacity must be greater than zero",
                    self.runtime
                )));
            }
            (_, NominalCapacity::Unknown | NominalCapacity::Units(_)) => {}
        }
        if let Some(tier) = &self.priority_tier {
            parse_identifier(tier).map_err(|_| {
                OptimizerError::invalid("priority_tier must be non-empty and trimmed")
            })?;
        }
        let mut alternatives = BTreeSet::new();
        for alternative in &self.authorized_alternatives {
            if !alternatives.insert(alternative) {
                return Err(OptimizerError::invalid(format!(
                    "quota pool '{}' has a duplicate authorized alternative",
                    self.runtime
                )));
            }
            if alternative.runtime == self.runtime
                && alternative.account == self.account
                && alternative.window == self.window
            {
                return Err(OptimizerError::invalid(format!(
                    "quota pool '{}' cannot degrade to itself",
                    self.runtime
                )));
            }
        }
        match self.exhaustion_behavior {
            ExhaustionBehavior::FailClosed if !self.authorized_alternatives.is_empty() => {
                return Err(OptimizerError::invalid(format!(
                    "fail-closed quota pool '{}' cannot declare degrade alternatives",
                    self.runtime
                )));
            }
            ExhaustionBehavior::Degrade if self.authorized_alternatives.is_empty() => {
                return Err(OptimizerError::invalid(format!(
                    "degrading quota pool '{}' requires at least one authorized alternative",
                    self.runtime
                )));
            }
            ExhaustionBehavior::FailClosed | ExhaustionBehavior::Degrade => {}
        }
        Ok(())
    }

    pub fn key(&self) -> PoolKey {
        PoolKey {
            runtime: self.runtime.clone(),
            account: self.account.clone(),
            window: self.window,
        }
    }
}

/// Strict, versioned repository-local operator quota configuration.
///
/// Parsing and validation are pure and never contact a runtime or provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    pub version: u32,
    pub pools: Vec<EntitlementDescriptor>,
}

impl QuotaConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OptimizerError> {
        if bytes.len() > MAX_QUOTA_CONFIG_BYTES {
            return Err(OptimizerError::invalid(format!(
                "operator quota config exceeds {MAX_QUOTA_CONFIG_BYTES} bytes"
            )));
        }
        let config = serde_json::from_slice::<Self>(bytes).map_err(|error| {
            OptimizerError::invalid(format!("operator quota config is not strict JSON: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.version != QUOTA_CONFIG_VERSION {
            return Err(OptimizerError::invalid(format!(
                "unsupported operator quota config version {} (expected {QUOTA_CONFIG_VERSION})",
                self.version
            )));
        }
        if self.pools.is_empty() {
            return Err(OptimizerError::invalid(
                "operator quota config requires at least one pool",
            ));
        }
        if self.pools.len() > MAX_QUOTA_POOLS {
            return Err(OptimizerError::invalid(format!(
                "operator quota config exceeds {MAX_QUOTA_POOLS} pools"
            )));
        }

        let mut keys = BTreeSet::new();
        let mut runtimes = BTreeSet::new();
        for pool in &self.pools {
            pool.validate()?;
            if !keys.insert(pool.key()) {
                return Err(OptimizerError::invalid(format!(
                    "duplicate quota pool for runtime '{}' account '{}' window {:?}",
                    pool.runtime, pool.account, pool.window
                )));
            }
            if !runtimes.insert(pool.runtime.clone()) {
                return Err(OptimizerError::invalid(format!(
                    "multiple quota pools for runtime '{}' are ambiguous for live selection",
                    pool.runtime
                )));
            }
        }

        validate_pool_relationships(&self.pools, &keys)?;
        Ok(())
    }
}

fn validate_pool_relationships(
    pools: &[EntitlementDescriptor],
    keys: &BTreeSet<PoolKey>,
) -> Result<(), OptimizerError> {
    for pool in pools {
        for alternative in &pool.authorized_alternatives {
            if !keys.iter().any(|key| {
                key.runtime == alternative.runtime
                    && key.account == alternative.account
                    && key.window == alternative.window
            }) {
                return Err(OptimizerError::invalid(format!(
                    "quota pool '{}' authorizes an alternative that is not declared in this config",
                    pool.runtime
                )));
            }
        }
    }
    reject_degrade_cycles(pools)
}

fn reject_degrade_cycles(pools: &[EntitlementDescriptor]) -> Result<(), OptimizerError> {
    let by_key = pools
        .iter()
        .map(|pool| (pool.key(), pool))
        .collect::<BTreeMap<_, _>>();
    let mut complete = BTreeSet::new();
    for start in by_key.keys() {
        reject_degrade_cycle_from(start, &by_key, &mut BTreeSet::new(), &mut complete)?;
    }
    Ok(())
}

fn reject_degrade_cycle_from(
    key: &PoolKey,
    by_key: &BTreeMap<PoolKey, &EntitlementDescriptor>,
    active_path: &mut BTreeSet<PoolKey>,
    complete: &mut BTreeSet<PoolKey>,
) -> Result<(), OptimizerError> {
    if complete.contains(key) {
        return Ok(());
    }
    if !active_path.insert(key.clone()) {
        return Err(OptimizerError::invalid(format!(
            "quota degrade alternatives contain a cycle reachable from runtime '{}'",
            key.runtime
        )));
    }
    if let Some(pool) = by_key.get(key) {
        for alternative in &pool.authorized_alternatives {
            let alternative_key = PoolKey {
                runtime: alternative.runtime.clone(),
                account: alternative.account.clone(),
                window: alternative.window,
            };
            reject_degrade_cycle_from(&alternative_key, by_key, active_path, complete)?;
        }
    }
    active_path.remove(key);
    complete.insert(key.clone());
    Ok(())
}

fn validate_optional_positive(value: Option<u32>, name: &str) -> Result<(), OptimizerError> {
    match value {
        Some(0) => Err(OptimizerError::invalid(format!(
            "{name} must be greater than zero when present"
        ))),
        Some(_) | None => Ok(()),
    }
}

/// Ledger key: observed usage is stored per contract window.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolKey {
    pub runtime: RuntimeSlug,
    pub account: AccountId,
    pub window: ResetWindow,
}

impl PoolKey {
    pub fn validate(&self) -> Result<(), OptimizerError> {
        parse_identifier(self.runtime.as_str()).map_err(|_| {
            OptimizerError::invalid(
                "quota pool runtime must be non-empty, bounded, and contain no whitespace",
            )
        })?;
        parse_identifier(self.account.as_str()).map_err(|_| {
            OptimizerError::invalid(
                "quota pool account must be non-empty, bounded, and contain no whitespace",
            )
        })?;
        if matches!(self.window, ResetWindow::RollingHours { hours: 0 }) {
            return Err(OptimizerError::invalid(
                "rolling quota window hours must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// One locally observed snapshot for a pool/window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub tokens: u64,
    pub requests: u64,
    pub observation_revision: String,
    pub source: ConsumptionSource,
}

impl LedgerEntry {
    pub fn local(tokens: u64, requests: u64, observation_revision: impl Into<String>) -> Self {
        Self {
            tokens,
            requests,
            observation_revision: observation_revision.into(),
            source: ConsumptionSource::LocalObserved,
        }
    }

    fn validate(&self) -> Result<(), OptimizerError> {
        parse_identifier(&self.observation_revision).map_err(|_| {
            OptimizerError::invalid("ledger observation_revision must be non-empty and trimmed")
        })?;
        if self.source != ConsumptionSource::LocalObserved {
            return Err(OptimizerError::invalid(
                "quota selector input refuses provider-reported consumption; local ledger only",
            ));
        }
        Ok(())
    }
}

/// Durable, local-only consumption ledger. No network or credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionLedger {
    pub version: u32,
    pub entries: BTreeMap<PoolKey, LedgerEntry>,
}

impl ConsumptionLedger {
    pub fn new() -> Self {
        Self {
            version: CONSUMPTION_LEDGER_VERSION,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert_snapshot(
        &mut self,
        key: PoolKey,
        entry: LedgerEntry,
    ) -> Result<(), OptimizerError> {
        entry.validate()?;
        self.entries.insert(key, entry);
        Ok(())
    }

    pub fn record_delta(
        &mut self,
        key: PoolKey,
        tokens: u64,
        requests: u64,
        observation_revision: impl Into<String>,
    ) -> Result<(), OptimizerError> {
        let revision = observation_revision.into();
        parse_identifier(&revision).map_err(|_| {
            OptimizerError::invalid("ledger observation_revision must be non-empty and trimmed")
        })?;
        match self.entries.get_mut(&key) {
            Some(entry) => {
                entry.validate()?;
                entry.tokens = entry
                    .tokens
                    .checked_add(tokens)
                    .ok_or_else(|| OptimizerError::invalid("quota token consumption overflowed"))?;
                entry.requests = entry.requests.checked_add(requests).ok_or_else(|| {
                    OptimizerError::invalid("quota request consumption overflowed")
                })?;
                entry.observation_revision = revision;
                Ok(())
            }
            None => self.insert_snapshot(key, LedgerEntry::local(tokens, requests, revision)),
        }
    }

    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.version != CONSUMPTION_LEDGER_VERSION {
            return Err(OptimizerError::invalid(format!(
                "unsupported consumption ledger version {} (expected {CONSUMPTION_LEDGER_VERSION})",
                self.version
            )));
        }
        for entry in self.entries.values() {
            entry.validate()?;
        }
        Ok(())
    }
}

/// One validated pool row for the selector. Missing observations never become
/// this type; the builder fails closed instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaPoolSelectorState {
    pub runtime: RuntimeSlug,
    pub account: AccountId,
    pub pool_kind: PoolKind,
    pub window: ResetWindow,
    pub admission_open: bool,
    pub capacity: NominalCapacity,
    pub remaining_units: Option<u64>,
    pub pool_pressure_basis_points: u16,
    pub observed_consumption_units: u64,
    pub observed_requests: u64,
    pub marginal_cost_microunits: u64,
    pub inside_included_pool: bool,
    pub exhausted: bool,
    pub exhaustion_behavior: ExhaustionBehavior,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_alternatives: Vec<PoolReference>,
    pub rate_limits: RateLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_tier: Option<String>,
    pub observation_revision: String,
    pub admission_provenance: String,
    pub observation_source: ConsumptionSource,
}

/// Fail-closed quota input for later selector scoring. This is not a live bill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSelectorInput {
    pub schema_version: u32,
    pub pools: Vec<QuotaPoolSelectorState>,
}

/// Build a selector input from local entitlements and the local ledger.
///
/// The function fails closed when a required observation is missing, a
/// provider-reported source is present, an included pool has unknown
/// capacity, or a metered pool has no declared list price.
pub fn build_quota_selector_input(
    entitlements: &[EntitlementDescriptor],
    ledger: &ConsumptionLedger,
) -> Result<QuotaSelectorInput, OptimizerError> {
    if entitlements.is_empty() {
        return Err(OptimizerError::invalid(
            "quota selector input requires at least one entitlement descriptor",
        ));
    }
    ledger.validate()?;

    let mut seen_pairs = BTreeSet::new();
    let mut seen_runtimes = BTreeSet::new();
    let mut expected_keys = BTreeSet::new();
    for entitlement in entitlements {
        entitlement.validate()?;
        let pair = (
            entitlement.runtime.as_str().to_string(),
            entitlement.account.as_str().to_string(),
        );
        if !seen_pairs.insert(pair) {
            return Err(OptimizerError::invalid(format!(
                "duplicate entitlement for runtime '{}' account '{}'",
                entitlement.runtime, entitlement.account
            )));
        }
        if !seen_runtimes.insert(entitlement.runtime.as_str().to_string()) {
            return Err(OptimizerError::invalid(format!(
                "duplicate entitlement runtime '{}' is ambiguous for selector input",
                entitlement.runtime
            )));
        }
        expected_keys.insert(entitlement.key());
    }
    validate_pool_relationships(entitlements, &expected_keys)?;

    let actual_keys: BTreeSet<_> = ledger.entries.keys().cloned().collect();
    if expected_keys != actual_keys {
        return Err(OptimizerError::invalid(
            "entitlement keys and consumption ledger keys must match exactly; missing or extra observations fail closed",
        ));
    }

    let mut pools = Vec::with_capacity(entitlements.len());
    for entitlement in entitlements {
        let entry = ledger.entries.get(&entitlement.key()).ok_or_else(|| {
            OptimizerError::invalid(format!(
                "consumption ledger is missing runtime '{}' account '{}'",
                entitlement.runtime, entitlement.account
            ))
        })?;
        pools.push(project_pool(entitlement, entry)?);
    }
    pools.sort_by(|left, right| {
        (left.runtime.as_str(), left.account.as_str())
            .cmp(&(right.runtime.as_str(), right.account.as_str()))
    });
    Ok(QuotaSelectorInput {
        schema_version: QUOTA_SELECTOR_INPUT_VERSION,
        pools,
    })
}

fn project_pool(
    entitlement: &EntitlementDescriptor,
    entry: &LedgerEntry,
) -> Result<QuotaPoolSelectorState, OptimizerError> {
    entry.validate()?;
    let (remaining_units, pressure, inside_included_pool, exhausted) = match entitlement.pool_kind {
        PoolKind::SubscriptionIncluded | PoolKind::PrepaidCredits => {
            let NominalCapacity::Units(capacity) = entitlement.nominal_capacity else {
                return Err(OptimizerError::invalid(format!(
                    "included and prepaid pool '{}' requires a known nominal capacity",
                    entitlement.runtime
                )));
            };
            let remaining = capacity.saturating_sub(entry.tokens);
            let used = capacity.saturating_sub(remaining);
            (
                Some(remaining),
                pressure_bp(used, capacity),
                remaining > 0,
                remaining == 0,
            )
        }
        PoolKind::Metered => match entitlement.nominal_capacity {
            NominalCapacity::Unknown => (None, 0, false, false),
            NominalCapacity::Units(capacity) => {
                let remaining = capacity.saturating_sub(entry.tokens);
                let used = capacity.saturating_sub(remaining);
                (
                    Some(remaining),
                    pressure_bp(used, capacity),
                    false,
                    remaining == 0,
                )
            }
        },
    };

    let marginal_cost_microunits = if inside_included_pool {
        0
    } else if matches!(entitlement.pool_kind, PoolKind::Metered) {
        entitlement.declared_list_price_microunits.ok_or_else(|| {
            OptimizerError::invalid(format!(
                "pool '{}' requires a declared list price in microunits; live billing is not consulted",
                entitlement.runtime
            ))
        })?
    } else {
        entitlement.declared_list_price_microunits.unwrap_or(0)
    };

    let admission_open = !exhausted;
    let admission_provenance = match (exhausted, entitlement.exhaustion_behavior) {
        (true, ExhaustionBehavior::Degrade) => format!(
            "{LOCAL_ADMISSION_PROVENANCE}; exhausted source is ineligible and only operator-authorized alternatives may be considered"
        ),
        _ => LOCAL_ADMISSION_PROVENANCE.to_string(),
    };

    Ok(QuotaPoolSelectorState {
        runtime: entitlement.runtime.clone(),
        account: entitlement.account.clone(),
        pool_kind: entitlement.pool_kind,
        window: entitlement.window,
        admission_open,
        capacity: entitlement.nominal_capacity,
        remaining_units,
        pool_pressure_basis_points: pressure,
        observed_consumption_units: entry.tokens,
        observed_requests: entry.requests,
        marginal_cost_microunits,
        inside_included_pool,
        exhausted,
        exhaustion_behavior: entitlement.exhaustion_behavior,
        authorized_alternatives: entitlement.authorized_alternatives.clone(),
        rate_limits: entitlement.rate_limits,
        priority_tier: entitlement.priority_tier.clone(),
        observation_revision: entry.observation_revision.clone(),
        admission_provenance,
        observation_source: entry.source,
    })
}

fn pressure_bp(used: u64, capacity: u64) -> u16 {
    if capacity == 0 {
        return 10_000;
    }
    ((u128::from(used) * 10_000) / u128::from(capacity)).min(10_000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> AccountId {
        AccountId::new("operator").expect("account")
    }

    fn runtime(name: &str) -> RuntimeSlug {
        RuntimeSlug::new(name).expect("runtime")
    }

    fn included() -> EntitlementDescriptor {
        EntitlementDescriptor {
            runtime: runtime("codex"),
            account: account(),
            pool_kind: PoolKind::SubscriptionIncluded,
            window: ResetWindow::CalendarMonth,
            nominal_capacity: NominalCapacity::Units(1_000),
            rate_limits: RateLimits {
                requests_per_minute: Some(60),
                tokens_per_minute: Some(100_000),
                max_concurrent_sessions: Some(4),
            },
            priority_tier: Some("plus".to_string()),
            exhaustion_behavior: ExhaustionBehavior::FailClosed,
            authorized_alternatives: Vec::new(),
            declared_list_price_microunits: Some(2_000_000),
        }
    }

    fn metered() -> EntitlementDescriptor {
        EntitlementDescriptor {
            runtime: runtime("grok"),
            account: account(),
            pool_kind: PoolKind::Metered,
            window: ResetWindow::None,
            nominal_capacity: NominalCapacity::Unknown,
            rate_limits: RateLimits::default(),
            priority_tier: None,
            exhaustion_behavior: ExhaustionBehavior::FailClosed,
            authorized_alternatives: Vec::new(),
            declared_list_price_microunits: Some(5_000_000),
        }
    }

    fn ledger_for(entitlements: &[EntitlementDescriptor], tokens: &[u64]) -> ConsumptionLedger {
        let mut ledger = ConsumptionLedger::new();
        for (entitlement, consumed) in entitlements.iter().zip(tokens.iter().copied()) {
            ledger
                .insert_snapshot(
                    entitlement.key(),
                    LedgerEntry::local(
                        consumed,
                        0,
                        format!("{}-obs-r1", entitlement.runtime.as_str()),
                    ),
                )
                .expect("snapshot");
        }
        ledger
    }

    fn ledger_one(entitlement: &EntitlementDescriptor, tokens: u64) -> ConsumptionLedger {
        ledger_for(std::slice::from_ref(entitlement), &[tokens])
    }

    fn reference(entitlement: &EntitlementDescriptor) -> PoolReference {
        PoolReference {
            runtime: entitlement.runtime.clone(),
            account: entitlement.account.clone(),
            window: entitlement.window,
        }
    }

    #[test]
    fn fresh_included_pool_has_zero_marginal_cost() {
        let entitlement = included();
        let ledger = ledger_one(&entitlement, 0);
        let input = build_quota_selector_input(&[entitlement], &ledger).expect("fresh pool");
        assert_eq!(input.schema_version, QUOTA_SELECTOR_INPUT_VERSION);
        assert_eq!(input.pools.len(), 1);
        let pool = &input.pools[0];
        assert!(pool.inside_included_pool);
        assert!(!pool.exhausted);
        assert!(pool.admission_open);
        assert_eq!(pool.marginal_cost_microunits, 0);
        assert_eq!(pool.pool_pressure_basis_points, 0);
        assert_eq!(pool.remaining_units, Some(1_000));
        assert!(pool
            .admission_provenance
            .contains("provider billing and rate-limit endpoints were not consulted"));
    }

    #[test]
    fn included_pool_pressure_rises_with_local_consumption() {
        let entitlement = included();
        let ledger = ledger_one(&entitlement, 900);
        let input = build_quota_selector_input(&[entitlement], &ledger).expect("pressured pool");
        let pool = &input.pools[0];
        assert!(pool.inside_included_pool);
        assert_eq!(pool.marginal_cost_microunits, 0);
        assert_eq!(pool.pool_pressure_basis_points, 9_000);
        assert_eq!(pool.remaining_units, Some(100));
    }

    #[test]
    fn exhausted_fail_closed_pool_closes_admission() {
        let entitlement = included();
        let ledger = ledger_one(&entitlement, 1_000);
        let input = build_quota_selector_input(&[entitlement], &ledger).expect("exhausted");
        let pool = &input.pools[0];
        assert!(pool.exhausted);
        assert!(!pool.inside_included_pool);
        assert!(!pool.admission_open);
        assert_eq!(pool.exhaustion_behavior, ExhaustionBehavior::FailClosed);
        assert!(pool.authorized_alternatives.is_empty());
    }

    #[test]
    fn exhausted_degrade_pool_exposes_only_operator_authorized_alternatives() {
        let target = metered();
        let mut source = included();
        source.exhaustion_behavior = ExhaustionBehavior::Degrade;
        source.authorized_alternatives = vec![reference(&target)];
        source.declared_list_price_microunits = None;
        let config = QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![source.clone(), target.clone()],
        };
        config.validate().expect("valid degrade config");
        let ledger = ledger_for(&config.pools, &[1_000, 0]);
        let input = build_quota_selector_input(&config.pools, &ledger).expect("selector input");
        let source_pool = input
            .pools
            .iter()
            .find(|pool| pool.runtime == source.runtime)
            .expect("source pool");
        assert!(source_pool.exhausted);
        assert!(!source_pool.admission_open);
        assert_eq!(source_pool.marginal_cost_microunits, 0);
        assert_eq!(source_pool.exhaustion_behavior, ExhaustionBehavior::Degrade);
        assert_eq!(
            source_pool.authorized_alternatives,
            vec![reference(&target)]
        );
        assert!(source_pool
            .admission_provenance
            .contains("exhausted source is ineligible"));

        let target_pool = input
            .pools
            .iter()
            .find(|pool| pool.runtime == target.runtime)
            .expect("authorized target pool");
        assert!(target_pool.admission_open);
        assert_eq!(target_pool.marginal_cost_microunits, 5_000_000);
    }

    #[test]
    fn metered_pool_uses_declared_list_price() {
        let entitlement = metered();
        let ledger = ledger_one(&entitlement, 42);
        let input = build_quota_selector_input(&[entitlement], &ledger).expect("metered");
        let pool = &input.pools[0];
        assert_eq!(pool.pool_kind, PoolKind::Metered);
        assert!(!pool.inside_included_pool);
        assert!(!pool.exhausted);
        assert_eq!(pool.capacity, NominalCapacity::Unknown);
        assert_eq!(pool.remaining_units, None);
        assert_eq!(pool.marginal_cost_microunits, 5_000_000);
        assert_eq!(pool.pool_pressure_basis_points, 0);
    }

    #[test]
    fn mixed_runtimes_keep_local_observations_sorted() {
        let grok = metered();
        let mut cursor = metered();
        cursor.runtime = runtime("cursor");
        cursor.declared_list_price_microunits = Some(1_000_000);
        let codex = included();
        let entitlements = vec![grok, cursor, codex];
        let ledger = ledger_for(&entitlements, &[10, 0, 100]);
        let input = build_quota_selector_input(&entitlements, &ledger).expect("mixed");
        let runtimes: Vec<_> = input
            .pools
            .iter()
            .map(|pool| pool.runtime.as_str().to_string())
            .collect();
        assert_eq!(runtimes, vec!["codex", "cursor", "grok"]);
        assert_eq!(input.pools[0].marginal_cost_microunits, 0);
        assert_eq!(input.pools[1].marginal_cost_microunits, 1_000_000);
        assert_eq!(input.pools[2].marginal_cost_microunits, 5_000_000);
    }

    #[test]
    fn missing_ledger_entry_fails_closed() {
        let entitlement = included();
        let ledger = ConsumptionLedger::new();
        let error = build_quota_selector_input(&[entitlement], &ledger).expect_err("missing");
        assert!(error.to_string().contains("must match exactly"), "{error}");
    }

    #[test]
    fn extra_ledger_entry_fails_closed() {
        let entitlement = included();
        let mut ledger = ledger_one(&entitlement, 0);
        let extra = metered();
        ledger
            .insert_snapshot(extra.key(), LedgerEntry::local(1, 0, "extra-obs"))
            .expect("extra");
        let error = build_quota_selector_input(&[entitlement], &ledger).expect_err("extra");
        assert!(error.to_string().contains("must match exactly"), "{error}");
    }

    #[test]
    fn unknown_included_capacity_fails_closed() {
        let mut entitlement = included();
        entitlement.nominal_capacity = NominalCapacity::Unknown;
        let ledger = ledger_one(&entitlement, 0);
        let error = build_quota_selector_input(&[entitlement], &ledger).expect_err("unknown");
        assert!(
            error.to_string().contains("known nominal capacity"),
            "{error}"
        );
    }

    #[test]
    fn metered_without_declared_price_fails_closed() {
        let mut entitlement = metered();
        entitlement.declared_list_price_microunits = None;
        let ledger = ledger_one(&entitlement, 0);
        let error = build_quota_selector_input(&[entitlement], &ledger).expect_err("no price");
        assert!(error.to_string().contains("declared list price"), "{error}");
        assert!(
            error.to_string().contains("live billing is not consulted"),
            "{error}"
        );
    }

    #[test]
    fn provider_reported_consumption_fails_closed() {
        let entitlement = included();
        let mut ledger = ConsumptionLedger::new();
        ledger
            .insert_snapshot(
                entitlement.key(),
                LedgerEntry {
                    tokens: 0,
                    requests: 0,
                    observation_revision: "provider-header".to_string(),
                    source: ConsumptionSource::ProviderReported,
                },
            )
            .expect_err("provider snapshot rejected");
        let mut accepted = ConsumptionLedger::new();
        accepted.entries.insert(
            entitlement.key(),
            LedgerEntry {
                tokens: 0,
                requests: 0,
                observation_revision: "provider-header".to_string(),
                source: ConsumptionSource::ProviderReported,
            },
        );
        let error = build_quota_selector_input(&[entitlement], &accepted).expect_err("provider");
        assert!(error.to_string().contains("provider-reported"), "{error}");
    }

    #[test]
    fn duplicate_runtime_fails_closed() {
        let first = included();
        let mut second = included();
        second.account = AccountId::new("other").expect("account");
        let mut ledger = ConsumptionLedger::new();
        ledger
            .insert_snapshot(first.key(), LedgerEntry::local(0, 0, "a-obs"))
            .expect("first");
        ledger
            .insert_snapshot(second.key(), LedgerEntry::local(0, 0, "b-obs"))
            .expect("second");
        let error = build_quota_selector_input(&[first, second], &ledger).expect_err("dup runtime");
        assert!(error.to_string().contains("ambiguous"), "{error}");
    }

    #[test]
    fn empty_entitlements_fail_closed() {
        let error = build_quota_selector_input(&[], &ConsumptionLedger::new()).expect_err("empty");
        assert!(
            error.to_string().contains("at least one entitlement"),
            "{error}"
        );
    }

    #[test]
    fn zero_rolling_window_fails_closed() {
        let mut entitlement = included();
        entitlement.window = ResetWindow::RollingHours { hours: 0 };
        let mut ledger = ConsumptionLedger::new();
        ledger
            .insert_snapshot(entitlement.key(), LedgerEntry::local(0, 0, "obs"))
            .expect("snapshot");
        let error = build_quota_selector_input(&[entitlement], &ledger).expect_err("window");
        assert!(
            error.to_string().contains("rolling quota window"),
            "{error}"
        );
    }

    #[test]
    fn record_delta_aggregates_local_usage() {
        let entitlement = included();
        let mut ledger = ConsumptionLedger::new();
        ledger
            .record_delta(entitlement.key(), 10, 1, "obs-1")
            .expect("first");
        ledger
            .record_delta(entitlement.key(), 15, 2, "obs-2")
            .expect("second");
        let entry = ledger.entries.get(&entitlement.key()).expect("entry");
        assert_eq!(entry.tokens, 25);
        assert_eq!(entry.requests, 3);
        assert_eq!(entry.observation_revision, "obs-2");
        assert_eq!(entry.source, ConsumptionSource::LocalObserved);
    }

    #[test]
    fn empty_account_is_rejected() {
        assert_eq!(
            AccountId::new("").unwrap_err(),
            OptimizerError::EmptyIdentifier
        );
        assert_eq!(
            AccountId::new(" padded ").unwrap_err(),
            OptimizerError::EmptyIdentifier
        );
    }

    #[test]
    fn strict_config_parser_rejects_unknown_fields_and_nonsense() {
        let config = QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![included()],
        };
        let bytes = serde_json::to_vec(&config).expect("serialize config");
        assert_eq!(
            QuotaConfig::from_json(&bytes).expect("parse config"),
            config
        );

        let mut value = serde_json::to_value(&config).expect("config value");
        value
            .as_object_mut()
            .expect("config object")
            .insert("probe_provider".to_string(), serde_json::json!(true));
        let error =
            QuotaConfig::from_json(&serde_json::to_vec(&value).expect("serialize invalid config"))
                .expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"), "{error}");

        let mut zero_capacity = included();
        zero_capacity.nominal_capacity = NominalCapacity::Units(0);
        assert!(QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![zero_capacity],
        }
        .validate()
        .expect_err("zero capacity")
        .to_string()
        .contains("greater than zero"));
    }

    #[test]
    fn ambiguous_runtime_and_unconfigured_alternative_fail_closed() {
        let first = included();
        let mut ambiguous = included();
        ambiguous.account = AccountId::new("other").expect("other account");
        assert!(QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![first.clone(), ambiguous],
        }
        .validate()
        .expect_err("ambiguous runtime")
        .to_string()
        .contains("ambiguous"));

        let undeclared = metered();
        let mut degrading = first;
        degrading.exhaustion_behavior = ExhaustionBehavior::Degrade;
        degrading.authorized_alternatives = vec![reference(&undeclared)];
        assert!(QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![degrading],
        }
        .validate()
        .expect_err("undeclared alternative")
        .to_string()
        .contains("not declared"));
    }

    #[test]
    fn degrade_cycle_rejects_but_convergent_dag_is_valid() {
        let mut a = included();
        a.runtime = runtime("a");
        let mut b = metered();
        b.runtime = runtime("b");
        let mut c = metered();
        c.runtime = runtime("c");
        let mut d = metered();
        d.runtime = runtime("d");

        a.exhaustion_behavior = ExhaustionBehavior::Degrade;
        a.authorized_alternatives = vec![reference(&b), reference(&c)];
        b.exhaustion_behavior = ExhaustionBehavior::Degrade;
        b.authorized_alternatives = vec![reference(&d)];
        c.exhaustion_behavior = ExhaustionBehavior::Degrade;
        c.authorized_alternatives = vec![reference(&d)];
        QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![a.clone(), b.clone(), c.clone(), d.clone()],
        }
        .validate()
        .expect("convergent DAG is not a cycle");

        d.exhaustion_behavior = ExhaustionBehavior::Degrade;
        d.authorized_alternatives = vec![reference(&a)];
        assert!(QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![a, b, c, d],
        }
        .validate()
        .expect_err("cycle")
        .to_string()
        .contains("cycle"));
    }
}
