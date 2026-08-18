//! Contract quota pools as a local-first selection input.
//!
//! Observed usage is the default source of truth. Provider-reported limits stay
//! opt-in and are not consulted here.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How an operator's contract bills remaining work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPoolKind {
    SubscriptionIncluded,
    Metered,
    PrepaidCredits,
}

/// Reset window for a quota pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindow {
    None,
    RollingHours { hours: u32 },
    CalendarMonth,
}

/// What to do when an included or prepaid pool is exhausted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaSpillPolicy {
    #[default]
    Stop,
    Degrade,
    SpillToMetered,
}

/// Local entitlement descriptor for one `(runtime, account)` pair.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaEntitlement {
    pub runtime: String,
    pub account: String,
    pub pool_kind: QuotaPoolKind,
    pub window: QuotaWindow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nominal_capacity_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_sessions: Option<u32>,
    #[serde(default)]
    pub spill: QuotaSpillPolicy,
    #[serde(default)]
    pub list_price_input_usd_per_million: f64,
    #[serde(default)]
    pub list_price_output_usd_per_million: f64,
}

impl QuotaEntitlement {
    pub fn validate(&self) -> Result<()> {
        if self.runtime.trim().is_empty() {
            bail!("quota entitlement runtime cannot be empty");
        }
        if self.account.trim().is_empty() {
            bail!("quota entitlement account cannot be empty");
        }
        if let QuotaWindow::RollingHours { hours } = self.window {
            if hours == 0 {
                bail!("rolling quota window hours must be greater than zero");
            }
        }
        if !self.list_price_input_usd_per_million.is_finite()
            || self.list_price_input_usd_per_million < 0.0
            || !self.list_price_output_usd_per_million.is_finite()
            || self.list_price_output_usd_per_million < 0.0
        {
            bail!("quota list prices must be finite and non-negative");
        }
        Ok(())
    }

    pub fn key(&self) -> QuotaPoolKey {
        QuotaPoolKey {
            runtime: self.runtime.clone(),
            account: self.account.clone(),
            window: self.window,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct QuotaPoolKey {
    pub runtime: String,
    pub account: String,
    pub window: QuotaWindow,
}

/// Locally observed consumption for one pool/window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct QuotaConsumption {
    pub tokens: u64,
    pub requests: u64,
}

/// Durable, local-only consumption ledger. No network or credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct QuotaLedger {
    pub version: u32,
    pub entries: BTreeMap<QuotaPoolKey, QuotaConsumption>,
}

pub const QUOTA_LEDGER_VERSION: u32 = 1;

impl QuotaLedger {
    pub fn new() -> Self {
        Self {
            version: QUOTA_LEDGER_VERSION,
            entries: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, key: QuotaPoolKey, tokens: u64, requests: u64) -> Result<()> {
        let entry = self.entries.entry(key).or_default();
        entry.tokens = entry
            .tokens
            .checked_add(tokens)
            .context("quota token consumption overflowed")?;
        entry.requests = entry
            .requests
            .checked_add(requests)
            .context("quota request consumption overflowed")?;
        Ok(())
    }

    pub fn consumed(&self, key: &QuotaPoolKey) -> QuotaConsumption {
        self.entries.get(key).cloned().unwrap_or_default()
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let ledger: Self =
            serde_json::from_slice(bytes).context("quota ledger is not valid JSON")?;
        if ledger.version != QUOTA_LEDGER_VERSION {
            bail!(
                "unsupported quota ledger version {} (expected {QUOTA_LEDGER_VERSION})",
                ledger.version
            );
        }
        Ok(ledger)
    }
}

/// Marginal cost of one assignment under the operator's actual contract.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MarginalCost {
    pub pool_runtime: String,
    pub pool_account: String,
    pub pool_kind: QuotaPoolKind,
    pub tokens: u64,
    pub usd: f64,
    pub inside_included_pool: bool,
    pub exhausted: bool,
    pub spill: QuotaSpillPolicy,
}

pub fn remaining_included_tokens(
    entitlement: &QuotaEntitlement,
    ledger: &QuotaLedger,
) -> Option<u64> {
    let capacity = entitlement.nominal_capacity_tokens?;
    let used = ledger.consumed(&entitlement.key()).tokens;
    Some(capacity.saturating_sub(used))
}

/// Score the marginal cost of `tokens` under `entitlement` and the local ledger.
pub fn marginal_cost(
    entitlement: &QuotaEntitlement,
    ledger: &QuotaLedger,
    input_tokens: u64,
    output_tokens: u64,
) -> Result<MarginalCost> {
    entitlement.validate()?;
    let tokens = input_tokens
        .checked_add(output_tokens)
        .context("assignment token count overflowed")?;
    let remaining = remaining_included_tokens(entitlement, ledger);
    let (inside, exhausted, usd) = match entitlement.pool_kind {
        QuotaPoolKind::SubscriptionIncluded | QuotaPoolKind::PrepaidCredits => {
            let remaining = remaining.unwrap_or(0);
            if remaining >= tokens {
                (true, false, 0.0)
            } else {
                let overflow = tokens.saturating_sub(remaining);
                let usd = metered_usd(
                    overflow,
                    0,
                    entitlement.list_price_input_usd_per_million,
                    entitlement.list_price_output_usd_per_million,
                );
                (false, true, usd)
            }
        }
        QuotaPoolKind::Metered => (
            false,
            false,
            metered_usd(
                input_tokens,
                output_tokens,
                entitlement.list_price_input_usd_per_million,
                entitlement.list_price_output_usd_per_million,
            ),
        ),
    };
    Ok(MarginalCost {
        pool_runtime: entitlement.runtime.clone(),
        pool_account: entitlement.account.clone(),
        pool_kind: entitlement.pool_kind,
        tokens,
        usd,
        inside_included_pool: inside,
        exhausted,
        spill: entitlement.spill,
    })
}

/// Admission bound from the entitlement, not host CPU parallelism.
pub fn admission_concurrency_cap(entitlement: &QuotaEntitlement) -> Option<u32> {
    entitlement.max_concurrent_sessions
}

fn metered_usd(input_tokens: u64, output_tokens: u64, input_rate: f64, output_rate: f64) -> f64 {
    (input_tokens as f64) * input_rate / 1_000_000.0
        + (output_tokens as f64) * output_rate / 1_000_000.0
}

/// Budget-facing action when a pool is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaExhaustionAction {
    Stop,
    Degrade,
    SpillToMetered,
}

pub fn exhaustion_action(cost: &MarginalCost) -> Option<QuotaExhaustionAction> {
    if !cost.exhausted {
        return None;
    }
    Some(match cost.spill {
        QuotaSpillPolicy::Stop => QuotaExhaustionAction::Stop,
        QuotaSpillPolicy::Degrade => QuotaExhaustionAction::Degrade,
        QuotaSpillPolicy::SpillToMetered => QuotaExhaustionAction::SpillToMetered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn included() -> QuotaEntitlement {
        QuotaEntitlement {
            runtime: "codex".to_string(),
            account: "operator".to_string(),
            pool_kind: QuotaPoolKind::SubscriptionIncluded,
            window: QuotaWindow::CalendarMonth,
            nominal_capacity_tokens: Some(1_000),
            requests_per_minute: Some(60),
            tokens_per_minute: Some(100_000),
            max_concurrent_sessions: Some(4),
            spill: QuotaSpillPolicy::Degrade,
            list_price_input_usd_per_million: 2.0,
            list_price_output_usd_per_million: 8.0,
        }
    }

    #[test]
    fn included_pool_has_zero_marginal_cost_until_exhausted() {
        let entitlement = included();
        let mut ledger = QuotaLedger::new();
        let cheap = marginal_cost(&entitlement, &ledger, 100, 50).expect("inside pool");
        assert!(cheap.inside_included_pool);
        assert_eq!(cheap.usd, 0.0);
        assert!(exhaustion_action(&cheap).is_none());

        ledger.record(entitlement.key(), 1_000, 1).expect("record");
        let over = marginal_cost(&entitlement, &ledger, 100, 0).expect("exhausted");
        assert!(over.exhausted);
        assert!(over.usd > 0.0);
        assert_eq!(
            exhaustion_action(&over),
            Some(QuotaExhaustionAction::Degrade)
        );
    }

    #[test]
    fn metered_pool_uses_list_price() {
        let mut entitlement = included();
        entitlement.pool_kind = QuotaPoolKind::Metered;
        let ledger = QuotaLedger::new();
        let cost = marginal_cost(&entitlement, &ledger, 1_000_000, 0).expect("metered");
        assert!(!cost.inside_included_pool);
        assert!((cost.usd - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rate_limit_cap_is_the_admission_bound() {
        let entitlement = included();
        assert_eq!(admission_concurrency_cap(&entitlement), Some(4));
    }
}
