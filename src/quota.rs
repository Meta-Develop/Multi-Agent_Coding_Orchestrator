//! Compatibility facade for the authoritative optimizer quota-pool contract.
//!
//! Quota descriptors and selector projections live in
//! [`crate::optimizer::quota_pools`]. Durable consumption lives only in the
//! authenticated workspace budget ledger; this module intentionally defines no
//! independent ledger or usage truth.

pub use crate::optimizer::quota_pools::{
    build_quota_selector_input, AccountId, ConsumptionLedger as QuotaLedger, ConsumptionSource,
    EntitlementDescriptor as QuotaEntitlement, ExhaustionBehavior, LedgerEntry as QuotaConsumption,
    NominalCapacity, PoolKey as QuotaPoolKey, PoolKind as QuotaPoolKind, PoolReference,
    QuotaConfig, QuotaPoolSelectorState, QuotaSelectorInput, RateLimits,
    ResetWindow as QuotaWindow, CONSUMPTION_LEDGER_VERSION, QUOTA_CONFIG_VERSION,
    QUOTA_SELECTOR_INPUT_VERSION,
};
