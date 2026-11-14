//! Pure, replayable runtime/model/effort selection.
//!
//! The selector has no runtime or clock access. Callers supply advertised
//! catalogs, operational state, dated priors, and the complete outcome ledger;
//! the returned decision contains the normalized-input digests and every
//! candidate considered.

pub mod decision_proposal;
mod public_benchmark;
mod quota_input;
pub mod routing_policy;
pub(crate) mod runtime_model_policy;
mod schema;
mod selector;
mod types;

pub use public_benchmark::{
    PublicBenchmarkRow, PublicBenchmarkScore, PublicBenchmarkSnapshot, RelativePublicBenchmarkPrior,
};
pub use quota_input::{
    apply_fail_closed_quota_pools, fail_closed_quota_selector_input, runtime_pool_states,
};
pub(crate) use schema::{accepted_task_cost_lane_schema_value, selection_event_schema_value};
pub use selector::{
    built_in_prior_dataset, effective_task_shape_ceiling, measured_authority_eligibility, select,
    select_with_loaded_routing_policy, select_with_switch_cost_estimates, validate_prior_dataset,
    validate_prior_date, SelectionError,
};
pub use types::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::base_input as selection_test_base_input;

#[cfg(test)]
pub(crate) use public_benchmark::tests::synthetic_snapshot as public_benchmark_test_snapshot;
