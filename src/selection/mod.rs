//! Pure, replayable runtime/model/effort selection.
//!
//! The selector has no runtime or clock access. Callers supply advertised
//! catalogs, operational state, dated priors, and the complete outcome ledger;
//! the returned decision contains the normalized-input digests and every
//! candidate considered.

mod quota_input;
mod schema;
mod selector;
mod types;

pub use quota_input::{
    apply_fail_closed_quota_pools, fail_closed_quota_selector_input, runtime_pool_states,
};
pub(crate) use schema::selection_event_schema_value;
pub use selector::{
    built_in_prior_dataset, measured_authority_eligibility, select,
    select_with_switch_cost_estimates, SelectionError,
};
pub use types::*;

#[cfg(test)]
mod tests;
