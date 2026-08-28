//! Typed secret-lifecycle contract for declared references, scoped injection,
//! and fail-closed residual handling.
//!
//! # Contract
//!
//! This module is the lifecycle governance surface. It does **not** replace
//! bounded credential redaction in `external_agent` (presence detection plus
//! log/report scrubbing). Callers that still copy host environment values into
//! child processes, plans, or journals remain a cross-lane handoff.
//!
//! The contract is:
//!
//! 1. **Declaration.** Plans, assignments, and artifacts may hold only a
//!    [`SecretRef`] plus public metadata ([`SecretPlanBinding`]). Raw material
//!    is never part of those types.
//! 2. **Scope binding.** Every secret is bound to an explicit [`SecretScope`]
//!    (assignment, worktree, and/or runtime). Empty scopes fail closed.
//! 3. **Lazy injection.** Material is copied into a [`SecretEnvironment`] or
//!    process map only at [`SecretVault::inject`] /
//!    [`SecretVault::inject_environment`] for a requester whose scope is the
//!    owner or an explicitly delegated child. Requester identity is exact
//!    [`SecretScope`] equality, not a subset match. Debug/serde of leases and
//!    environments omit raw values.
//! 4. **Persistence.** The only persistence policy is
//!    [`PersistencePolicy::ReferenceOnly`]. [`SecretVault`] itself is not
//!    serializable. Reports, plan bindings, audit events, and errors serialize
//!    references and metadata only.
//! 5. **Delegation.** Children do not inherit secrets. [`SecretVault::delegate`]
//!    grants an exact child scope, or fails when [`DelegationPolicy::Forbidden`].
//! 6. **Rotation / revocation.** [`SecretVault::rotate_material`] issues a new
//!    generation; stale [`SecretRef`] values fail closed.
//!    [`SecretVault::revoke`] stops injection without rewriting history.
//! 7. **Expiry.** Lifetime bounds are checked at the injection boundary.
//! 8. **Destruction.** [`SecretVault::destroy`] drops injection capability.
//!    [`SecretVault::finish`] zeroizes residual redaction copies at end of run.
//! 9. **Audit.** Every mutating action and every denied injection appends a
//!    [`SecretAuditEvent`] that cannot carry raw material.
//! 10. **Redaction.** Residual material in logs, JSON artifacts, reports, and
//!     error formatting is scrubbed through the existing [`crate::llm::Redactor`],
//!     which this lane also made Debug-safe.
//!
//! Fail closed throughout: invalid names, missing material, scope mismatch,
//! undeclared children, stale generations, expiry, revocation, destruction,
//! and audit/capacity overflow are typed errors that omit raw material.

mod audit;
mod injection;
mod material;
mod types;
mod vault;

pub use audit::{SecretAuditAction, SecretAuditEvent, SecretAuditOutcome, SecretAuditTrail};
pub use injection::{SecretEnvironment, SecretLease};
pub use types::{
    DelegationPolicy, PersistencePolicy, SecretDeclaration, SecretLifecycleError,
    SecretPlanBinding, SecretRef, SecretScope, SecretState, SecretStatusView,
    SECRET_LIFECYCLE_VERSION,
};
pub use vault::{SecretLifecycleReport, SecretVault};

#[cfg(test)]
mod tests;
