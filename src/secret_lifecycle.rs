//! Typed secret-lifecycle contract for declared references, scoped injection,
//! and fail-closed residual handling.
//!
//! # Contract
//!
//! This module is the lifecycle governance surface. It does **not** replace
//! bounded credential redaction in `external_agent` (presence detection plus
//! log/report scrubbing). CAM selected launches and root selected-account dispatch use the
//! equivalent closed operation: an exact incarnation/use lease and run-bound admission.
//! Codex, Claude, Cursor, Gemini and Grok open their selected credential capability during guarded
//! construction and settles custody only from live process-tree evidence.
//! On Linux, `ProviderLaunchMetadata` is reference-only descriptive evidence.
//! Admission deadlines and pre-spawn revocation refuse pending construction.
//! Once a child starts, cancellation and verified tree exit govern finalization;
//! expiry or revocation cannot assert that a running child has stopped. The
//! incarnation/use lease prevents rotation and account replacement until exit,
//! and an outer authority lease also covers report and relay teardown. Unknown
//! exit retains custody. Managed Grok catalog discovery follows the same rule.
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
#[cfg(target_os = "linux")]
mod provider_dispatch;
mod types;
mod vault;

pub use audit::{SecretAuditAction, SecretAuditEvent, SecretAuditOutcome, SecretAuditTrail};
pub use injection::{SecretEnvironment, SecretLease};
#[cfg(target_os = "linux")]
pub use provider_dispatch::ProviderLaunchMetadata;
pub use types::{
    DelegationPolicy, PersistencePolicy, SecretDeclaration, SecretLifecycleError,
    SecretPlanBinding, SecretRef, SecretScope, SecretState, SecretStatusView,
    SECRET_LIFECYCLE_VERSION,
};
pub use vault::{SecretLifecycleReport, SecretVault};

#[cfg(test)]
mod tests;
