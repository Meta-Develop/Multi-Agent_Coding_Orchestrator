#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
#[macro_use]
mod test_containment;
#[cfg(all(test, unix))]
mod test_support;

pub mod agent;
pub mod agent_lifecycle;
pub mod artifacts;
pub mod autopilot;
pub mod cli;
pub mod consult;
#[doc(hidden)]
pub mod containment_probe;
pub mod decision_claim;
pub mod eval_harness;
pub mod evaluation;
pub mod evaluation_gate_policy;
pub mod execution_capability;
pub mod execution_replay;
pub mod executor;
pub mod external_agent;
pub mod field_guide;
pub mod gate_denial;
pub mod hierarchy_ledger;
pub mod inbox;
pub mod lane_build;
pub mod live_claim;
pub mod llm;
pub mod loop_guard;
pub mod machine_global;
pub mod megafile;
pub mod merge;
pub mod mutation_taxonomy;
pub mod objective_profile;
pub mod optimizer;
pub mod orchestration_event;
pub mod orchestrator;
pub mod planning;
pub mod pre_action_review;
pub mod process_runner;
pub mod protected_path;
pub mod publication;
pub mod quota;
pub mod repo_map;
pub mod repo_semantic;
pub mod review;
pub mod run_ops;
pub mod runtime_adapter;
pub mod safe_state;
pub mod scope;
pub mod selection;
pub mod semantic_coord;
pub mod steering;
pub mod supervise;
pub mod swarm_health;
pub mod sync;
pub mod sync_store;
pub mod worktree;

pub(crate) mod authenticated_snapshot;
pub(crate) mod budget_ledger;
pub(crate) mod checkpoint_wire;
pub(crate) mod collect_revalidation;
pub(crate) mod effect_wal;
#[cfg(any(windows, test))]
pub(crate) mod file_identity;
pub(crate) mod follow_up_queue;
mod git_repository;
pub(crate) mod merge_freshness;
pub(crate) mod merge_semantic;
pub(crate) mod pinned_exec;
pub(crate) mod secure_output;
pub(crate) mod state_journal;
pub(crate) mod state_migration;
mod supervise_budget;

#[doc(hidden)]
pub use git_repository::configure_libgit2_repository_extensions;

/// Reserved package-internal bootstrap used by the sealed executable guardian.
///
/// Normal callers receive `Ok(false)`. Package binaries call this before tracing, Tokio, or Clap
/// initialization so the helper path has no ambient CLI/runtime side effects.
#[doc(hidden)]
pub fn maybe_run_pinned_helper_from_args() -> std::io::Result<bool> {
    pinned_exec::maybe_run_helper_from_args()
}
