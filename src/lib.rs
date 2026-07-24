#![deny(unsafe_op_in_unsafe_fn)]

pub mod agent;
pub mod agent_lifecycle;
pub mod artifacts;
pub(crate) mod authenticated_snapshot;
pub mod autopilot;
pub(crate) mod checkpoint_wire;
pub mod cli;
pub mod consult;
pub(crate) mod effect_wal;
pub mod external_agent;
pub mod inbox;
pub mod live_claim;
pub mod llm;
pub mod merge;
pub(crate) mod merge_semantic;
pub mod orchestration_event;
pub mod orchestrator;
pub(crate) mod pinned_exec;
pub mod planning;
pub mod process_runner;
pub mod publication;
pub mod repo_map;
pub mod repo_semantic;
pub mod review;
pub mod safe_state;
pub mod scope;
pub(crate) mod secure_output;
pub mod semantic_coord;
pub(crate) mod state_journal;
pub(crate) mod state_migration;
pub mod supervise;
pub mod sync;
pub mod sync_store;
pub mod worktree;

/// Reserved package-internal bootstrap used by the sealed executable guardian.
///
/// Normal callers receive `Ok(false)`. Package binaries call this before tracing, Tokio, or Clap
/// initialization so the helper path has no ambient CLI/runtime side effects.
#[doc(hidden)]
pub fn maybe_run_pinned_helper_from_args() -> std::io::Result<bool> {
    pinned_exec::maybe_run_helper_from_args()
}
