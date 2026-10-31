//! Typed executor protocol foundation for local-compatible and remote agent runs.
//!
//! This module has no dependency on the current
//! external-agent report types. [`LocalExecutor`] preserves the existing atomic
//! callback contract, while [`SshExecutor`] exercises the lifecycle protocol only
//! through an injected [`SshTransport`]. Remote results remain candidate evidence;
//! coordinator-side containment, review, recapture, and merge gates are outside
//! this protocol boundary.
//!
//! [`SupervisedSshExecutor`] binds an explicitly selected, locally validated trust
//! configuration to a transport factory and an attempt-scoped lifecycle. It
//! translates declared local paths to manifest names and observes the existing
//! cancellation token. A Linux lifecycle client is available through `lifecycle`.
//! The supervisor owns durable receipts, recovery,
//! candidate import/recapture, and cleanup through explicit embedding configuration.
//!
//! Collection validates and returns manifest-bound candidate evidence without
//! deleting its remote workspace. Cleanup is a separate typed effect requested by
//! the coordinator only after durable persistence and local import/recapture.
//!
//! `LocalExecutor` is compatibility forwarding, not remote-lifecycle trait parity. The real
//! crate's existing concrete higher-ranked reviewed runner forwards through it without
//! changing the callback surface. Supervisor authority remains outside this
//! executor-owned foundation.

mod checksum;
#[cfg(target_os = "linux")]
pub(crate) mod launch_lifecycle;
#[cfg(target_os = "linux")]
pub mod lifecycle;
mod local;
mod selection;
mod ssh;
mod supervised;
mod supervised_checkpoint;
mod types;

pub use local::LocalExecutor;
pub use selection::ExecutorSelection;
pub use ssh::{AgentExecutor, SshExecutor, SshTransport};
pub use supervised::{
    SupervisedAttemptId, SupervisedEvent, SupervisedPaths, SupervisedSshAttempt,
    SupervisedSshExecutor,
};
pub(crate) use supervised_checkpoint::{DurableCollection, SupervisedCheckpoint};
pub use types::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod supervised_tests;
