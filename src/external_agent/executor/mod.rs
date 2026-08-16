//! Typed executor protocol foundation for local-compatible and remote agent runs.
//!
//! This module intentionally has no SSH client and no dependency on the current
//! external-agent report types. [`LocalExecutor`] preserves the existing atomic
//! callback contract, while [`SshExecutor`] exercises the lifecycle protocol only
//! through an injected [`SshTransport`]. Remote results remain candidate evidence;
//! coordinator-side containment, review, recapture, and merge gates are outside
//! this protocol boundary.
//!
//! `LocalExecutor` is compatibility forwarding, not six-phase trait parity. A common
//! selectable outer seam requires the concrete higher-ranked borrowed review/runtime
//! types in the sequenced registration wave and is intentionally not fabricated here.

mod checksum;
mod local;
mod ssh;
mod types;

pub use local::LocalExecutor;
pub use ssh::{AgentExecutor, SshExecutor, SshTransport};
pub use types::*;

#[cfg(test)]
mod tests;
