//! Typed executor protocol foundation for local-compatible and remote agent runs.
//!
//! This module intentionally has no SSH client and no dependency on the current
//! external-agent report types. [`LocalExecutor`] preserves the existing atomic
//! callback contract, while [`SshExecutor`] exercises the lifecycle protocol only
//! through an injected [`SshTransport`]. Remote results remain candidate evidence;
//! coordinator-side containment, review, recapture, and merge gates are outside
//! this protocol boundary.
//!
//! Collection validates and returns manifest-bound candidate evidence without
//! deleting its remote workspace. Cleanup is a separate typed effect that a future
//! coordinator may request only after durable persistence and local import/recapture;
//! that coordinator wiring is intentionally not claimed here.
//!
//! `LocalExecutor` is compatibility forwarding, not remote-lifecycle trait parity. The real
//! crate's existing concrete higher-ranked reviewed runner forwards through it without
//! changing the callback surface. Production selection and SSH transport wiring remain
//! outside this executor-owned foundation.

mod checksum;
mod local;
mod selection;
mod ssh;
mod types;

pub use local::LocalExecutor;
pub use selection::ExecutorSelection;
pub use ssh::{AgentExecutor, SshExecutor, SshTransport};
pub use types::*;

#[cfg(test)]
mod tests;
