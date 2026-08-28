//! Provider-neutral live steering and in-flight correction.
//!
//! This module is the write-side control plane for in-flight assignments. Scope
//! remains a GET-only observability surface; steering never posts through it.
//! Durable evidence lives in a dedicated authenticated journal so crash-replay
//! checkpoint state is never rewritten by a steering action.

mod authority;
mod control_plane;
mod evidence;
mod plane;
mod runtime;
mod types;

pub use control_plane::{bind_and_serve, serve, serve_listener, SteeringServeOptions};
pub use evidence::STEERING_STATE_NAMESPACE;
pub use plane::SteeringPlane;
pub use runtime::{apply_inject_to_prompt, SteerableFakeSession};
pub use types::{
    AssignmentBinding, AssignmentKind, HitlDecisionKind, SignedSteeringAckRequest,
    SignedSteeringRequest, SignedSteeringSweepRequest, SteeringAck, SteeringAction, SteeringActor,
    SteeringDecision, SteeringDirective, SteeringEvidenceRecord, SteeringOutcome, SteeringRefusal,
    SteeringRequest, STEERING_REQUEST_VERSION,
};

#[cfg(test)]
mod tests;
