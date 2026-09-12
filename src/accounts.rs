//! Account observations, manual management, and explicitly bound agent proposals.
//!
//! Discovery supplies metadata, never execution authority or quality evidence.

pub mod evaluation;
pub mod invocation_protocol;
mod invocation_state;
pub mod login_protocol;
pub mod management;
pub mod protocol;
pub mod provider;
mod state;
mod transport;

pub(crate) mod cli;

pub use transport::{AccountClient, AccountClientConfig};

use serde::Serialize;

/// Public diagnostics are fixed codes; upstream text and endpoint paths are discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AccountError {
    #[error("account capability transport is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("account capability endpoint failed trust validation")]
    UnsafeEndpoint,
    #[error("account capability request timed out")]
    Timeout,
    #[error("account capability service is unavailable")]
    Unavailable,
    #[error("account capability response failed protocol validation")]
    Protocol,
    #[error("account capability request was refused")]
    Refused,
    #[error("account capability input is invalid")]
    InvalidInput,
    #[error("account management state is unsafe or belongs to another endpoint")]
    UnsafeState,
    #[error("account selection changed; reload before trying again")]
    SelectionConflict,
}
