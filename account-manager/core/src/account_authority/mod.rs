//! Account authority foundation: incarnation identity, selection revisions,
//! cross-process registry locking, and active-use leases.

mod binding;
mod document;
mod incarnation;
mod lock;
mod observe;
mod protocol;
mod registry;
mod server;
mod socket_path;
mod use_lease;

#[cfg(unix)]
mod peer;

pub mod test_worker;

pub use binding::SelectedAccountBinding;
pub use incarnation::new_account_incarnation;
pub use observe::{
    AccountObserveRequest, AccountObserveResult, AuthObservation, CategoryObservation,
    ModelsObservation, ObservationError, ObservationErrorKind, ObservationOutcome, ObserveCategory,
    QuotaObservation,
};
pub use protocol::{
    authority_id_for, decode_request, dispatch, map_core_error, AuthorityContext, AuthorityResponse,
    DecodedRequest, ErrorCode, LoginPort, ProtocolBounds, ProtocolFailure, ADVERTISED_OPERATIONS,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION, REQUEST_IO_DEADLINE,
};
pub use registry::StoredAccountRegistry;
pub use server::{
    listen, AuthorityListener, AuthorityServerConfig, GeminiLoginPort, ListenError, PeerPolicy,
};
pub use socket_path::{resolve_socket_path, SafeSocketPath, SocketPathError};
pub use use_lease::{PendingLoginBinding, PendingLoginLease, SelectedUseLease};
