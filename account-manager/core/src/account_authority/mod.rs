//! Account authority foundation: incarnation identity, selection revisions,
//! cross-process registry locking, and active-use leases.

mod binding;
mod document;
mod incarnation;
mod lock;
mod observe;
mod registry;
mod socket_path;
mod use_lease;

pub mod test_worker;

pub use binding::SelectedAccountBinding;
pub use incarnation::new_account_incarnation;
pub use observe::{
    AccountObserveRequest, AccountObserveResult, AuthObservation, CategoryObservation,
    ModelsObservation, ObservationError, ObservationErrorKind, ObservationOutcome, ObserveCategory,
    QuotaObservation,
};
pub use registry::StoredAccountRegistry;
pub use socket_path::{resolve_socket_path, SafeSocketPath, SocketPathError};
pub use use_lease::SelectedUseLease;
