//! Account authority foundation: incarnation identity, selection revisions,
//! cross-process registry locking, and active-use leases.

mod binding;
mod document;
mod incarnation;
mod lock;
mod registry;
mod use_lease;

pub mod test_worker;

pub use binding::SelectedAccountBinding;
pub use incarnation::new_account_incarnation;
pub use registry::StoredAccountRegistry;
pub use use_lease::{PendingLoginBinding, PendingLoginLease, SelectedUseLease};
