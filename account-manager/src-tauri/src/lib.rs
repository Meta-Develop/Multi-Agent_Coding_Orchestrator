//! Desktop wrapper: Tauri IPC (`commands`) over the headless core crate.

pub use coding_agent_manager_core::{
    account_authority, backup, error, fsx, login, model, paths, providers, relay, router, storage,
};

#[cfg(feature = "desktop")]
pub mod commands;

/// Start the desktop application.
#[cfg(feature = "desktop")]
pub fn run() {
    commands::run();
}
