//! Desktop wrapper: Tauri IPC (`commands`) over the headless core crate.

pub use coding_agent_manager_core::{
    account_authority, backup, error, fsx, login, model, paths, providers, relay, router, storage,
};

// Transport and launch custody can be checked without the GUI runtime.
#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
pub mod authority_client;
#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
pub mod launch_client;
mod login_ipc;

#[cfg(feature = "desktop")]
pub mod commands;

/// Start the desktop application.
#[cfg(feature = "desktop")]
pub fn run() {
    commands::run();
}
