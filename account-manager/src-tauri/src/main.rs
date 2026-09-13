// Prevents an additional console window from opening on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    coding_agent_manager_lib::run()
}
