//! Subprocess entry points for cross-process registry tests.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::model::{AuthKind, StoredAccountMaterial};

use super::StoredAccountRegistry;

pub const WORKER_ENV: &str = "CAM_ACCOUNT_AUTHORITY_WORKER";

/// Run a worker command when the environment requests it. Returns `true` when
/// the process should exit immediately (worker mode).
pub fn run_from_env() -> bool {
    match env::var(WORKER_ENV).ok().as_deref() {
        Some("concurrent_batch_add") => {
            concurrent_batch_add_worker();
            true
        }
        Some("hold_use_lease") => {
            hold_use_lease_worker();
            true
        }
        _ => false,
    }
}

fn concurrent_batch_add_worker() {
    let slot = env::var("CAM_WORKER_SLOT")
        .expect("worker slot")
        .parse::<u8>()
        .expect("worker slot byte");
    let sync = PathBuf::from(env::var("CAM_SYNC_DIR").expect("sync directory"));
    let ready = sync.join(format!("ready-{slot}"));
    let start = sync.join("start");
    let done = sync.join(format!("done-{slot}"));

    fs::write(&ready, b"ready").expect("signal ready");

    let deadline = Instant::now() + Duration::from_secs(30);
    while fs::read(&start)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .is_none()
    {
        if Instant::now() > deadline {
            panic!("timed out waiting for concurrent start barrier");
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let path = PathBuf::from(env::var("CAM_REGISTRY_PATH").expect("registry path"));
    let provider = env::var("CAM_PROVIDER_ID").expect("provider id");
    let registry = StoredAccountRegistry::new(path);
    for index in 0..8 {
        let account_id = format!("batch-a{slot}-{index:02}");
        registry
            .begin_add(
                &provider,
                &account_id,
                &account_id,
                AuthKind::ApiKey,
                StoredAccountMaterial::CredentialStore,
            )
            .expect("begin concurrent add");
        registry
            .complete_add(&provider, &account_id)
            .expect("complete concurrent add");
    }
    fs::write(&done, b"ok").expect("signal done");
}

fn hold_use_lease_worker() {
    let path = PathBuf::from(env::var("CAM_REGISTRY_PATH").expect("registry path"));
    let provider = env::var("CAM_PROVIDER_ID").expect("provider id");
    let registry = StoredAccountRegistry::new(path);
    let binding = registry
        .selected_binding(&provider)
        .expect("binding")
        .expect("selected binding");
    let _lease = registry
        .acquire_selected_use(&binding)
        .expect("child use lease");
    let signal = PathBuf::from(env::var("CAM_LEASE_HELD_FILE").expect("lease held file"));
    fs::write(&signal, b"held").expect("signal lease");
    loop {
        if fs::read_to_string(&signal).ok().as_deref() != Some("held") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
