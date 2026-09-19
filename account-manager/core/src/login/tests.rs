use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use tokio::runtime::Runtime;

use crate::login::{LoginAccountBinding, LoginService, LoginStartRequest, LoginState};
use crate::model::{AuthKind, StoredAccountState};
use crate::paths;
use crate::providers::{gemini_cli::GeminiCliAdapter, ProviderAdapter, StoredAccountRegistry};

use super::LoginStatus;

const PROVIDER_ID: &str = "gemini-cli";

fn oauth_adapter(
    completer: fn(&Path) -> crate::error::Result<()>,
) -> (tempfile::TempDir, GeminiCliAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    let cwd = dir.path().join("workspace");
    std::fs::create_dir_all(home.join(".gemini")).expect("home settings dir");
    std::fs::create_dir_all(cwd.join(".gemini")).expect("workspace settings dir");
    std::fs::write(
        home.join(".gemini/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
    )
    .expect("settings");
    let adapter = GeminiCliAdapter::with_test_context(
        home,
        data.clone(),
        cwd,
        dir.path().join("system/settings.json"),
        dir.path().join("system/system-defaults.json"),
        None,
    )
    .with_oauth_completer(completer);
    let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data));
    (dir, adapter, registry)
}

fn cancel_driver_adapter() -> (tempfile::TempDir, GeminiCliAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    let cwd = dir.path().join("workspace");
    std::fs::create_dir_all(home.join(".gemini")).expect("home settings dir");
    std::fs::create_dir_all(cwd.join(".gemini")).expect("workspace settings dir");
    std::fs::write(
        home.join(".gemini/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
    )
    .expect("settings");
    let adapter = GeminiCliAdapter::with_test_context(
        home,
        data.clone(),
        cwd,
        dir.path().join("system/settings.json"),
        dir.path().join("system/system-defaults.json"),
        None,
    )
    .with_test_oauth_watch_cancel_driver();
    let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data));
    (dir, adapter, registry)
}

fn service(registry: &StoredAccountRegistry) -> (Runtime, LoginService) {
    let runtime = Runtime::new().expect("runtime");
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    (runtime, service)
}

fn service_with_retain(
    registry: &StoredAccountRegistry,
    retain: Duration,
) -> (Runtime, LoginService) {
    let runtime = Runtime::new().expect("runtime");
    let service = LoginService::with_operation_retain(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
        retain,
    );
    (runtime, service)
}

fn start_request(account_id: &str, key: &str) -> LoginStartRequest {
    LoginStartRequest {
        provider_id: PROVIDER_ID.to_string(),
        account_id: account_id.to_string(),
        label: account_id.to_string(),
        auth_kind: AuthKind::OAuth,
        idempotency_key: key.to_string(),
    }
}

fn wait_for_state(
    runtime: &Runtime,
    service: &LoginService,
    status: &LoginStatus,
    target: LoginState,
) {
    for _ in 0..200 {
        let current = service
            .status(&status.handle, &status.binding)
            .expect("status");
        if current.state == target {
            return;
        }
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(10)).await });
    }
    panic!("timed out waiting for {target:?}");
}

fn write_oauth_files(home: &Path) -> crate::error::Result<()> {
    crate::providers::gemini_oauth::write_fake_oauth_home(home, None)
}

fn fail_oauth(_home: &Path) -> crate::error::Result<()> {
    Err(crate::error::Error::ConfigWrite {
        provider: PROVIDER_ID.to_string(),
        reason: "injected FAKE-token at /tmp/secret/oauth failed".to_string(),
    })
}

fn panic_if_oauth_runs(_home: &Path) -> crate::error::Result<()> {
    panic!("interactive OAuth must not run for a recovered home marker")
}

static GATED_COMPLETER_READY: AtomicBool = AtomicBool::new(false);
static GATED_COMPLETER_RELEASE: AtomicBool = AtomicBool::new(false);
static RACE_COMPLETER_STARTED: AtomicBool = AtomicBool::new(false);
static RACE_COMPLETER_RELEASE: AtomicBool = AtomicBool::new(false);

static COMPLETER_SYNC_GLOBALS: Mutex<()> = Mutex::new(());

struct CompleterSyncGuard {
    _lock: MutexGuard<'static, ()>,
}

impl CompleterSyncGuard {
    fn acquire() -> Self {
        let lock = COMPLETER_SYNC_GLOBALS.lock().expect("completer sync");
        GATED_COMPLETER_READY.store(false, Ordering::SeqCst);
        GATED_COMPLETER_RELEASE.store(false, Ordering::SeqCst);
        RACE_COMPLETER_STARTED.store(false, Ordering::SeqCst);
        RACE_COMPLETER_RELEASE.store(false, Ordering::SeqCst);
        Self { _lock: lock }
    }
}

impl Drop for CompleterSyncGuard {
    fn drop(&mut self) {
        GATED_COMPLETER_RELEASE.store(true, Ordering::SeqCst);
        RACE_COMPLETER_RELEASE.store(true, Ordering::SeqCst);
    }
}

const COMPLETER_SYNC_WAIT: Duration = Duration::from_secs(5);

fn wait_for_completer_flag(flag: &AtomicBool) {
    let deadline = std::time::Instant::now() + COMPLETER_SYNC_WAIT;
    while !flag.load(Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for completer synchronization");
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn gated_completer(home: &Path) -> crate::error::Result<()> {
    GATED_COMPLETER_READY.store(true, Ordering::SeqCst);
    while !GATED_COMPLETER_RELEASE.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    write_oauth_files(home)
}

#[test]
fn ready_completes_registry_row_without_changing_selection() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-ready"), &adapter)
        .expect("start");
    wait_for_state(&runtime, &service, &started, LoginState::Ready);
    let row = registry.account(PROVIDER_ID, "work").expect("account");
    assert_eq!(row.state, StoredAccountState::Complete);
    assert!(!row.is_selected);
    assert!(registry.selected(PROVIDER_ID).expect("selected").is_none());
}

#[test]
fn idempotency_replay_returns_same_handle_without_second_pending_row() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (runtime, service) = service(&registry);
    let first = service
        .start(start_request("work", "same-key"), &adapter)
        .expect("first start");
    let second = service
        .start(start_request("work", "same-key"), &adapter)
        .expect("replay");
    assert_eq!(first.handle, second.handle);
    assert_eq!(first.binding, second.binding);
    wait_for_state(&runtime, &service, &first, LoginState::Ready);
    let rows: Vec<_> = registry
        .load()
        .expect("load")
        .into_iter()
        .filter(|row| row.id == "work")
        .collect();
    assert_eq!(rows.len(), 1);
}

#[test]
fn idempotency_mismatch_is_refused_without_extra_pending_row() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (_runtime, service) = service(&registry);
    service
        .start(start_request("work", "same-key"), &adapter)
        .expect("start");
    let mut replay = start_request("work", "same-key");
    replay.label = "different-label".to_string();
    assert!(service.start(replay, &adapter).is_err());
    assert_eq!(
        registry
            .load()
            .expect("load")
            .into_iter()
            .filter(|row| row.id == "work")
            .count(),
        1
    );
}

#[test]
fn concurrent_idempotency_duplicate_start_is_serialized() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (runtime, service) = service(&registry);
    let service = Arc::new(service);
    let adapter = Arc::new(adapter);
    let barrier = Arc::new(Barrier::new(2));
    let request = start_request("work", "concurrent-key");
    let mut handles = Vec::new();
    for _ in 0..2 {
        let service = Arc::clone(&service);
        let adapter = Arc::clone(&adapter);
        let barrier = Arc::clone(&barrier);
        let request = request.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            service.start(request, adapter.as_ref())
        }));
    }
    let first = handles.pop().expect("thread").join().expect("join");
    let second = handles.pop().expect("thread").join().expect("join");
    match (first, second) {
        (Ok(left), Ok(right)) => assert_eq!(left.handle, right.handle),
        (Ok(_), Err(crate::error::Error::AccountAuthorityBusy { .. }))
        | (Err(crate::error::Error::AccountAuthorityBusy { .. }), Ok(_)) => {}
        (Err(left), Err(right)) => panic!("both failed: {left:?} {right:?}"),
        other => panic!("unexpected concurrent login results: {other:?}"),
    }
    let _ = runtime;
}

#[test]
fn failed_login_leaves_recoverable_pending_row_and_terminal_state() {
    let (_dir, adapter, registry) = oauth_adapter(fail_oauth);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-fail"), &adapter)
        .expect("start");
    wait_for_state(&runtime, &service, &started, LoginState::Failed);
    let status = service
        .status(&started.handle, &started.binding)
        .expect("status");
    assert_eq!(status.state, LoginState::Failed);
    let reason = status.failure_reason.expect("reason");
    assert!(!reason.contains("FAKE-"));
    assert!(!reason.contains("/tmp/secret"));
    let row = registry.account(PROVIDER_ID, "work").expect("pending");
    assert_eq!(row.state, StoredAccountState::Pending);
}

#[test]
fn cancelled_login_confirmed_by_owned_async_oauth_fixture() {
    let (_dir, adapter, registry) = cancel_driver_adapter();
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-cancel"), &adapter)
        .expect("start");
    service
        .cancel(&started.handle, &started.binding)
        .expect("cancel");
    wait_for_state(&runtime, &service, &started, LoginState::Cancelled);
    let row = registry.account(PROVIDER_ID, "work").expect("pending");
    assert_eq!(row.state, StoredAccountState::Pending);
}

#[test]
fn cancel_does_not_prematurely_report_cancelled_before_oauth_finishes() {
    let _sync = CompleterSyncGuard::acquire();
    let (_dir, adapter, registry) = oauth_adapter(gated_completer);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-gated-cancel"), &adapter)
        .expect("start");
    wait_for_completer_flag(&GATED_COMPLETER_READY);
    let mid = service
        .cancel(&started.handle, &started.binding)
        .expect("cancel");
    assert_ne!(mid.state, LoginState::Cancelled);
    assert_ne!(mid.state, LoginState::Ready);
    GATED_COMPLETER_RELEASE.store(true, Ordering::SeqCst);
    wait_for_state(&runtime, &service, &started, LoginState::Ready);
}

fn race_completer(home: &Path) -> crate::error::Result<()> {
    RACE_COMPLETER_STARTED.store(true, Ordering::SeqCst);
    while !RACE_COMPLETER_RELEASE.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    write_oauth_files(home)
}

#[test]
fn cancel_vs_ready_race_reports_ready_after_commit() {
    let _sync = CompleterSyncGuard::acquire();
    let (_dir, adapter, registry) = oauth_adapter(race_completer);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-race"), &adapter)
        .expect("start");
    wait_for_completer_flag(&RACE_COMPLETER_STARTED);
    let mid = service
        .cancel(&started.handle, &started.binding)
        .expect("cancel");
    assert_ne!(mid.state, LoginState::Ready);
    RACE_COMPLETER_RELEASE.store(true, Ordering::SeqCst);
    wait_for_state(&runtime, &service, &started, LoginState::Ready);
    let final_status = service
        .cancel(&started.handle, &started.binding)
        .expect("cancel after ready");
    assert_eq!(final_status.state, LoginState::Ready);
}

#[test]
fn unsupported_provider_start_is_refused() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (_runtime, service) = service(&registry);
    let mut request = start_request("work", "key");
    request.provider_id = "codex-cli".to_string();
    assert!(matches!(
        service.start(request, &adapter),
        Err(crate::error::Error::NotImplemented(_))
    ));
}

#[test]
fn unknown_handle_cancel_reports_unknown_without_registry_mutation() {
    let (_dir, _adapter, registry) = oauth_adapter(write_oauth_files);
    let (_runtime, service) = service(&registry);
    let binding = LoginAccountBinding {
        provider_id: PROVIDER_ID.to_string(),
        account_id: "missing".to_string(),
        account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
    };
    let handle = crate::login::LoginHandle("unknown-handle".to_string());
    let status = service.cancel(&handle, &binding).expect("cancel");
    assert_eq!(status.state, LoginState::Unknown);
    assert!(registry.load().expect("load").is_empty());
}

#[test]
fn cancel_after_ready_reports_ready() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-ready-cancel"), &adapter)
        .expect("start");
    wait_for_state(&runtime, &service, &started, LoginState::Ready);
    let status = service
        .cancel(&started.handle, &started.binding)
        .expect("cancel");
    assert_eq!(status.state, LoginState::Ready);
}

#[test]
fn active_login_blocks_delete_until_async_login_settles() {
    let _sync = CompleterSyncGuard::acquire();
    let (_dir, adapter, registry) = oauth_adapter(gated_completer);
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-delete-block"), &adapter)
        .expect("start");
    wait_for_completer_flag(&GATED_COMPLETER_READY);
    assert!(registry.begin_delete(PROVIDER_ID, "work").is_err());
    GATED_COMPLETER_RELEASE.store(true, Ordering::SeqCst);
    wait_for_state(&runtime, &service, &started, LoginState::Ready);
    registry
        .begin_delete(PROVIDER_ID, "work")
        .expect("delete after settle");
}

#[test]
fn service_drop_leaves_unknown_status_without_aborting_inflight_writer() {
    let (_dir, adapter, registry) = cancel_driver_adapter();
    let (runtime, service) = service(&registry);
    let started = service
        .start(start_request("work", "key-drop"), &adapter)
        .expect("start");
    drop(service);
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    let status = service
        .status(&started.handle, &started.binding)
        .expect("status");
    assert_eq!(status.state, LoginState::Unknown);
}

#[test]
fn unfinished_expiry_signals_cancel_and_retains_handle_until_settled() {
    let (_dir, adapter, registry) = cancel_driver_adapter();
    let (runtime, service) = service_with_retain(&registry, Duration::from_millis(50));
    let started = service
        .start(start_request("work", "key-expiry"), &adapter)
        .expect("start");
    runtime.block_on(async { tokio::time::sleep(Duration::from_millis(60)).await });
    let mid = service
        .status(&started.handle, &started.binding)
        .expect("status");
    assert_ne!(mid.state, LoginState::Unknown);
    let cancel = service
        .cancel(&started.handle, &started.binding)
        .expect("cancel");
    assert_ne!(cancel.state, LoginState::Unknown);
    wait_for_state(&runtime, &service, &started, LoginState::Cancelled);
    registry.begin_delete(PROVIDER_ID, "work").expect("delete");
}

#[test]
fn recovered_valid_home_marker_completes_without_oauth_completer() {
    let (_dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let (runtime, service) = service(&registry);
    let first = service
        .start(start_request("work", "key-first"), &adapter)
        .expect("start");
    wait_for_state(&runtime, &service, &first, LoginState::Ready);
    registry.begin_delete(PROVIDER_ID, "work").expect("delete");
    registry.finish_delete(PROVIDER_ID, "work").expect("finish");
    let adapter = adapter.with_oauth_completer(panic_if_oauth_runs);
    let second = service
        .start(start_request("work", "key-recover"), &adapter)
        .expect("recover");
    wait_for_state(&runtime, &service, &second, LoginState::Ready);
    assert!(registry.selected(PROVIDER_ID).expect("selected").is_none());
}

#[cfg(unix)]
#[test]
fn corrupt_oauth_marker_prepare_is_fail_closed() {
    use std::os::unix::fs::symlink;
    let (dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let account = registry
        .begin_add(
            PROVIDER_ID,
            "work",
            "Work",
            AuthKind::OAuth,
            crate::model::StoredAccountMaterial::VendorHome,
        )
        .expect("pending");
    let data = dir.path().join("data");
    let home = crate::providers::managed_account_dir(&data, PROVIDER_ID, "work");
    std::fs::create_dir_all(home.join(".gemini")).expect("dir");
    symlink(home.as_path(), home.join(".gemini/oauth_creds.json")).expect("symlink");
    assert!(adapter.prepare_pending_oauth_home(&account).is_err());
}

#[test]
fn stale_incarnation_commit_with_material_is_outcome_unknown() {
    let (dir, adapter, registry) = oauth_adapter(write_oauth_files);
    let data = dir.path().join("data");
    let first = registry
        .begin_add(
            PROVIDER_ID,
            "work",
            "Work",
            AuthKind::OAuth,
            crate::model::StoredAccountMaterial::VendorHome,
        )
        .expect("begin");
    let home = crate::providers::managed_account_dir(&data, PROVIDER_ID, "work");
    std::fs::create_dir_all(home.join(".gemini")).expect("dir");
    crate::providers::gemini_oauth::write_fake_oauth_home(&home, None).expect("marker");
    registry.begin_delete(PROVIDER_ID, "work").expect("delete");
    registry.finish_delete(PROVIDER_ID, "work").expect("finish");
    let second = registry
        .begin_add(
            PROVIDER_ID,
            "work",
            "Work",
            AuthKind::OAuth,
            crate::model::StoredAccountMaterial::VendorHome,
        )
        .expect("readd");
    assert!(matches!(
        registry.complete_pending_if_incarnation_matches(
            PROVIDER_ID,
            "work",
            &first.account_incarnation,
            AuthKind::OAuth,
            crate::model::StoredAccountMaterial::VendorHome,
        ),
        Err(crate::error::Error::StaleAccount { .. })
    ));
    assert!(home.join(".gemini/oauth_creds.json").is_file());
    assert_ne!(second.account_incarnation, first.account_incarnation);

    assert!(matches!(
        super::commit_managed_login_after_oauth(
            &registry,
            &adapter as &dyn ProviderAdapter,
            &home,
            &first,
        ),
        super::ManagedLoginCommitOutcome::OutcomeUnknown
    ));
    assert_eq!(
        registry
            .account(PROVIDER_ID, "work")
            .expect("replacement row")
            .state,
        StoredAccountState::Pending
    );
}
