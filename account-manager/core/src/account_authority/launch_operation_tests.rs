#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use super::*;
use crate::account_authority::protocol::dispatch_for_peer;
use crate::account_authority::{
    decode_request, dispatch, listen, resolve_socket_path, AuthorityContext, AuthorityListener,
    AuthorityServerConfig, StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::model::{
    Account, AuthKind, InstallState, ProviderDescriptor, StoredAccountMaterial,
    StoredAccountMetadata,
};
use crate::providers::{ActivationMechanism, LaunchSpec, ProviderAdapter};
use crate::storage::{CredentialStore, Secret, SecretRef};
use serde_json::{json, Value};

const PROVIDER: &str = "launch-fixture";
const SECRET: &[u8] = b"FAKE-service-owned-launch-secret";
const PROBE: &str = "account_authority::launch_operation::tests::child_probe";

struct Adapter {
    directory: PathBuf,
    declarations: Arc<AtomicUsize>,
    missing_program: bool,
}

impl ProviderAdapter for Adapter {
    fn id(&self) -> &'static str {
        PROVIDER
    }
    fn descriptor(&self) -> ProviderDescriptor {
        unimplemented!()
    }
    fn config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn detect(&self) -> InstallState {
        InstallState::Unknown
    }
    fn list_accounts(&self) -> Result<Vec<Account>> {
        Ok(Vec::new())
    }
    fn activate_account(&self, _: &str) -> Result<()> {
        unimplemented!()
    }
    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::LaunchEnvironment
    }
    fn launch_spec(&self, _: &StoredAccountMetadata) -> Result<LaunchSpec> {
        self.declarations.fetch_add(1, Ordering::SeqCst);
        let program = if self.missing_program {
            self.directory.join("missing-provider")
        } else {
            std::env::current_exe().unwrap()
        };
        Ok(LaunchSpec::new(program)
            .current_dir(&self.directory)
            .arg("--exact")
            .arg(PROBE)
            .arg("--nocapture")
            .set_plain_env("CAM_REMOTE_LAUNCH_PROBE", &self.directory)
            .set_secret_env("CAM_REMOTE_LAUNCH_SECRET"))
    }
}

struct Store {
    registry: StoredAccountRegistry,
    reads: Arc<AtomicUsize>,
    missing: bool,
    gate: Option<Arc<CredentialGate>>,
}

struct CredentialGate {
    block_next: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl CredentialStore for Store {
    fn id(&self) -> &'static str {
        "launch-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn put(&self, _: &SecretRef, _: &Secret) -> Result<()> {
        unimplemented!()
    }
    fn delete(&self, _: &SecretRef) -> Result<()> {
        unimplemented!()
    }
    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        assert_eq!(*key, SecretRef::for_account(PROVIDER, "work"));
        assert_busy(&self.registry);
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            if gate.block_next.swap(false, Ordering::SeqCst) {
                gate.entered.send(()).unwrap();
                let _ = gate
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30));
                return Err(Error::CredentialStoreUnavailable(
                    "fixture lookup interrupted".into(),
                ));
            }
        }
        Ok((!self.missing).then(|| Secret::new(SECRET.to_vec())))
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    registry: StoredAccountRegistry,
    context: AuthorityContext,
    start: Value,
    declarations: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
}

struct SocketFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    registry: StoredAccountRegistry,
    start: Value,
    declarations: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    listener: Arc<AuthorityListener>,
}

impl Fixture {
    fn new(missing_program: bool, missing_secret: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let metadata = root.join("accounts.json");
        let registry = StoredAccountRegistry::new(&metadata);
        for account in ["work", "other"] {
            registry
                .begin_add(
                    PROVIDER,
                    account,
                    account,
                    AuthKind::ApiKey,
                    StoredAccountMaterial::CredentialStore,
                )
                .unwrap();
            registry.complete_add(PROVIDER, account).unwrap();
        }
        registry.select_complete(PROVIDER, "work").unwrap();
        let declarations = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let mut context = AuthorityContext::new(StoredAccountRegistry::new(&metadata))
            .without_registry_fallback()
            .with_adapter(Arc::new(Adapter {
                directory: root.clone(),
                declarations: Arc::clone(&declarations),
                missing_program,
            }));
        context.credential_store = Some(Arc::new(Store {
            registry: StoredAccountRegistry::new(&metadata),
            reads: Arc::clone(&reads),
            missing: missing_secret,
            gate: None,
        }));
        let describe = decode_request(
            br#"{"protocolVersion":1,"requestId":"describe","operation":"authority.describe"}"#,
        )
        .unwrap();
        let service_id = dispatch(&context, &describe).result.unwrap()["launchServiceId"].clone();
        let start = json!({
            "protocolVersion": 1, "requestId": "start", "operation": "launch.start",
            "authorityId": context.authority_id, "serviceId": service_id,
            "binding": registry.selected_binding(PROVIDER).unwrap().unwrap(),
            "idempotencyKey": "one-launch",
        });
        Self {
            _directory: directory,
            root,
            registry,
            context,
            start,
            declarations,
            reads,
        }
    }

    fn listener(self) -> SocketFixture {
        let path = resolve_socket_path(self.root.join("authority.sock")).unwrap();
        let listener = listen(path, AuthorityServerConfig::new(self.context).unwrap()).unwrap();
        SocketFixture {
            _directory: self._directory,
            root: self.root,
            registry: self.registry,
            start: self.start,
            declarations: self.declarations,
            reads: self.reads,
            listener: Arc::new(listener),
        }
    }
}

fn rpc(listener: &Arc<AuthorityListener>, request: &Value, disconnect: bool) -> Value {
    if disconnect {
        // Close before accept so dispatch must survive a fully disconnected
        // peer with buffered bytes, rather than depend on worker scheduling.
        let response = exchange(listener.path(), request, true);
        listener.accept_once().unwrap();
        return response;
    }
    let server = Arc::clone(listener);
    let serve = std::thread::spawn(move || server.accept_once().unwrap());
    let response = exchange(listener.path(), request, disconnect);
    serve.join().unwrap();
    response
}

fn exchange(path: &Path, request: &Value, disconnect: bool) -> Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = serde_json::to_vec(request).unwrap();
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&request).unwrap();
    if disconnect {
        drop(stream);
        Value::Null
    } else {
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(std::str::from_utf8(SECRET).unwrap()));
        assert!(!text.contains("CAM_REMOTE_LAUNCH"));
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn status_request(start: &Value, handle: &Value, cancel: bool) -> Value {
    json!({
        "protocolVersion": 1, "requestId": "status",
        "operation": if cancel { "launch.cancel" } else { "launch.status" },
        "authorityId": start["authorityId"], "serviceId": start["serviceId"], "handle": handle,
    })
}

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !predicate() {
        assert!(Instant::now() < deadline, "fixture barrier timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_busy(registry: &StoredAccountRegistry) {
    assert!(matches!(
        registry.begin_delete(PROVIDER, "work"),
        Err(Error::AccountAuthorityBusy { .. })
    ));
}

fn release(root: &Path, nonzero: bool) {
    fs::write(
        root.join("release.pending"),
        if nonzero { b"fail" } else { b"okay" },
    )
    .unwrap();
    fs::rename(root.join("release.pending"), root.join("release")).unwrap();
}

#[test]
fn child_probe() {
    let Some(root) = std::env::var_os("CAM_REMOTE_LAUNCH_PROBE") else {
        return;
    };
    assert_eq!(
        std::env::var("CAM_REMOTE_LAUNCH_SECRET")
            .unwrap()
            .as_bytes(),
        SECRET
    );
    let root = PathBuf::from(root);
    fs::write(root.join("ready"), b"ready").unwrap();
    until(|| root.join("release").exists());
    assert_eq!(fs::read(root.join("release")).unwrap(), b"okay");
}

#[test]
fn remote_launch_holds_service_owned_lease() {
    for nonzero in [false, true] {
        let SocketFixture {
            _directory,
            root,
            registry,
            start,
            declarations,
            reads,
            listener,
        } = Fixture::new(false, false).listener();
        // The service completes dispatch even when the start reply is lost.
        rpc(&listener, &start, true);
        until(|| root.join("ready").exists());
        assert_busy(&registry);
        let future = registry
            .select_complete_revision(
                PROVIDER,
                "other",
                start["binding"]["selectionRevision"].as_u64(),
            )
            .unwrap();
        assert_eq!(future.account_id, "other");
        registry.begin_delete(PROVIDER, "other").unwrap();
        registry.finish_delete(PROVIDER, "other").unwrap();
        assert_busy(&registry);
        let replay = rpc(&listener, &start, false);
        assert_eq!(replay["result"]["state"], "running");
        let status = status_request(&start, &replay["result"]["handle"], false);
        assert_eq!(rpc(&listener, &status, false)["result"]["state"], "running");
        assert_eq!(declarations.load(Ordering::SeqCst), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        release(&root, nonzero);
        let mut exited = Value::Null;
        until(|| {
            exited = rpc(&listener, &status, false);
            exited["result"]["state"] == "exited"
        });
        assert_eq!(exited["result"]["exitCode"] == 0, !nonzero);
        assert_eq!(rpc(&listener, &start, false)["result"], exited["result"]);
        registry.begin_delete(PROVIDER, "work").unwrap();
        registry.finish_delete(PROVIDER, "work").unwrap();
        registry
            .begin_add(
                PROVIDER,
                "work",
                "Replacement",
                AuthKind::ApiKey,
                StoredAccountMaterial::CredentialStore,
            )
            .unwrap();
        assert_ne!(
            registry
                .account(PROVIDER, "work")
                .unwrap()
                .account_incarnation,
            start["binding"]["accountIncarnation"].as_str().unwrap()
        );
        assert_eq!(declarations.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn remote_launch_cancel_and_listener_drop_retain_custody() {
    let SocketFixture {
        _directory,
        root,
        registry,
        start,
        declarations,
        listener,
        ..
    } = Fixture::new(false, false).listener();
    let response = rpc(&listener, &start, false);
    until(|| root.join("ready").exists());
    let cancel = status_request(&start, &response["result"]["handle"], true);
    rpc(&listener, &cancel, true);
    until(|| rpc(&listener, &cancel, false)["result"]["state"] == "cancelled");
    assert_eq!(
        rpc(&listener, &start, false)["result"]["state"],
        "cancelled"
    );
    assert_eq!(declarations.load(Ordering::SeqCst), 1);
    registry.select_complete(PROVIDER, "other").unwrap();
    assert!(root.join("ready").exists());

    let SocketFixture {
        _directory,
        root: root2,
        registry,
        start,
        listener,
        ..
    } = Fixture::new(false, false).listener();
    rpc(&listener, &start, false);
    until(|| root2.join("ready").exists());
    drop(listener);
    assert_busy(&registry);
    release(&root2, false);
    until(|| registry.begin_delete(PROVIDER, "work").is_ok());
}

#[test]
fn unknown_outcome_stops_reaper_without_releasing_custody() {
    let fixture = Fixture::new(false, false);
    let operations = LaunchOperationStore::new();
    let binding = fixture
        .registry
        .selected_binding(PROVIDER)
        .unwrap()
        .unwrap();
    let status = operations
        .start(
            "authority",
            "uid:1",
            &binding,
            "unknown-wait",
            |lifecycle| spawn_fixture_child(&fixture, lifecycle),
        )
        .unwrap();
    until(|| fixture.root.join("ready").exists());
    let row = Arc::clone(&operations.inner.lock().unwrap().by_handle[&status.handle]);
    // Prevent the reaper from observing this exact test-owned child's exit,
    // then force an unconfirmable wait without touching any unrelated PID.
    let custody = row.lock().unwrap();
    let pid = custody.child.as_ref().unwrap().id() as libc::pid_t;
    release(&fixture.root, false);
    let mut exit_status = 0;
    loop {
        // SAFETY: pid is solely this fixture's child; exit_status is writable.
        if unsafe { libc::waitpid(pid, &mut exit_status, 0) } == pid {
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    drop(custody);
    for _ in 0..2 {
        let status = operations
            .status("authority", "uid:1", &status.handle, true)
            .unwrap();
        assert_eq!(status.state, LaunchOperationState::OutcomeUnknown);
        assert_busy(&fixture.registry);
    }
    let (stopped_tx, stopped_rx) = mpsc::channel();
    let reaper_row = Arc::clone(&row);
    let reaper = std::thread::spawn(move || {
        reap(reaper_row);
        stopped_tx.send(()).unwrap();
    });
    let stopped = stopped_rx.recv_timeout(Duration::from_secs(2));
    if stopped.is_err() {
        // Let a regressed reaper terminate before failing the assertion.
        row.lock().unwrap().child.take();
    }
    reaper.join().unwrap();
    stopped.expect("unknown-outcome reaper kept polling");
    assert!(row.lock().unwrap().child.is_some());
    assert_eq!(
        row.lock().unwrap().lifecycle.snapshot().phase,
        LaunchPhase::ExitUnknown
    );
    assert_busy(&fixture.registry);
    assert_eq!(
        operations
            .status("authority", "uid:1", &status.handle, false)
            .unwrap()
            .state,
        LaunchOperationState::OutcomeUnknown
    );
}

fn spawn_fixture_child(
    fixture: &Fixture,
    lifecycle: LaunchLifecycle,
) -> std::result::Result<LeasedChild, ErrorCode> {
    let adapter = fixture.context.adapters.get(PROVIDER).unwrap();
    crate::providers::leased_launch::spawn_service_launch(
        &fixture.registry,
        adapter.as_ref(),
        lifecycle,
        || {
            Ok(Box::new(Store {
                registry: StoredAccountRegistry::new(fixture.registry.metadata_path()),
                reads: Arc::clone(&fixture.reads),
                missing: false,
                gate: None,
            }))
        },
    )
    .map_err(|_| ErrorCode::Unavailable)
}

#[test]
fn stalled_start_and_retry_do_not_block_other_status_or_cancel() {
    let fixture = Fixture::new(false, false);
    let operations = Arc::new(LaunchOperationStore::new());
    let binding = fixture
        .registry
        .selected_binding(PROVIDER)
        .unwrap()
        .unwrap();
    let live = operations
        .start("authority", "uid:1", &binding, "live", |lifecycle| {
            spawn_fixture_child(&fixture, lifecycle)
        })
        .unwrap();
    until(|| fixture.root.join("ready").exists());

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocked_operations = Arc::clone(&operations);
    let blocked_binding = binding.clone();
    let blocked = std::thread::spawn(move || {
        blocked_operations.start(
            "authority",
            "uid:1",
            &blocked_binding,
            "stalled",
            |_lifecycle| {
                entered_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                Err(ErrorCode::Unavailable)
            },
        )
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let (retry_entered_tx, retry_entered_rx) = mpsc::channel();
    let retry_operations = Arc::clone(&operations);
    let retry = std::thread::spawn(move || {
        retry_entered_tx.send(()).unwrap();
        retry_operations.start("authority", "uid:1", &binding, "stalled", |_lifecycle| {
            panic!("a retry must not invoke the provider twice")
        })
    });
    retry_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();

    let (observed_tx, observed_rx) = mpsc::channel();
    let query_operations = Arc::clone(&operations);
    let live_handle = live.handle.clone();
    let query = std::thread::spawn(move || {
        let before = query_operations.status("authority", "uid:1", &live_handle, false);
        let cancel = query_operations.status("authority", "uid:1", &live_handle, true);
        observed_tx.send((before, cancel)).unwrap();
    });
    let observed = observed_rx.recv_timeout(Duration::from_secs(5));
    // Unblock and join the fixture workers before asserting, including when
    // the regression would have prevented status/cancel from completing.
    release_tx.send(()).unwrap();
    let first = blocked.join().unwrap().unwrap();
    let repeated = retry.join().unwrap().unwrap();
    query.join().unwrap();
    let (before, cancel) = observed.expect("unrelated status/cancel blocked behind start");
    assert_eq!(before.unwrap().state, LaunchOperationState::Running);
    assert!(matches!(
        cancel.unwrap().state,
        LaunchOperationState::Cancelling | LaunchOperationState::Cancelled
    ));
    assert_eq!(first, repeated);
    assert_eq!(first.state, LaunchOperationState::Failed);
    assert_eq!(fixture.declarations.load(Ordering::SeqCst), 1);
    until(|| {
        operations
            .status("authority", "uid:1", &live.handle, false)
            .unwrap()
            .state
            == LaunchOperationState::Cancelled
    });
    let lifecycle = operations.inner.lock().unwrap().by_handle[&live.handle]
        .lock()
        .unwrap()
        .lifecycle
        .clone();
    let finalized = lifecycle.snapshot();
    assert_eq!(
        finalized.phase,
        LaunchPhase::Finalized(LaunchFinalization::Cancelled)
    );
    operations
        .status("authority", "uid:1", &live.handle, true)
        .unwrap();
    assert_eq!(lifecycle.snapshot(), finalized);
    fixture.registry.select_complete(PROVIDER, "other").unwrap();
}

#[test]
fn service_operation_consumes_one_exact_lifecycle_and_preserves_finalization() {
    for nonzero in [false, true] {
        let fixture = Fixture::new(false, false);
        let operations = LaunchOperationStore::new();
        let binding = fixture
            .registry
            .selected_binding(PROVIDER)
            .unwrap()
            .unwrap();
        let live = operations
            .start("authority", "uid:1", &binding, "one-guard", |lifecycle| {
                spawn_fixture_child(&fixture, lifecycle)
            })
            .unwrap();
        until(|| fixture.root.join("ready").exists());
        let lifecycle = operations.inner.lock().unwrap().by_handle[&live.handle]
            .lock()
            .unwrap()
            .lifecycle
            .clone();
        let view = lifecycle.snapshot();
        assert_eq!(view.run_id, operations.service_id);
        assert_eq!(view.operation_id, live.handle.as_str());
        assert_eq!(view.binding, binding);
        assert_eq!(view.phase, LaunchPhase::Running);
        assert_eq!(
            view.credential,
            Some(SecretRef::for_account(PROVIDER, "work"))
        );
        assert_eq!(
            operations
                .start("authority", "uid:1", &binding, "one-guard", |_| {
                    panic!("retry must not allocate or spawn another lifecycle")
                })
                .unwrap(),
            live
        );
        assert_eq!(lifecycle.snapshot(), view);
        assert_eq!(fixture.declarations.load(Ordering::SeqCst), 1);
        release(&fixture.root, nonzero);
        until(|| {
            operations
                .status("authority", "uid:1", &live.handle, false)
                .unwrap()
                .state
                == LaunchOperationState::Exited
        });
        let finalized = lifecycle.snapshot();
        assert_eq!(
            finalized.phase,
            LaunchPhase::Finalized(if nonzero {
                LaunchFinalization::AbnormalExit
            } else {
                LaunchFinalization::Exited
            })
        );
        operations
            .status("authority", "uid:1", &live.handle, true)
            .unwrap();
        assert_eq!(lifecycle.snapshot(), finalized);
        fixture.registry.begin_delete(PROVIDER, "work").unwrap();
    }

    let fixture = Fixture::new(true, false);
    let operations = LaunchOperationStore::new();
    let binding = fixture
        .registry
        .selected_binding(PROVIDER)
        .unwrap()
        .unwrap();
    let failed = operations
        .start(
            "authority",
            "uid:1",
            &binding,
            "failed-guard",
            |lifecycle| spawn_fixture_child(&fixture, lifecycle),
        )
        .unwrap();
    assert_eq!(failed.state, LaunchOperationState::Failed);
    let lifecycle = operations.inner.lock().unwrap().by_handle[&failed.handle]
        .lock()
        .unwrap()
        .lifecycle
        .clone();
    let finalized = lifecycle.snapshot();
    assert_eq!(
        finalized.phase,
        LaunchPhase::Finalized(LaunchFinalization::SpawnFailed)
    );
    assert_eq!(
        operations
            .start("authority", "uid:1", &binding, "failed-guard", |_| {
                panic!("failed operation retries must keep their original guard")
            })
            .unwrap(),
        failed
    );
    assert_eq!(lifecycle.snapshot(), finalized);
    fixture.registry.begin_delete(PROVIDER, "work").unwrap();
}

#[test]
fn listener_cancels_live_child_while_another_start_blocks_in_credentials() {
    let mut fixture = Fixture::new(false, false);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let gate = Arc::new(CredentialGate {
        block_next: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    fixture.context.credential_store = Some(Arc::new(Store {
        registry: StoredAccountRegistry::new(fixture.registry.metadata_path()),
        reads: Arc::clone(&fixture.reads),
        missing: false,
        gate: Some(Arc::clone(&gate)),
    }));
    let SocketFixture {
        _directory,
        root,
        registry,
        start,
        listener,
        ..
    } = fixture.listener();
    let path = listener.path().to_path_buf();
    let server_listener = Arc::clone(&listener);
    // Use the same single accept-thread loop as the service, across all three
    // connections. No request helper spawns another accept thread.
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            server_listener.accept_once().unwrap();
        }
    });
    let live = exchange(&path, &start, false);
    until(|| root.join("ready").exists());
    gate.block_next.store(true, Ordering::SeqCst);
    let mut blocked_start = start.clone();
    blocked_start["idempotencyKey"] = json!("blocked-start");
    let blocked_path = path.clone();
    let blocked = std::thread::spawn(move || exchange(&blocked_path, &blocked_start, false));
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let cancel = status_request(&start, &live["result"]["handle"], true);
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let cancelling = std::thread::spawn(move || {
        cancelled_tx.send(exchange(&path, &cancel, false)).unwrap();
    });
    let cancelled = cancelled_rx.recv_timeout(Duration::from_secs(2));
    // Always release the blocked lookup and join the exact fixture workers,
    // including when synchronous accept would have delayed cancellation.
    release_tx.send(()).unwrap();
    let failed_start = blocked.join().unwrap();
    cancelling.join().unwrap();
    server.join().unwrap();
    let cancelled =
        cancelled.expect("cancel blocked behind another connection's credential lookup");
    assert!(matches!(
        cancelled["result"]["state"].as_str(),
        Some("cancelling" | "cancelled")
    ));
    assert_eq!(failed_start["result"]["state"], "failed");
    until(|| registry.begin_delete(PROVIDER, "work").is_ok());
}

#[test]
fn remote_launch_failures_are_idempotent_and_stale_bindings_refuse() {
    for failure in ["program", "secret", "selection", "incarnation"] {
        let fixture = Fixture::new(failure == "program", failure == "secret");
        let mut start = fixture.start.clone();
        if failure == "selection" {
            fixture.registry.select_complete(PROVIDER, "other").unwrap();
        }
        if failure == "incarnation" {
            start["binding"]["accountIncarnation"] = json!("0".repeat(32));
        }
        let SocketFixture {
            _directory,
            registry,
            declarations,
            listener,
            ..
        } = fixture.listener();
        let response = rpc(&listener, &start, false);
        assert_eq!(response["result"]["state"], "failed");
        let code = match failure {
            "selection" => "stale-selection",
            "incarnation" => "stale-account",
            "secret" => "unknown-account",
            _ => "invalid-request",
        };
        assert_eq!(response["result"]["failureCode"], code);
        assert_eq!(rpc(&listener, &start, false), response);
        let mut changed = start.clone();
        changed["binding"]["selectionRevision"] = json!(99);
        assert_eq!(
            rpc(&listener, &changed, false)["error"]["code"],
            "invalid-request"
        );
        assert_eq!(
            declarations.load(Ordering::SeqCst),
            usize::from(matches!(failure, "program" | "secret"))
        );
        registry.select_complete(PROVIDER, "other").unwrap();
        registry.begin_delete(PROVIDER, "work").unwrap();
    }
}

#[test]
fn remote_launch_closed_fields_and_requester_are_enforced() {
    let fixture = Fixture::new(true, false);
    for field in [
        "program",
        "args",
        "environment",
        "callerIdentity",
        "credential",
    ] {
        let mut request = fixture.start.clone();
        request[field] = json!("untrusted");
        assert_eq!(
            decode_request(&serde_json::to_vec(&request).unwrap())
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
    }
    let decoded = decode_request(&serde_json::to_vec(&fixture.start).unwrap()).unwrap();
    assert_eq!(
        dispatch(&fixture.context, &decoded).error.unwrap().code,
        ErrorCode::AccessDenied
    );
    for field in ["authorityId", "serviceId"] {
        let mut request = fixture.start.clone();
        request[field] = json!("different-authority-or-restarted-service");
        let decoded = decode_request(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert_eq!(
            dispatch_for_peer(&fixture.context, &decoded, Some("uid:1"))
                .error
                .unwrap()
                .code,
            ErrorCode::AccessDenied
        );
    }
    assert_eq!(fixture.declarations.load(Ordering::SeqCst), 0);
    let response = dispatch_for_peer(&fixture.context, &decoded, Some("uid:1"));
    let status = status_request(&fixture.start, &response.result.unwrap()["handle"], true);
    let status = decode_request(&serde_json::to_vec(&status).unwrap()).unwrap();
    assert_eq!(
        dispatch_for_peer(&fixture.context, &status, Some("uid:2"))
            .error
            .unwrap()
            .code,
        ErrorCode::AccessDenied
    );
    assert!(dispatch_for_peer(&fixture.context, &status, Some("uid:1"))
        .error
        .is_none());
}
