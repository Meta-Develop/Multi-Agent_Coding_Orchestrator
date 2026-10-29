use super::*;
use crate::account_authority::{
    listen, resolve_socket_path, AuthorityContext, AuthorityListener, AuthorityServerConfig,
    LaunchOperationState, StoredAccountRegistry,
};
use crate::model::{
    Account, AuthKind, ProviderDescriptor, StoredAccountMaterial, StoredAccountMetadata,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROVIDER: &str = "desktop-remote-probe";

struct Adapter {
    root: PathBuf,
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
    fn detect(&self) -> crate::model::InstallState {
        crate::model::InstallState::Unknown
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
    fn launch_spec(&self, _: &StoredAccountMetadata) -> Result<providers::LaunchSpec> {
        self.declarations.fetch_add(1, Ordering::SeqCst);
        let program = if self.missing_program {
            self.root.join("missing-provider")
        } else {
            std::env::current_exe()?
        };
        Ok(providers::LaunchSpec::new(program)
            .current_dir(&self.root)
            .arg("--exact")
            .arg("launch_client::remote_tests::child_probe")
            .set_plain_env("CAM_DESKTOP_REMOTE_PROBE", &self.root))
    }
}

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !predicate() {
        assert!(Instant::now() < deadline, "launch fixture timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn child_probe() {
    let Some(root) = std::env::var_os("CAM_DESKTOP_REMOTE_PROBE") else {
        return;
    };
    let root = PathBuf::from(root);
    fs::write(root.join("ready"), b"ready").unwrap();
    until(|| root.join("release").exists());
    if fs::read(root.join("release")).unwrap() == b"fail" {
        std::process::exit(17);
    }
}

// A framed proxy allows a completed service reply to be lost without touching
// its child, and keeps the same authenticated peer identity as the desktop.
struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    registry: StoredAccountRegistry,
    service: ManagedLaunchService,
    adapter: Adapter,
    drop_reply: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    proxy: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new(missing_program: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let registry = StoredAccountRegistry::new(root.join("accounts.json"));
        registry
            .begin_add(
                PROVIDER,
                "work",
                "Work",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .unwrap();
        registry.complete_add(PROVIDER, "work").unwrap();
        registry.select_complete(PROVIDER, "work").unwrap();
        let declarations = Arc::new(AtomicUsize::new(0));
        let context = AuthorityContext::new(StoredAccountRegistry::new(registry.metadata_path()))
            .without_registry_fallback()
            .with_adapter(Arc::new(Adapter {
                root: root.clone(),
                declarations: Arc::clone(&declarations),
                missing_program,
            }));
        let listener = Arc::new(
            listen(
                resolve_socket_path(root.join("service.sock")).unwrap(),
                AuthorityServerConfig::new(context).unwrap(),
            )
            .unwrap(),
        );
        let socket = root.join("desktop.sock");
        let proxy_listener = UnixListener::bind(&socket).unwrap();
        proxy_listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let drop_reply = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let proxy = {
            let stop = Arc::clone(&stop);
            let drop_reply = Arc::clone(&drop_reply);
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let (mut stream, _) = match proxy_listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("proxy accept: {error}"),
                    };
                    let request = read(&mut stream);
                    let value: Value = serde_json::from_slice(&request).unwrap();
                    let launch_request =
                        value["operation"].as_str().unwrap().starts_with("launch.");
                    requests.lock().unwrap().push(value);
                    let server: Arc<AuthorityListener> = Arc::clone(&listener);
                    let serve = std::thread::spawn(move || server.accept_once().unwrap());
                    let mut upstream = UnixStream::connect(listener.path()).unwrap();
                    write(&mut upstream, &request);
                    let response = read(&mut upstream);
                    serve.join().unwrap();
                    if !(launch_request && drop_reply.swap(false, Ordering::SeqCst)) {
                        write(&mut stream, &response);
                    }
                }
            })
        };
        Self {
            service: ManagedLaunchService::new(AccountAuthority::Remote(
                AuthorityClient::connect(socket).unwrap(),
            )),
            // Client declarations must never be evaluated. Only the service
            // adapter has a usable working directory/program.
            adapter: Adapter {
                root: root.join("client-must-not-resolve"),
                declarations,
                missing_program: true,
            },
            _directory: directory,
            root,
            registry,
            drop_reply,
            requests,
            stop,
            proxy: Some(proxy),
        }
    }

    fn start(&self) -> LaunchOperationStatus {
        let DesktopLaunch::Remote(status) = self.service.start(&self.adapter).unwrap() else {
            panic!("expected remote launch")
        };
        status
    }

    fn status(&self, handle: &OperationHandle, cancel: bool) -> LaunchOperationStatus {
        self.service.status(handle, cancel).unwrap()
    }

    fn assert_busy(&self) {
        assert!(matches!(
            self.registry.begin_delete(PROVIDER, "work"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Release any barrier child even if an assertion fails.
        let _ = fs::write(self.root.join("release"), b"okay");
        self.stop.store(true, Ordering::SeqCst);
        if let Some(proxy) = self.proxy.take() {
            proxy.join().unwrap();
        }
    }
}

fn read(stream: &mut UnixStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut size = [0; 4];
    stream.read_exact(&mut size).unwrap();
    let size = u32::from_be_bytes(size) as usize;
    assert!(size <= crate::account_authority::MAX_RESPONSE_BYTES);
    let mut body = vec![0; size];
    stream.read_exact(&mut body).unwrap();
    body
}

fn write(stream: &mut UnixStream, body: &[u8]) {
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
}

#[test]
fn remote_launch_handle_retains_authority_custody() {
    for nonzero in [false, true] {
        let fixture = Fixture::new(false);
        let status = fixture.start();
        assert_eq!(status.state, LaunchOperationState::Running);
        until(|| fixture.root.join("ready").exists());
        fixture.assert_busy();
        let encoded = serde_json::to_value(DesktopLaunch::Remote(status.clone())).unwrap();
        assert_eq!(encoded.as_object().unwrap().len(), 5);
        assert!(encoded.get("binding").is_none());
        assert!(encoded.get("accountId").is_none());
        fs::write(
            fixture.root.join("release.pending"),
            if nonzero { b"fail" } else { b"okay" },
        )
        .unwrap();
        fs::rename(
            fixture.root.join("release.pending"),
            fixture.root.join("release"),
        )
        .unwrap();
        let mut exit = status.clone();
        until(|| {
            exit = fixture.status(&status.handle, false);
            exit.state == LaunchOperationState::Exited
        });
        assert_eq!(exit.exit_code, Some(if nonzero { 17 } else { 0 }));
        fixture.registry.begin_delete(PROVIDER, "work").unwrap();
        fixture.registry.finish_delete(PROVIDER, "work").unwrap();
        fixture
            .registry
            .begin_add(
                PROVIDER,
                "work",
                "Replacement",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .unwrap();
        assert_eq!(fixture.adapter.declarations.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn lost_start_reply_retries_frozen_binding_and_key() {
    let fixture = Fixture::new(false);
    fixture.drop_reply.store(true, Ordering::SeqCst);
    assert!(fixture.service.start(&fixture.adapter).is_err());
    until(|| fixture.root.join("ready").exists());
    fixture.assert_busy();
    fixture
        .registry
        .begin_add(
            PROVIDER,
            "other",
            "Other",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .unwrap();
    fixture.registry.complete_add(PROVIDER, "other").unwrap();
    fixture.registry.select_complete(PROVIDER, "other").unwrap();
    fixture.registry.begin_delete(PROVIDER, "other").unwrap();
    fixture.registry.finish_delete(PROVIDER, "other").unwrap();
    fixture.assert_busy();
    let status = fixture.start();
    assert_eq!(status.state, LaunchOperationState::Running);
    let requests = fixture.requests.lock().unwrap();
    let starts: Vec<_> = requests
        .iter()
        .filter(|request| request["operation"] == "launch.start")
        .collect();
    assert_eq!(starts.len(), 2);
    for field in ["binding", "idempotencyKey", "authorityId", "serviceId"] {
        assert_eq!(starts[0][field], starts[1][field]);
    }
    assert_eq!(fixture.adapter.declarations.load(Ordering::SeqCst), 1);
    drop(requests);
    until(|| {
        matches!(
            fixture.status(&status.handle, true).state,
            LaunchOperationState::Cancelled | LaunchOperationState::Exited
        )
    });
}

#[test]
fn confirmed_start_refusals_refresh_service_and_retry_key() {
    for (failure, refresh) in [
        ("access-denied", true),
        ("busy", true),
        ("unavailable", true),
        ("state-unavailable", false),
        ("invalid-status", false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("retry.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let service = ManagedLaunchService::new(AccountAuthority::Remote(
            AuthorityClient::connect(&socket).unwrap(),
        ));
        let adapter = Adapter {
            root,
            declarations: Arc::new(AtomicUsize::new(0)),
            missing_program: true,
        };
        let server = std::thread::spawn(move || {
            let binding = json!({
                "providerId": PROVIDER, "accountId": "work",
                "accountIncarnation": "a".repeat(32), "selectionRevision": 1,
            });
            let mut starts = Vec::new();
            for attempt in 0..2 {
                let operations = if attempt == 0 || refresh {
                    vec!["authority.describe", "selection.get", "launch.start"]
                } else {
                    vec!["launch.start"]
                };
                for operation in operations {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request: Value = serde_json::from_slice(&read(&mut stream)).unwrap();
                    assert_eq!(request["operation"], operation, "{failure}");
                    let mut response = json!({
                        "protocolVersion": 1, "requestId": request["requestId"],
                    });
                    match operation {
                        "authority.describe" => {
                            response["result"] = json!({
                                "authorityId": "authority", "launchServiceId": if attempt == 0 { "old-service" } else { "new-service" },
                                "operations": ["launch.start", "launch.status", "launch.cancel"],
                            })
                        }
                        "selection.get" => {
                            response["result"] = binding.clone();
                            response["result"]["selected"] = json!(true);
                        }
                        "launch.start" => {
                            starts.push(request);
                            if attempt == 0 && failure != "invalid-status" {
                                response["error"] = json!({"code": failure, "message": "refused"});
                            } else {
                                response["result"] = json!({
                                    "handle": if attempt == 0 { "invalid".to_string() } else { "h".repeat(32) },
                                    "state": "running", "processId": 42, "exitCode": null, "failureCode": null,
                                });
                            }
                        }
                        _ => unreachable!(),
                    }
                    write(&mut stream, &serde_json::to_vec(&response).unwrap());
                }
            }
            starts
        });
        assert!(service.start(&adapter).is_err());
        assert!(matches!(
            service.start(&adapter).unwrap(),
            DesktopLaunch::Remote(_)
        ));
        let starts = server.join().unwrap();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0]["serviceId"], "old-service");
        assert_eq!(
            starts[1]["serviceId"],
            if refresh {
                "new-service"
            } else {
                "old-service"
            }
        );
        assert_eq!(
            starts[0]["idempotencyKey"] != starts[1]["idempotencyKey"],
            refresh
        );
        assert_eq!(starts[0]["binding"], starts[1]["binding"]);
        assert_eq!(adapter.declarations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn cancellation_disconnect_retains_reference_until_confirmed_exit() {
    let fixture = Fixture::new(false);
    let status = fixture.start();
    until(|| fixture.root.join("ready").exists());
    fixture.drop_reply.store(true, Ordering::SeqCst);
    assert!(fixture.service.status(&status.handle, false).is_err());
    fixture.assert_busy();
    assert_eq!(
        fixture.status(&status.handle, false).state,
        LaunchOperationState::Running
    );
    fixture.drop_reply.store(true, Ordering::SeqCst);
    assert!(fixture.service.status(&status.handle, true).is_err());
    let mut exit = status.clone();
    until(|| {
        exit = fixture.status(&status.handle, false);
        exit.state == LaunchOperationState::Cancelled
    });
    assert_eq!(fixture.status(&status.handle, true), exit);
    fixture.registry.begin_delete(PROVIDER, "work").unwrap();
}

#[test]
fn remote_spawn_failure_returns_closed_status_and_releases_lease() {
    let fixture = Fixture::new(true);
    let status = fixture.start();
    assert_eq!(status.state, LaunchOperationState::Failed);
    assert_eq!(
        status.failure_code,
        Some(crate::account_authority::ErrorCode::InvalidRequest)
    );
    assert_eq!(status.process_id, None);
    fixture.registry.begin_delete(PROVIDER, "work").unwrap();
    let unknown = serde_json::from_value(json!("x".repeat(32))).unwrap();
    assert!(fixture.service.status(&unknown, true).is_err());
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|request| request["handle"] == "x".repeat(32)));
}
