use multi_agent_coding_orchestrator::accounts::login_protocol::{
    LoginObservation, DEVICE_VERIFICATION_URL,
};
use serde_json::{json, Value};

fn login(alias: &str, handle: &str, status: &str) -> Value {
    json!({"schema_version":1,"handle":handle,"alias":alias,"provider":"openai","runtime":"codex",
        "status":status,"verification_url":if status == "pending" { Some(DEVICE_VERIFICATION_URL) } else { None },
        "user_code":if status == "pending" { Some("opaque-AB C<> &") } else { None },
        "expires_at":null,"broker_deadline":900,"failure":null})
}

const HANDLE: &str = "00000000-0000-4000-8000-000000000001";
const NONCE: &str = "00000000-0000-4000-8000-000000000002";

#[test]
fn login_projection_refuses_unknown_fields_and_unsafe_pending_values() {
    let pending = login("first", HANDLE, "pending");
    serde_json::from_value::<LoginObservation>(pending.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (field, replacement) in [
        (
            "verification_url",
            json!("https://auth.openai.com/codex/device?code=secret"),
        ),
        ("verification_url", Value::Null),
        ("user_code", json!("")),
        ("user_code", json!("bad\ncode")),
        ("expires_at", json!(901)),
        ("schema_version", json!(2)),
        ("handle", json!("not-a-handle")),
        ("failure", json!("timeout")),
        ("alias", json!("../account")),
    ] {
        let mut value = pending.clone();
        value[field] = replacement;
        // Avoid logging the projected code even on assertion failure.
        let result = serde_json::from_value::<LoginObservation>(value);
        assert!(
            result.is_err() || result.unwrap().validate().is_err(),
            "field {field}"
        );
    }
    for field in ["verification_url", "user_code", "expires_at", "failure"] {
        let mut value = pending.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<LoginObservation>(value).is_err());
    }
    for (field, replacement) in [
        ("status", json!("unknown")),
        ("provider", json!("other")),
        ("runtime", json!("other")),
        ("failure", json!("raw_upstream_error")),
        ("raw_provider_id", json!("secret")),
    ] {
        let mut value = pending.clone();
        value[field] = replacement;
        assert!(serde_json::from_value::<LoginObservation>(value).is_err());
    }
    let mut ready = pending;
    ready["status"] = json!("ready");
    assert!(serde_json::from_value::<LoginObservation>(ready)
        .unwrap()
        .validate()
        .is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use multi_agent_coding_orchestrator::accounts::{
        login_protocol::LoginStatus, management::ManagementServer, AccountClient,
        AccountClientConfig, AccountError,
    };
    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::{SocketAddr, TcpStream},
        os::unix::{
            fs::{symlink, MetadataExt, PermissionsExt},
            net::UnixListener,
        },
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread,
        time::Duration,
    };

    struct Attempt {
        nonce: String,
        result: Value,
    }
    #[derive(Default)]
    struct BrokerState {
        requests: Vec<Value>,
        attempts: BTreeMap<String, Attempt>,
        starts: u64,
        next_result: Option<Value>,
    }
    struct Broker {
        temp: tempfile::TempDir,
        config: AccountClientConfig,
        state: Arc<Mutex<BrokerState>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Broker {
        fn new() -> Self {
            let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let socket = temp.path().join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let state = Arc::new(Mutex::new(BrokerState::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let server_state = Arc::clone(&state);
            let server_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !server_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut bytes = String::new();
                            BufReader::new(&stream).read_line(&mut bytes).unwrap();
                            let request: Value = serde_json::from_str(&bytes).unwrap();
                            let mut state = server_state.lock().unwrap();
                            state.requests.push(request.clone());
                            let result = state
                                .next_result
                                .take()
                                .map(Ok)
                                .unwrap_or_else(|| produce(&request, &mut state));
                            let envelope = match result {
                                Ok(value) => json!({"id":request["id"],"ok":true,"result":value}),
                                Err(()) => {
                                    json!({"id":request["id"],"ok":false,"error":{"code":"access_denied","message":"untrusted diagnostic discarded"}})
                                }
                            };
                            let mut reply = serde_json::to_vec(&envelope).unwrap();
                            reply.push(b'\n');
                            stream.write_all(&reply).unwrap();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25))
                        }
                        Err(error) => panic!("synthetic service accept: {error}"),
                    }
                }
            });
            let config = AccountClientConfig {
                socket,
                expected_uid: unsafe { libc::geteuid() },
                timeout: Duration::from_secs(5),
            };
            Self {
                temp,
                config,
                state,
                stop,
                thread: Some(thread),
            }
        }
        fn client(&self) -> AccountClient {
            AccountClient::new(self.config.clone()).unwrap()
        }
        fn start_ui(&self, state_name: &str) -> Ui {
            Ui::start(
                ManagementServer::bind(
                    self.client(),
                    &self.temp.path().join(state_name),
                    "127.0.0.1:0".parse().unwrap(),
                )
                .unwrap(),
            )
        }
    }
    impl Drop for Broker {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    fn produce(request: &Value, state: &mut BrokerState) -> Result<Value, ()> {
        let arguments = &request["arguments"];
        let alias = arguments["alias"].as_str().unwrap_or("");
        match request["capability"].as_str().unwrap() {
            "accounts.list" => Ok(json!({"schema_version":1,"accounts":[
                {"alias":"first","provider":"openai","runtime":"codex","enabled":true},
                {"alias":"second","provider":"openai","runtime":"codex","enabled":true},
                {"alias":"disabled","provider":"openai","runtime":"codex","enabled":false}]})),
            "accounts.discover" if matches!(alias, "first" | "second") => Ok(json!({
                "schema_version":1,"observation_id":HANDLE,"account":{"alias":alias,"provider":"openai","runtime":"codex","enabled":true},
                "observed_at":100,"expires_at":null,"auth":{"state":"unknown","provenance":"none"},
                "models":{"state":"unknown","provenance":"none","entitlement":"unknown","items":[]},
                "quota":{"state":"unknown","provenance":"none","windows":[]},"availability":"unknown","failure":null})),
            "accounts.login.start" if matches!(alias, "first" | "second") => {
                let nonce = arguments["request_nonce"].as_str().unwrap();
                if let Some(previous) = state.attempts.get(alias) {
                    if previous.nonce == nonce {
                        return Ok(previous.result.clone());
                    }
                    if matches!(
                        previous.result["status"].as_str(),
                        Some("starting" | "pending" | "confirming")
                    ) || arguments["replace_handle"] != previous.result["handle"]
                    {
                        return Err(());
                    }
                } else if !arguments["replace_handle"].is_null() {
                    return Err(());
                }
                state.starts += 1;
                let handle = format!("00000000-0000-4000-8000-{:012x}", state.starts);
                let result = login(alias, &handle, "pending");
                state.attempts.insert(
                    alias.into(),
                    Attempt {
                        nonce: nonce.into(),
                        result: result.clone(),
                    },
                );
                Ok(result)
            }
            "accounts.login.status" | "accounts.login.cancel" => {
                let attempt = state.attempts.get_mut(alias).ok_or(())?;
                if !arguments["handle"].is_null() && arguments["handle"] != attempt.result["handle"]
                {
                    return Err(());
                }
                if request["capability"] == "accounts.login.cancel" {
                    attempt.result = login(
                        alias,
                        attempt.result["handle"].as_str().unwrap(),
                        "cancelled",
                    );
                }
                Ok(attempt.result.clone())
            }
            _ => Err(()),
        }
    }

    struct Ui {
        address: SocketAddr,
        secret: String,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }
    impl Ui {
        fn start(server: ManagementServer) -> Self {
            let address = server.local_addr().unwrap();
            let secret = server.launch_url().split_once('#').unwrap().1.to_owned();
            let stop = Arc::new(AtomicBool::new(false));
            let server_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || server.serve(server_stop).unwrap());
            Self {
                address,
                secret,
                stop,
                thread: Some(thread),
            }
        }
        fn raw(&self, request: &str) -> (u16, String) {
            let mut stream = TcpStream::connect(self.address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reader = BufReader::new(stream);
            let mut response = String::new();
            let mut length = None;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
                response.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length.unwrap()];
            reader.read_exact(&mut body).unwrap();
            response.push_str(std::str::from_utf8(&body).unwrap());
            (
                response.split_whitespace().nth(1).unwrap().parse().unwrap(),
                response,
            )
        }
        fn api(&self, route: &str, value: Value) -> (u16, Value) {
            let body = value.to_string();
            let (status, response) = self.raw(&format!("POST /api/{route} HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", self.address, self.address, self.secret, body.len()));
            (
                status,
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap(),
            )
        }
    }
    impl Drop for Ui {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn real_http_refuses_authority_csrf_and_frame_errors_before_broker() {
        let broker = Broker::new();
        let ui = broker.start_ui("state");
        let correct = format!(
            "Host: {}\r\nOrigin: http://{}\r\nAuthorization: Bearer {}\r\n",
            ui.address, ui.address, ui.secret
        );
        for headers in [
            correct.replace(&format!("Host: {}", ui.address), "Host: attacker.invalid"),
            correct.replace(&format!("Origin: http://{}\r\n", ui.address), ""),
            correct.replace(
                &format!("Origin: http://{}", ui.address),
                "Origin: http://attacker.invalid",
            ),
            correct.replace(&format!("Authorization: Bearer {}\r\n", ui.secret), ""),
            correct.replace(&ui.secret, "wrong"),
            format!("{correct}Sec-Fetch-Site: cross-site\r\n"),
        ] {
            assert_eq!(ui.raw(&format!("POST /api/list HTTP/1.1\r\n{headers}Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}")).0, 403);
        }
        for extra in [
            "Host: duplicate\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 2\r\n",
            " Bad: folded\r\n",
        ] {
            assert_eq!(ui.raw(&format!("POST /api/list HTTP/1.1\r\n{correct}{extra}Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}")).0, 400);
        }
        assert_eq!(ui.raw(&format!("POST /api/list HTTP/1.1\r\n{correct}Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}")).0, 415);
        assert_eq!(ui.raw(&format!("POST /api/list HTTP/1.1\r\n{correct}Content-Type: application/json\r\nContent-Length: 65537\r\n\r\n")).0, 400);
        assert_eq!(ui.api("list", json!({"unknown":true})).0, 400);
        assert!(broker.state.lock().unwrap().requests.is_empty());
        let (status, response) = ui.raw(&format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", ui.address));
        assert_eq!(status, 200);
        assert!(response.contains("Referrer-Policy: no-referrer"));
        assert!(response.contains("frame-ancestors 'none'"));
        assert!(!response.contains("Access-Control-Allow-Origin"));
        assert!(!response.contains(&ui.secret));
    }

    #[test]
    fn manual_selection_is_durable_exact_and_never_discovers_another_account() {
        let broker = Broker::new();
        let ui = broker.start_ui("state");
        assert_eq!(
            ui.api("list", json!({})).1["selection"]["selected_alias"],
            Value::Null
        );
        assert_eq!(
            ui.api("discover", json!({"alias":"first","expected_revision":0}))
                .0,
            409
        );
        let selected = ui.api("select", json!({"alias":"second","expected_revision":0}));
        assert_eq!(selected.0, 200);
        assert_eq!(selected.1["selection"]["revision"], 1);
        assert_eq!(
            ui.api("discover", json!({"alias":"first","expected_revision":1}))
                .0,
            409
        );
        let observed = ui.api("discover", json!({"alias":"second","expected_revision":1}));
        assert_eq!(observed.0, 200);
        assert_eq!(observed.1["observation"]["account"]["alias"], "second");
        assert_eq!(observed.1["observation"]["quota"]["state"], "unknown");
        assert_eq!(
            ui.api("select", json!({"alias":"first","expected_revision":0}))
                .0,
            409
        );
        assert_eq!(
            ui.api("select", json!({"alias":"disabled","expected_revision":1}))
                .0,
            403
        );
        drop(ui);
        let reloaded = broker.start_ui("state");
        assert_eq!(
            reloaded.api("list", json!({})).1["selection"]["selected_alias"],
            "second"
        );
        let state_file = broker.temp.path().join("state/selection.json");
        assert_eq!(fs::metadata(&state_file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(state_file.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        let saved = fs::read_to_string(state_file).unwrap();
        assert!(!saved.contains("broker.sock"));
        assert!(!saved.contains("user_code"));
        assert!(!saved.contains("verification_url"));
        let state = broker.state.lock().unwrap();
        let discoveries: Vec<_> = state
            .requests
            .iter()
            .filter(|r| r["capability"] == "accounts.discover")
            .collect();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0]["arguments"]["alias"], "second");
        assert!(!state.requests.iter().any(|r| r["capability"]
            .as_str()
            .unwrap()
            .starts_with("accounts.login")));
    }

    #[test]
    fn concurrent_windows_compare_revisions_and_endpoint_or_symlink_reuse_fails_closed() {
        let broker = Broker::new();
        let first = broker.start_ui("state");
        let second = broker.start_ui("state");
        let outcomes = thread::scope(|scope| {
            let a = scope.spawn(|| {
                first
                    .api("select", json!({"alias":"first","expected_revision":0}))
                    .0
            });
            let b = scope.spawn(|| {
                second
                    .api("select", json!({"alias":"second","expected_revision":0}))
                    .0
            });
            vec![a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|status| **status == 200).count(), 1);
        assert_eq!(outcomes.iter().filter(|status| **status == 409).count(), 1);
        let mut other = broker.config.clone();
        other.socket = broker.temp.path().join("other.sock");
        assert!(matches!(
            ManagementServer::bind(
                AccountClient::new(other).unwrap(),
                &broker.temp.path().join("state"),
                "127.0.0.1:0".parse().unwrap()
            ),
            Err(AccountError::UnsafeState)
        ));
        symlink(
            broker.temp.path().join("state"),
            broker.temp.path().join("linked-state"),
        )
        .unwrap();
        assert!(matches!(
            ManagementServer::bind(
                broker.client(),
                &broker.temp.path().join("linked-state"),
                "127.0.0.1:0".parse().unwrap()
            ),
            Err(AccountError::UnsafeState)
        ));
        assert!(matches!(
            ManagementServer::bind(
                broker.client(),
                &broker.temp.path().join("unused"),
                "0.0.0.0:0".parse().unwrap()
            ),
            Err(AccountError::InvalidInput)
        ));
        assert!(!broker.temp.path().join("unused").exists());
    }

    #[test]
    fn explicit_login_idempotency_cancel_and_reload_never_select_or_replay_start() {
        let broker = Broker::new();
        let ui = broker.start_ui("state");
        let start = json!({"alias":"first","request_nonce":NONCE,"replace_handle":null});
        let pending = ui.api("login/start", start.clone());
        assert_eq!(pending.0, 200);
        assert_eq!(pending.1["status"], "pending");
        assert_eq!(
            ui.api("login/start", start).1["handle"],
            pending.1["handle"]
        );
        assert_eq!(broker.state.lock().unwrap().starts, 1);
        assert_eq!(
            ui.api("login/status", json!({"alias":"first","handle":NONCE}))
                .0,
            403
        );
        let cancelled = ui.api(
            "login/cancel",
            json!({"alias":"first","handle":pending.1["handle"]}),
        );
        assert_eq!(cancelled.1["status"], "cancelled");
        assert!(cancelled.1["user_code"].is_null());
        assert_eq!(
            ui.api(
                "login/cancel",
                json!({"alias":"first","handle":pending.1["handle"]})
            )
            .1["status"],
            "cancelled"
        );
        assert_eq!(
            ui.api(
                "login/start",
                json!({"alias":"first","request_nonce":HANDLE,"replace_handle":NONCE})
            )
            .0,
            403
        );
        let replacement = ui.api(
            "login/start",
            json!({"alias":"first","request_nonce":HANDLE,"replace_handle":pending.1["handle"]}),
        );
        assert_eq!(replacement.0, 200);
        assert_ne!(replacement.1["handle"], pending.1["handle"]);
        {
            let mut state = broker.state.lock().unwrap();
            state.attempts.get_mut("first").unwrap().result =
                login("first", replacement.1["handle"].as_str().unwrap(), "ready");
        }
        assert_eq!(
            ui.api("login/status", json!({"alias":"first"})).1["status"],
            "ready"
        );
        assert!(ui.api("list", json!({})).1["selection"]["selected_alias"].is_null());
        drop(ui);
        let reloaded = broker.start_ui("state");
        assert_eq!(
            reloaded.api("login/status", json!({"alias":"first"})).1["status"],
            "ready"
        );
        assert_eq!(broker.state.lock().unwrap().starts, 2);
        assert_eq!(
            reloaded
                .api("select", json!({"alias":"first","expected_revision":0}))
                .0,
            200
        );
        assert!(!broker
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| r["capability"] == "accounts.discover"));
        broker.state.lock().unwrap().attempts.clear(); // A daemon restart invalidates process-lifetime handles.
        assert_eq!(
            reloaded
                .api(
                    "login/status",
                    json!({"alias":"first","handle":replacement.1["handle"]})
                )
                .0,
            403
        );
        assert_eq!(broker.state.lock().unwrap().starts, 2);
    }

    #[test]
    fn login_client_binds_alias_and_handle_and_refuses_untrusted_projection() {
        let broker = Broker::new();
        let client = broker.client();
        broker.state.lock().unwrap().next_result = Some(login("second", HANDLE, "pending"));
        assert!(matches!(
            client.login_start("first", NONCE, None),
            Err(AccountError::Protocol)
        ));
        broker.state.lock().unwrap().next_result = Some(login("first", NONCE, "pending"));
        assert!(matches!(
            client.login_status("first", Some(HANDLE)),
            Err(AccountError::Protocol)
        ));
        assert!(matches!(
            client.login_start("../bad", NONCE, None),
            Err(AccountError::InvalidInput)
        ));
        let count = broker.state.lock().unwrap().requests.len();
        assert!(matches!(
            client.login_start("first", "not-uuid", None),
            Err(AccountError::InvalidInput)
        ));
        assert_eq!(broker.state.lock().unwrap().requests.len(), count);
        let ready: LoginObservation =
            serde_json::from_value(login("first", HANDLE, "ready")).unwrap();
        assert_eq!(ready.status, LoginStatus::Ready);
        ready.validate().unwrap();
    }
}
