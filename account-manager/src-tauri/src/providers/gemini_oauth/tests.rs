use super::*;
use std::collections::BTreeMap;

fn credentials() -> GeminiOAuthCreds {
    GeminiOAuthCreds {
        access_token: "FAKE-access-0001".into(),
        refresh_token: "FAKE-refresh-0001".into(),
        expiry_date: 1_700_000_000_000,
        token_type: "Bearer".into(),
        id_token: None,
        scope: None,
    }
}

fn redirect() -> Url {
    Url::parse("http://127.0.0.1:12345/oauth2callback").expect("fixture redirect")
}

fn request(query: &str) -> String {
    format!("GET /oauth2callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n")
}

fn assert_sanitized(error: Error) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    let json = serde_json::to_string(&error).expect("error serialization");
    for value in [display, debug, json] {
        assert!(
            !value.contains("FAKE-"),
            "synthetic credential escaped error"
        );
    }
}

#[test]
fn pkce_matches_rfc7636_s256_vector() {
    // RFC 7636 Appendix B's published interoperability vector.
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[tokio::test]
async fn authorization_is_bound_to_the_listener_and_fresh_pkce_state() {
    let first = BrowserSession::bind().await.expect("first session");
    let second = BrowserSession::bind().await.expect("second session");
    assert_ne!(*first.state, *second.state);
    assert_ne!(*first.verifier, *second.verifier);
    assert_eq!(first.state.len(), 43);
    assert_eq!(first.verifier.len(), 43);
    let url = first.authorization_url().expect("authorization URL");
    let fields: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://accounts.google.com"
    );
    assert_eq!(fields["redirect_uri"], first.redirect.as_str());
    assert_eq!(fields["state"], *first.state);
    assert_eq!(fields["code_challenge"], pkce_challenge(&first.verifier));
    assert_eq!(fields["code_challenge_method"], "S256");
    assert_eq!(fields["scope"], SCOPES);
    assert_eq!(fields["access_type"], "offline");
    assert_eq!(fields["response_type"], "code");
}

#[test]
fn callback_requires_one_state_bound_outcome_and_exact_http_target() {
    let good = request("state=FAKE-state&code=FAKE-code%2Bwith%2Fencoding");
    assert_eq!(
        *parse_callback(&good, &redirect(), "FAKE-state").expect("valid callback"),
        "FAKE-code+with/encoding"
    );
    for bad in [
        request("state=FAKE-wrong&code=FAKE-code"),
        request("state=FAKE-state&state=FAKE-state&code=FAKE-code"),
        request("state=FAKE-state&code=FAKE-one&code=FAKE-two"),
        request("state=FAKE-state&error=FAKE-denied&code=FAKE-code"),
        request("state=FAKE-state&error=FAKE-denied"),
        request("code=FAKE-code"),
        request("state=FAKE-state&code="),
        request("state=FAKE-state&code=FAKE-code%0A"),
        request("state=FAKE-state&code=FAKE-code%GG"),
        good.replacen("GET ", "POST ", 1),
        good.replace("/oauth2callback?", "/other?"),
        good.replace("/oauth2callback?", "http://example.invalid/oauth2callback?"),
        good.replace("Host: 127.0.0.1:12345", "Host: example.invalid"),
        good.replace(
            "Host: 127.0.0.1:12345",
            "Host: 127.0.0.1:12345\r\nHost: 127.0.0.1:12345",
        ),
        good.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n"),
        good.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
    ] {
        assert_sanitized(
            parse_callback(&bad, &redirect(), "FAKE-state").expect_err("refused callback"),
        );
    }
}

#[tokio::test]
async fn callback_reads_a_split_frame_on_the_real_loopback_socket() {
    let session = BrowserSession::bind().await.expect("session");
    let address = session.listener.local_addr().expect("address");
    let raw = format!(
        "GET /oauth2callback?state={}&code=FAKE-callback HTTP/1.1\r\nHost: {address}\r\n\r\n",
        session.state.as_str()
    );
    let callback = tokio::spawn(async move { session.callback().await });
    let mut client = TcpStream::connect(address).await.expect("connect");
    for part in raw.as_bytes().chunks(3) {
        client.write_all(part).await.expect("request fragment");
    }
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("response");
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.contains("FAKE-"));
    assert_eq!(
        *callback.await.expect("join").expect("code"),
        "FAKE-callback"
    );
}

#[tokio::test]
async fn callback_refuses_an_oversized_frame_without_returning_its_contents() {
    let session = BrowserSession::bind().await.expect("session");
    let address = session.listener.local_addr().expect("address");
    let callback = tokio::spawn(async move { session.callback().await });
    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(&vec![b'x'; FRAME_BYTES + 1])
        .await
        .expect("oversized request");
    assert_sanitized(
        callback
            .await
            .expect("join")
            .expect_err("oversized refusal"),
    );
}

// Each long-lived synthetic browser has a release channel and its actual
// reaper handle. Drop releases and joins it even during assertion unwinding.
struct OpenerFixture {
    control: Option<std::net::TcpStream>,
    reaper: Option<std::thread::JoinHandle<()>>,
}

impl Drop for OpenerFixture {
    fn drop(&mut self) {
        use std::io::Write;
        if let Some(mut control) = self.control.take() {
            let _ = control.write_all(b"x");
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
    }
}

fn opener_fixture(session: &BrowserSession, mode: &str) -> (BrowserExit, OpenerFixture) {
    let control =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("control listener");
    let mut command = Command::new(std::env::current_exe().expect("libtest executable"));
    command
        .args([
            "--exact",
            "providers::gemini_oauth::tests::synthetic_browser_process",
            "--nocapture",
        ])
        .env("CAM_TEST_OAUTH_OPENER", mode)
        .env(
            "CAM_TEST_OAUTH_CONTROL",
            control.local_addr().expect("control address").to_string(),
        )
        .env(
            "CAM_TEST_OAUTH_CALLBACK",
            session
                .listener
                .local_addr()
                .expect("callback address")
                .to_string(),
        )
        .env("CAM_TEST_OAUTH_STATE", session.state.as_str());
    let (exit, reaper) = handoff_browser(command).expect("synthetic browser handoff");
    let mut fixture = OpenerFixture {
        control: None,
        reaper: Some(reaper),
    };
    if mode != "fail" {
        fixture.control = Some(control.accept().expect("browser control").0);
    }
    (exit, fixture)
}

#[test]
fn synthetic_browser_process() {
    use std::io::{Read, Write};
    let Ok(mode) = std::env::var("CAM_TEST_OAUTH_OPENER") else {
        return;
    };
    if mode == "fail" {
        std::process::exit(1);
    }
    let mut control = std::net::TcpStream::connect(
        std::env::var("CAM_TEST_OAUTH_CONTROL").expect("control address"),
    )
    .expect("control connect");
    if mode == "callback" {
        let address = std::env::var("CAM_TEST_OAUTH_CALLBACK").expect("callback address");
        let state = std::env::var("CAM_TEST_OAUTH_STATE").expect("callback state");
        let mut callback = std::net::TcpStream::connect(&address).expect("callback connect");
        write!(callback, "GET /oauth2callback?state={state}&code=FAKE-opened HTTP/1.1\r\nHost: {address}\r\n\r\n").expect("callback write");
    }
    let mut byte = [0];
    while control.read_exact(&mut byte).is_ok() && byte[0] != b'x' {
        control.write_all(&byte).expect("browser still alive");
    }
}

#[tokio::test]
async fn callback_completes_while_external_opener_remains_alive() {
    use std::io::{Read, Write};
    let session = BrowserSession::bind().await.expect("session");
    let (exit, mut fixture) = opener_fixture(&session, "callback");
    let code = code_with_browser(&session, exit)
        .await
        .expect("callback before browser exit");
    assert_eq!(*code, "FAKE-opened");
    let control = fixture.control.as_mut().expect("control");
    control.write_all(b"p").expect("ping still-running opener");
    let mut response = [0];
    control
        .read_exact(&mut response)
        .expect("opener survived callback");
    assert_eq!(response, *b"p");
}

#[tokio::test]
async fn cancellation_leaves_external_browser_alive_and_fixture_reaps_it() {
    use std::io::{Read, Write};
    let session = BrowserSession::bind().await.expect("session");
    let (exit, mut fixture) = opener_fixture(&session, "wait");
    let login = tokio::spawn(async move { code_with_browser(&session, exit).await });
    tokio::task::yield_now().await;
    login.abort();
    assert!(login.await.expect_err("cancelled login").is_cancelled());
    let control = fixture.control.as_mut().expect("control");
    control.write_all(b"p").expect("ping after cancellation");
    let mut response = [0];
    control
        .read_exact(&mut response)
        .expect("browser survives cancellation");
    assert_eq!(response, *b"p");
}

#[tokio::test]
async fn early_opener_failure_refuses_without_waiting_for_a_callback() {
    let session = BrowserSession::bind().await.expect("session");
    let (exit, _fixture) = opener_fixture(&session, "fail");
    assert_sanitized(
        code_with_browser(&session, exit)
            .await
            .expect_err("early launch refusal"),
    );
}

async fn fake_endpoint(
    status: &str,
    headers: &str,
    body: &str,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fake endpoint");
    let url = format!(
        "http://{}/token",
        listener.local_addr().expect("endpoint address")
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("token request");
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.expect("request read");
            assert_ne!(n, 0, "request ended early");
            bytes.extend_from_slice(&chunk[..n]);
            assert!(bytes.len() <= FRAME_BYTES);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..end]).expect("HTTP request headers");
                let len = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("body length"))
                    })
                    .unwrap_or(0);
                if bytes.len() == end + 4 + len {
                    break;
                }
            }
        }
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response write");
        stream.shutdown().await.expect("response close");
        String::from_utf8(bytes).expect("synthetic request")
    });
    (url, task)
}

#[tokio::test]
async fn token_exchange_binds_code_redirect_client_and_pkce_verifier() {
    let (endpoint, request) = fake_endpoint("200 OK", "Content-Type: application/json\r\n", r#"{"access_token":"FAKE-access","refresh_token":"FAKE-refresh","expires_in":3600,"token_type":"Bearer"}"#).await;
    let creds = exchange(
        &http_client().expect("client"),
        &endpoint,
        "FAKE-code",
        &redirect(),
        "FAKE-verifier",
    )
    .await
    .expect("exchange");
    assert_eq!(creds.access_token, "FAKE-access");
    assert_eq!(creds.refresh_token, "FAKE-refresh");
    let raw = request.await.expect("request task");
    assert!(raw.starts_with("POST /token HTTP/1.1"));
    let body = raw.split_once("\r\n\r\n").expect("request body").1;
    let form = Url::parse(&format!("http://example.invalid/?{body}")).expect("form");
    let fields: BTreeMap<_, _> = form.query_pairs().into_owned().collect();
    assert_eq!(fields.len(), 6);
    assert_eq!(fields["grant_type"], "authorization_code");
    assert_eq!(fields["code"], "FAKE-code");
    assert_eq!(fields["redirect_uri"], redirect().as_str());
    assert_eq!(fields["code_verifier"], "FAKE-verifier");
    assert_eq!(fields["client_id"], CLIENT_ID);
    assert_eq!(fields["client_secret"], CLIENT_SECRET);
}

#[tokio::test]
async fn token_exchange_refuses_redirects_and_malformed_or_incomplete_grants() {
    let trap =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("redirect trap");
    trap.set_nonblocking(true).expect("nonblocking trap");
    let headers = format!(
        "Location: http://{}/FAKE-redirect\r\n",
        trap.local_addr().expect("trap address")
    );
    let (endpoint, request) = fake_endpoint("302 Found", &headers, "FAKE-redirect-body").await;
    assert_sanitized(
        exchange(
            &http_client().expect("client"),
            &endpoint,
            "FAKE-code",
            &redirect(),
            "FAKE-verifier",
        )
        .await
        .err()
        .expect("redirect refused"),
    );
    request.await.expect("redirect request");
    assert_eq!(
        trap.accept().expect_err("redirect must not connect").kind(),
        io::ErrorKind::WouldBlock
    );
    for body in [
        "FAKE-invalid-json".to_string(),
        r#"{"access_token":"FAKE-access","expires_in":3600,"token_type":"Bearer"}"#.into(),
        r#"{"access_token":"FAKE-access","refresh_token":"FAKE-refresh","expires_in":-1,"token_type":"Bearer"}"#.into(),
        r#"{"access_token":"FAKE-access","refresh_token":"FAKE-refresh","expires_in":3600,"token_type":"Basic"}"#.into(),
        "x".repeat(FRAME_BYTES + 1),
    ] {
        let (endpoint, request) = fake_endpoint("200 OK", "", &body).await;
        assert_sanitized(exchange(&http_client().expect("client"), &endpoint, "FAKE-code", &redirect(), "FAKE-verifier").await.err().expect("invalid response refused"));
        request.await.expect("invalid-response request");
    }
}

#[tokio::test]
async fn lost_token_response_does_not_replay_the_authorization_code() {
    // The endpoint receives the request but closes without a response. Keeping
    // its listening socket alive lets a forbidden retry connect and fail this
    // assertion, rather than confusing a connection refusal with no replay.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("endpoint");
    let endpoint = format!("http://{}/token", listener.local_addr().expect("address"));
    let client = http_client().expect("client");
    let call = tokio::spawn(async move {
        exchange(
            &client,
            &endpoint,
            "FAKE-code",
            &redirect(),
            "FAKE-verifier",
        )
        .await
    });
    let (mut stream, _) = listener.accept().await.expect("first request");
    let mut bytes = [0u8; FRAME_BYTES];
    assert_ne!(stream.read(&mut bytes).await.expect("request bytes"), 0);
    drop(stream);
    tokio::select! {
        outcome = call => assert_sanitized(outcome.expect("exchange task").err().expect("lost response refused")),
        retry = listener.accept() => panic!("token exchange was replayed: {}", retry.is_ok()),
    }
}

#[test]
fn credentials_are_committed_after_valid_companions_with_private_permissions() {
    let dir = tempfile::tempdir().expect("isolated home");
    let home = dir.path().join("account");
    let seen = std::cell::Cell::new(false);
    write_documents(
        &home,
        &credentials(),
        Some("FAKE-user@example.invalid"),
        &|path, bytes| {
            if path
                .file_name()
                .is_some_and(|name| name == "oauth_creds.json")
            {
                let settings: Value =
                    serde_json::from_slice(&fs::read(home.join(".gemini/settings.json"))?)
                        .expect("settings JSON");
                assert_eq!(
                    settings["security"]["auth"]["selectedType"],
                    "oauth-personal"
                );
                let accounts: Value =
                    serde_json::from_slice(&fs::read(home.join(".gemini/google_accounts.json"))?)
                        .expect("accounts JSON");
                assert_eq!(accounts["active"], "FAKE-user@example.invalid");
                assert_eq!(accounts["old"], serde_json::json!([]));
                seen.set(true);
            }
            fsx::write_atomic(path, bytes)
        },
    )
    .expect("write complete account");
    assert!(seen.get());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["oauth_creds.json", "settings.json", "google_accounts.json"] {
            assert_eq!(
                fs::metadata(home.join(".gemini").join(name))
                    .expect("file")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    assert_eq!(
        expiry_rfc3339_from_oauth_creds(&home.join(".gemini/oauth_creds.json")).as_deref(),
        Some("2023-11-14T22:13:20Z")
    );
    assert_sanitized(
        write_fake_oauth_home(&home, None)
            .expect_err("existing credential marker refuses overwrite"),
    );
}

#[test]
fn companion_failure_restores_settings_and_never_creates_a_credential_marker() {
    let dir = tempfile::tempdir().expect("isolated home");
    let home = dir.path();
    fsx::create_dir_all_private(&home.join(".gemini")).expect("settings directory");
    let settings = home.join(".gemini/settings.json");
    let original = br#"{"ui":{"theme":"retained"},"security":{"auth":{"useExternal":false}}}"#;
    fs::write(&settings, original).expect("prior settings");
    let result = write_documents(home, &credentials(), None, &|path, bytes| {
        if path
            .file_name()
            .is_some_and(|name| name == "google_accounts.json")
        {
            return Err(failure("injected companion failure"));
        }
        fsx::write_atomic(path, bytes)
    });
    assert_sanitized(result.expect_err("injected failure"));
    assert_eq!(fs::read(settings).expect("restored settings"), original);
    assert!(!home.join(".gemini/oauth_creds.json").exists());
    assert!(!home.join(".gemini/google_accounts.json").exists());
}

#[test]
fn failure_after_credential_rename_retains_complete_recoverable_configuration() {
    let dir = tempfile::tempdir().expect("isolated home");
    let result = write_documents(dir.path(), &credentials(), None, &|path, bytes| {
        fsx::write_atomic(path, bytes)?;
        if path
            .file_name()
            .is_some_and(|name| name == "oauth_creds.json")
        {
            return Err(failure("injected post-rename sync failure"));
        }
        Ok(())
    });
    assert_sanitized(result.expect_err("post-rename failure"));
    for name in ["oauth_creds.json", "settings.json", "google_accounts.json"] {
        let _: Value = serde_json::from_slice(
            &fs::read(dir.path().join(".gemini").join(name)).expect("complete document"),
        )
        .expect("valid JSON");
    }
    write_managed_oauth_settings(dir.path())
        .expect("existing registry recovery repairs settings without OAuth");
    assert_sanitized(
        provision_managed_home(dir.path())
            .expect_err("existing marker prevents another browser/token request"),
    );
}

#[test]
fn malformed_settings_and_invalid_credentials_fail_before_any_document_write() {
    let dir = tempfile::tempdir().expect("isolated home");
    fsx::create_dir_all_private(&dir.path().join(".gemini")).expect("directory");
    let settings = dir.path().join(".gemini/settings.json");
    fs::write(&settings, br#"{"security":"FAKE-invalid"}"#).expect("malformed settings");
    let before = fs::read(&settings).expect("before");
    assert_sanitized(
        write_oauth_documents(dir.path(), &credentials(), None)
            .expect_err("malformed settings refused"),
    );
    assert_eq!(fs::read(settings).expect("after"), before);
    assert!(!dir.path().join(".gemini/oauth_creds.json").exists());
    let mut invalid = credentials();
    invalid.refresh_token.clear();
    assert_sanitized(
        write_oauth_documents(dir.path(), &invalid, None).expect_err("missing refresh refused"),
    );
}

#[test]
fn settings_preserve_siblings_and_expiry_and_identity_helpers_fail_closed() {
    let dir = tempfile::tempdir().expect("isolated home");
    fsx::create_dir_all_private(&dir.path().join(".gemini")).expect("directory");
    let settings = dir.path().join(".gemini/settings.json");
    fs::write(
        &settings,
        br#"{"ui":{"theme":"retained"},"security":{"auth":{"useExternal":false}}}"#,
    )
    .expect("settings");
    write_managed_oauth_settings(dir.path()).expect("overlay");
    let result: Value =
        serde_json::from_slice(&fs::read(settings).expect("settings")).expect("JSON");
    assert_eq!(result["ui"]["theme"], "retained");
    assert_eq!(result["security"]["auth"]["useExternal"], false);
    assert_eq!(result["security"]["auth"]["selectedType"], "oauth-personal");
    assert!(expiry_date_ms(i64::MAX, 1).is_err());
    assert!(expiry_date_ms(0, -1).is_err());
    assert_eq!(expiry_date_ms(1000, 2).expect("milliseconds"), 3000);
    assert_eq!(
        mask_email("FAKE-user@example.invalid").as_deref(),
        Some("F***@example.invalid")
    );
    assert!(mask_email("FAKE-invalid").is_none());
}
