//! Native Gemini login, independently implemented from Google's OAuth protocol.
//!
//! Protocol and compatibility facts are recorded in `docs/OAUTH_PROVENANCE.md`.
//! This module does not include the attributed implementation from the imported
//! CAM snapshot. Only explicit provisioning opens a browser; Gemini CLI owns
//! subsequent refresh. Account selection and account-registry recovery remain
//! the caller's responsibility.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::fsx;

// Public installed-application identifiers published by google-gemini/gemini-cli
// at 571851b1077a51cef757146ce13f9da887326bec. These are not user credentials.
const CLIENT_ID: &str = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "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";
const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const EMAIL_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const SCOPES: &str = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
const CALLBACK_PATH: &str = "/oauth2callback";
// CAM's existing callback frame admission bound, applied to OAuth HTTP payloads.
const FRAME_BYTES: usize = 8192;
// The pinned Gemini CLI's browser-login deadline; covers this complete operation.
const LOGIN_DEADLINE: Duration = Duration::from_secs(5 * 60);

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct GeminiOAuthCreds {
    access_token: String,
    refresh_token: String,
    expiry_date: i64,
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct Grant {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: String,
    id_token: Option<String>,
    scope: Option<String>,
}

struct BrowserSession {
    listener: TcpListener,
    redirect: Url,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
}

impl BrowserSession {
    async fn bind() -> Result<Self> {
        let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(_) => TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
                .await
                .map_err(|_| failure("loopback listener unavailable"))?,
        };
        let address = listener
            .local_addr()
            .map_err(|_| failure("loopback address unavailable"))?;
        let redirect = Url::parse(&format!("http://{address}{CALLBACK_PATH}"))
            .map_err(|_| failure("invalid loopback address"))?;
        Ok(Self {
            listener,
            redirect,
            state: random_text()?,
            verifier: random_text()?,
        })
    }

    fn authorization_url(&self) -> Result<Url> {
        let mut url =
            Url::parse(AUTH_ENDPOINT).map_err(|_| failure("invalid authorization endpoint"))?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", CLIENT_ID),
            ("redirect_uri", self.redirect.as_str()),
            ("response_type", "code"),
            ("scope", SCOPES),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("state", self.state.as_str()),
            ("code_challenge", pkce_challenge(&self.verifier).as_str()),
            ("code_challenge_method", "S256"),
        ]);
        Ok(url)
    }

    async fn callback(&self) -> Result<Zeroizing<String>> {
        let (mut stream, peer) = self
            .listener
            .accept()
            .await
            .map_err(|_| failure("callback connection failed"))?;
        if !peer.ip().is_loopback() {
            return Err(failure("callback peer is not loopback"));
        }
        let result = read_callback(&mut stream, &self.redirect, &self.state).await;
        let response = if result.is_ok() {
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\nAuthorization received. Return to Coding Agent Manager to check the result."
        } else {
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\nAuthorization was not accepted. Return to Coding Agent Manager."
        };
        // The browser response never includes codes, tokens, addresses or errors.
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
        result
    }
}

fn random_text() -> Result<Zeroizing<String>> {
    // RFC 7636 recommends a 32-octet random verifier (43 base64url characters).
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut()).map_err(|_| failure("secure randomness unavailable"))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_ref())))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn read_callback(
    stream: &mut TcpStream,
    redirect: &Url,
    expected_state: &str,
) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let count = stream
            .read(chunk.as_mut())
            .await
            .map_err(|_| failure("callback read failed"))?;
        if count == 0 || bytes.len().saturating_add(count) > FRAME_BYTES {
            return Err(failure("incomplete or oversized callback"));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 != bytes.len() {
                return Err(failure("callback body is not permitted"));
            }
            let request =
                std::str::from_utf8(&bytes).map_err(|_| failure("invalid callback encoding"))?;
            return parse_callback(request, redirect, expected_state);
        }
    }
}

fn parse_callback(
    request: &str,
    redirect: &Url,
    expected_state: &str,
) -> Result<Zeroizing<String>> {
    if request.len() > FRAME_BYTES || !request.ends_with("\r\n\r\n") {
        return Err(failure("invalid callback frame"));
    }
    let mut lines = request[..request.len() - 4].split("\r\n");
    let parts = lines
        .next()
        .unwrap_or_default()
        .split(' ')
        .collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" {
        return Err(failure("invalid callback request line"));
    }
    if parts[1]
        .bytes()
        .any(|byte| byte <= b' ' || !byte.is_ascii())
    {
        return Err(failure("invalid callback target encoding"));
    }
    let target = parts[1].as_bytes();
    for (index, byte) in target.iter().enumerate() {
        if *byte == b'%'
            && (target
                .get(index + 1)
                .is_none_or(|byte| !byte.is_ascii_hexdigit())
                || target
                    .get(index + 2)
                    .is_none_or(|byte| !byte.is_ascii_hexdigit()))
        {
            return Err(failure("invalid callback percent encoding"));
        }
    }
    let expected_host = &redirect.as_str()[url_authority_range(redirect)?];
    let mut host_seen = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| failure("invalid callback header"))?;
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
        {
            return Err(failure("invalid callback header name"));
        }
        if name.eq_ignore_ascii_case("host") {
            if host_seen || value.trim() != expected_host {
                return Err(failure("callback host mismatch"));
            }
            host_seen = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(failure("callback body is not permitted"));
        }
    }
    if !host_seen || !parts[1].starts_with(&format!("{CALLBACK_PATH}?")) || parts[1].contains('#') {
        return Err(failure("invalid callback target"));
    }
    let url = redirect
        .join(parts[1])
        .map_err(|_| failure("invalid callback query"))?;
    if url.path() != CALLBACK_PATH {
        return Err(failure("callback path mismatch"));
    }
    let mut state = None;
    let mut code = None;
    let mut denied = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "state" => &mut state,
            "code" => &mut code,
            "error" => &mut denied,
            _ => continue,
        };
        if slot.is_some() || value.is_empty() || value.chars().any(char::is_control) {
            return Err(failure("duplicate or empty callback parameter"));
        }
        *slot = Some(Zeroizing::new(value.into_owned()));
    }
    let state = state.ok_or_else(|| failure("callback state missing"))?;
    if !bool::from(state.as_bytes().ct_eq(expected_state.as_bytes())) {
        return Err(failure("callback state mismatch"));
    }
    match (code, denied) {
        (Some(code), None) => Ok(code),
        (None, Some(_)) => Err(failure("authorization denied")),
        _ => Err(failure("callback must contain one authorization outcome")),
    }
}

fn url_authority_range(url: &Url) -> Result<std::ops::Range<usize>> {
    let start = url
        .as_str()
        .find("://")
        .ok_or_else(|| failure("invalid callback URL"))?
        + 3;
    let end = url.as_str()[start..]
        .find('/')
        .map_or(url.as_str().len(), |at| start + at);
    Ok(start..end)
}

pub(crate) fn provision_managed_home(home: &Path) -> Result<()> {
    ensure_no_credential_marker(home)?;
    let directory = managed_directory(home)?;
    let previous = previous_document(&directory.join("settings.json"))?;
    settings_bytes(previous.as_ref().map(|value| value.as_slice()))?;
    previous_document(&directory.join("google_accounts.json"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| failure("login runtime unavailable"))?;
    runtime.block_on(async {
        tokio::time::timeout(LOGIN_DEADLINE, async {
            let session = BrowserSession::bind().await?;
            let (browser, _reaper) = open_browser(session.authorization_url()?.as_str())?;
            let code = code_with_browser(&session, browser).await?;
            let client = http_client()?;
            let creds = exchange(
                &client,
                TOKEN_ENDPOINT,
                &code,
                &session.redirect,
                &session.verifier,
            )
            .await?;
            let email = lookup_email(&client, EMAIL_ENDPOINT, &creds.access_token)
                .await
                .ok();
            write_oauth_documents(home, &creds, email.as_ref().map(|value| value.as_str()))
        })
        .await
        .map_err(|_| failure("login operation timed out"))?
    })
}

type BrowserExit = tokio::sync::oneshot::Receiver<io::Result<ExitStatus>>;

fn open_browser(url: &str) -> Result<(BrowserExit, std::thread::JoinHandle<()>)> {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32.exe");
        command.arg("url.dll,FileProtocolHandler");
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = Command::new("xdg-open");
    command.arg(url);
    handoff_browser(command)
}

fn handoff_browser(mut command: Command) -> Result<(BrowserExit, std::thread::JoinHandle<()>)> {
    // xdg-open may stay alive for the browser's lifetime (its documented EXIT
    // CODES contract). This is an explicit external-browser handoff, not an
    // owned agent execution: login cancellation must never kill that browser.
    // The reaper survives this async runtime and retains sole child ownership.
    let (child_tx, child_rx) = std::sync::mpsc::channel::<Child>();
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
    let reaper = std::thread::Builder::new()
        .name("oauth-browser-reaper".into())
        .spawn(move || {
            if let Ok(mut child) = child_rx.recv() {
                let _ = exit_tx.send(child.wait());
            }
        })
        .map_err(|_| failure("system browser reaper unavailable"))?;
    let child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            drop(child_tx);
            let _ = reaper.join();
            return Err(failure("system browser could not be opened"));
        }
    };
    child_tx
        .send(child)
        .map_err(|_| failure("system browser handoff failed"))?;
    Ok((exit_rx, reaper))
}

async fn code_with_browser(
    session: &BrowserSession,
    mut browser: BrowserExit,
) -> Result<Zeroizing<String>> {
    let callback = session.callback();
    tokio::pin!(callback);
    tokio::select! {
        result = &mut callback => result,
        exit = &mut browser => {
            match exit {
                Ok(Ok(status)) if status.success() => callback.await,
                _ => Err(failure("system browser refused the authorization URL")),
            }
        }
    }
}

fn http_client() -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(LOGIN_DEADLINE);
    #[cfg(test)]
    let builder = builder.no_proxy();
    builder
        .build()
        .map_err(|_| failure("OAuth HTTP client unavailable"))
}

async fn response_bytes(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>> {
    if !response.status().is_success() {
        return Err(failure("OAuth endpoint refused the request"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("OAuth response read failed"))?
    {
        if bytes.len().saturating_add(chunk.len()) > FRAME_BYTES {
            return Err(failure("OAuth response exceeds its admission bound"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

// The URLs are private implementation parameters for synthetic unit tests.
// Production calls above use constants; no endpoint is accepted through IPC.
async fn exchange(
    client: &reqwest::Client,
    endpoint: &str,
    code: &str,
    redirect: &Url,
    verifier: &str,
) -> Result<GeminiOAuthCreds> {
    let response = client
        .post(endpoint)
        .form(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|_| failure("token exchange failed; request was not retried"))?;
    let bytes = response_bytes(response).await?;
    let grant: Grant =
        serde_json::from_slice(&bytes).map_err(|_| failure("invalid token response"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failure("system clock is invalid"))?;
    let now_ms =
        i64::try_from(now.as_millis()).map_err(|_| failure("system clock is out of range"))?;
    let creds = GeminiOAuthCreds {
        access_token: grant.access_token.clone(),
        refresh_token: grant.refresh_token.clone(),
        expiry_date: expiry_date_ms(now_ms, grant.expires_in)?,
        token_type: grant.token_type.clone(),
        id_token: grant.id_token.clone(),
        scope: grant.scope.clone(),
    };
    validate_credentials(&creds)?;
    Ok(creds)
}

async fn lookup_email(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
) -> Result<Zeroizing<String>> {
    #[derive(Deserialize)]
    struct Identity {
        email: String,
    }
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| failure("account identity unavailable"))?;
    let bytes = response_bytes(response).await?;
    let identity: Identity =
        serde_json::from_slice(&bytes).map_err(|_| failure("invalid account identity response"))?;
    let email = Zeroizing::new(identity.email);
    if mask_email(&email).is_none() {
        return Err(failure("invalid account email"));
    }
    Ok(email)
}

fn validate_credentials(creds: &GeminiOAuthCreds) -> Result<()> {
    if creds.access_token.trim().is_empty()
        || creds.refresh_token.trim().is_empty()
        || creds.expiry_date <= 0
        || !creds.token_type.eq_ignore_ascii_case("Bearer")
        || [&creds.access_token, &creds.refresh_token]
            .into_iter()
            .any(|v| v.chars().any(char::is_control))
        || [creds.id_token.as_deref(), creds.scope.as_deref()]
            .into_iter()
            .flatten()
            .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
    {
        return Err(failure("incomplete or invalid OAuth credentials"));
    }
    Ok(())
}

pub(crate) fn expiry_date_ms(now_ms: i64, expires_in_secs: i64) -> Result<i64> {
    if now_ms < 0 || expires_in_secs <= 0 {
        return Err(failure("invalid token lifetime"));
    }
    expires_in_secs
        .checked_mul(1000)
        .and_then(|duration| now_ms.checked_add(duration))
        .ok_or_else(|| failure("token expiry is out of range"))
}

fn ensure_no_credential_marker(home: &Path) -> Result<()> {
    match fs::symlink_metadata(home.join(".gemini/oauth_creds.json")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(failure(
            "managed OAuth credentials already exist; use account recovery",
        )),
        Err(_) => Err(failure("managed OAuth credentials cannot be inspected")),
    }
}

fn managed_directory(home: &Path) -> Result<PathBuf> {
    if !home.is_absolute() {
        return Err(failure("managed home must be absolute"));
    }
    let directory = home.join(".gemini");
    for path in [home, directory.as_path()] {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(failure("managed home is not a regular directory"))
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure("managed home cannot be inspected")),
        }
    }
    fsx::create_dir_all_private(&directory)?;
    Ok(directory)
}

fn previous_document(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            Err(failure("managed OAuth document is not a regular file"))
        }
        Ok(_) => fs::read(path)
            .map(Zeroizing::new)
            .map(Some)
            .map_err(|_| failure("managed OAuth document cannot be read")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("managed OAuth document cannot be inspected")),
    }
}

fn settings_bytes(previous: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let mut root: Map<String, Value> = match previous {
        Some(bytes) => serde_json::from_slice(bytes)
            .map_err(|_| failure("managed settings must be a JSON object"))?,
        None => Map::new(),
    };
    let security = root
        .entry("security")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| failure("managed security settings must be an object"))?;
    let auth = security
        .entry("auth")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| failure("managed authentication settings must be an object"))?;
    auth.insert(
        "selectedType".to_string(),
        Value::String("oauth-personal".to_string()),
    );
    serde_json::to_vec_pretty(&root)
        .map(Zeroizing::new)
        .map_err(|_| failure("managed settings could not be encoded"))
}

pub(crate) fn write_managed_oauth_settings(home: &Path) -> Result<()> {
    let path = managed_directory(home)?.join("settings.json");
    let previous = previous_document(&path)?;
    let bytes = settings_bytes(previous.as_ref().map(|v| v.as_slice()))?;
    fsx::write_atomic(&path, &bytes)
}

pub(crate) fn write_oauth_documents(
    home: &Path,
    creds: &GeminiOAuthCreds,
    email: Option<&str>,
) -> Result<()> {
    write_documents(home, creds, email, &fsx::write_atomic)
}

fn write_documents(
    home: &Path,
    creds: &GeminiOAuthCreds,
    email: Option<&str>,
    write: &impl Fn(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    validate_credentials(creds)?;
    if email.is_some_and(|value| mask_email(value).is_none()) {
        return Err(failure("invalid account email"));
    }
    ensure_no_credential_marker(home)?;
    let directory = managed_directory(home)?;
    let settings = directory.join("settings.json");
    let accounts = directory.join("google_accounts.json");
    let before_settings = previous_document(&settings)?;
    let before_accounts = previous_document(&accounts)?;
    let settings_after = settings_bytes(before_settings.as_ref().map(|value| value.as_slice()))?;
    let accounts_after = Zeroizing::new(
        serde_json::to_vec_pretty(&serde_json::json!({"active": email, "old": []}))
            .map_err(|_| failure("account identity could not be encoded"))?,
    );
    let credentials_after = Zeroizing::new(
        serde_json::to_vec_pretty(creds)
            .map_err(|_| failure("OAuth credentials could not be encoded"))?,
    );
    let companions = [
        (&settings, before_settings.as_ref(), &settings_after),
        (&accounts, before_accounts.as_ref(), &accounts_after),
    ];
    for (index, (path, _, after)) in companions.iter().enumerate() {
        if write(path, after).is_err() {
            for (restore_path, before, _) in companions[..=index].iter().rev() {
                match before {
                    Some(bytes) => fsx::write_atomic(restore_path, bytes)?,
                    None => match fs::remove_file(restore_path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => {
                            return Err(failure("OAuth companion rollback requires recovery"))
                        }
                    },
                }
            }
            return Err(failure(
                "OAuth companion write failed; previous documents restored",
            ));
        }
    }
    // Existing registry recovery recognizes oauth_creds.json. Commit that marker
    // only after BOTH companion files are valid and durably written. If its
    // rename succeeds but directory fsync fails, retain the valid companions:
    // recovery can safely validate the marker without repeating token exchange.
    write(&directory.join("oauth_creds.json"), &credentials_after)
}

pub(crate) fn expiry_rfc3339_from_oauth_creds(path: &Path) -> Option<String> {
    #[derive(Deserialize)]
    struct Expiry {
        expiry_date: i64,
    }
    let bytes = previous_document(path).ok()??;
    let expiry: Expiry = serde_json::from_slice(&bytes).ok()?;
    let time =
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(expiry.expiry_date) * 1_000_000)
            .ok()?;
    time.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

pub(crate) fn mask_email(email: &str) -> Option<String> {
    let (user, domain) = email.split_once('@')?;
    if user.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || email.chars().any(char::is_control)
    {
        return None;
    }
    let initial = user.chars().next()?;
    let masked = format!("{initial}***@{domain}");
    (masked != email).then_some(masked)
}

#[cfg(test)]
pub(crate) fn write_fake_oauth_home(home: &Path, email: Option<&str>) -> Result<()> {
    write_oauth_documents(
        home,
        &GeminiOAuthCreds {
            access_token: "FAKE-gemini-access".to_string(),
            refresh_token: "FAKE-gemini-refresh".to_string(),
            expiry_date: 1_700_000_000_000,
            token_type: "Bearer".to_string(),
            id_token: None,
            scope: None,
        },
        email,
    )
}

fn failure(reason: &'static str) -> Error {
    Error::ConfigWrite {
        provider: "gemini-cli".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests;
