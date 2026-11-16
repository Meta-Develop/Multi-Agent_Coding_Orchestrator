//! Persists ChatGPT tokens that a staged Codex home rotated back to the
//! canonical source `auth.json` (#1021). Every Codex supervisor invocation
//! receives a private copy of the source auth file in a parent-owned staged
//! `CODEX_HOME`, and a token refresh rewrites only that copy before the
//! staged home is deleted, which would leave the source with a stale refresh
//! token. The write-back here copies rotated tokens back to the source once
//! the last invocation using that source in this process has finished.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{anyhow, Context, Result};

use super::MAX_PROMPT_BYTES;

/// Outcome of copying rotated staged Codex auth bytes back to the source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CodexAuthWriteBack {
    /// The launch bytes carry no ChatGPT account, so no write-back applies.
    NotApplicable,
    /// The staged bytes equal the bytes that were staged at launch.
    Unchanged,
    /// The source changed since launch, so it was left untouched.
    SourceChanged,
    /// The rotated bytes were persisted to the source.
    Persisted,
}

/// Reads the staged `auth.json` of a staged Codex home, bounded and without
/// following symlinks. Returns `Ok(None)` when the file does not exist.
pub(super) fn capture_staged_codex_auth(staged_home: &Path) -> Result<Option<Vec<u8>>> {
    let path = staged_home.join("auth.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(anyhow!("staged codex auth file is not a regular file"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("staged codex auth file inspection failed");
        }
    }
    read_bounded_no_follow(&path)
        .map(Some)
        .context("staged codex auth file read failed")
}

/// Reads a regular file with `O_NOFOLLOW | O_CLOEXEC`, refusing reads beyond
/// `MAX_PROMPT_BYTES`.
fn read_bounded_no_follow(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let metadata = fs::symlink_metadata(path).context("codex auth file inspection failed")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(anyhow!("codex auth file is not a regular file"));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).context("codex auth file open failed")?;
    if !file
        .metadata()
        .context("codex auth file metadata check failed")?
        .is_file()
    {
        return Err(anyhow!("codex auth file is not a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_PROMPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("codex auth file read failed")?;
    if bytes.len() > MAX_PROMPT_BYTES {
        return Err(anyhow!("codex auth file exceeds the bounded size"));
    }
    Ok(bytes)
}

/// Returns the ChatGPT account id of auth bytes, or `None` when the bytes are
/// not a JSON object with a `tokens` object whose `refresh_token` and
/// `account_id` are both non-empty strings.
fn chatgpt_account(bytes: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let tokens = value.get("tokens")?.as_object()?;
    let account = tokens.get("account_id")?.as_str()?;
    let refresh = tokens.get("refresh_token")?.as_str()?;
    if account.is_empty() || refresh.is_empty() {
        return None;
    }
    Some(account.to_string())
}

/// A ChatGPT access token that expires within this margin is refreshed before a
/// launch while no other launch of its source runs (#1039).
pub(super) const CODEX_AUTH_PROACTIVE_REFRESH_MARGIN: Duration =
    Duration::from_secs(3 * 24 * 60 * 60);

/// Decodes unpadded base64url (RFC 4648 section 5); `None` on any other byte.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut decoded = Vec::with_capacity(text.len() * 3 / 4);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            decoded.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(decoded)
}

/// Expiry of the ChatGPT access token in auth bytes: the `exp` claim (seconds
/// since the Unix epoch) of the unverified JWT payload of `tokens.access_token`
/// (#1039). `None` when the bytes carry no such claim.
pub(super) fn access_token_expiry(bytes: &[u8]) -> Option<SystemTime> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let token = value.get("tokens")?.get("access_token")?.as_str()?;
    let payload = token.split('.').nth(1)?;
    let decoded = decode_base64url(payload)?;
    let claims = serde_json::from_slice::<serde_json::Value>(&decoded).ok()?;
    let exp = claims.get("exp")?.as_u64()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp))
}

/// Whether auth bytes carry a ChatGPT account whose access token expires within
/// `margin` of `now` (#1039). Bytes without a readable expiry are never due.
pub(super) fn codex_auth_refresh_due(bytes: &[u8], now: SystemTime, margin: Duration) -> bool {
    if chatgpt_account(bytes).is_none() {
        return false;
    }
    match (access_token_expiry(bytes), now.checked_add(margin)) {
        (Some(expiry), Some(limit)) => expiry <= limit,
        _ => false,
    }
}

/// Returns the `auth_mode` JSON value of auth bytes, or `None` when the bytes
/// are not a JSON object or carry no `auth_mode` key.
fn auth_mode(bytes: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("auth_mode")
        .cloned()
}

/// Opens a directory read-only with `O_DIRECTORY | O_CLOEXEC` and takes an
/// exclusive `flock` on it. The lock ends when the returned handle is dropped.
fn lock_source_directory(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .context("codex auth source directory open failed")?;
    // SAFETY: flock operates on a live file descriptor owned by this handle.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("codex auth source directory lock failed");
    }
    Ok(directory)
}

/// Writes `staged` to a newly created temporary file and renames it onto the
/// source, removing only that temporary file if a later step fails.
fn write_temp_and_rename(temp: &Path, source: &Path, staged: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temp)
        .context("codex auth write-back temporary file creation failed")?;
    let write_result = (|| {
        file.write_all(staged)
            .and_then(|()| file.sync_all())
            .context("codex auth write-back temporary file write failed")?;
        fs::rename(temp, source).context("codex auth write-back rename failed")?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(temp);
    }
    write_result
}

/// Copies rotated staged Codex auth bytes back to the source auth file under an
/// exclusive lock on the source's parent directory.
pub(super) fn write_back_rotated_codex_auth(
    source: &Path,
    launch: &[u8],
    staged: &[u8],
) -> Result<CodexAuthWriteBack> {
    if staged == launch {
        return Ok(CodexAuthWriteBack::Unchanged);
    }
    let Some(launch_account) = chatgpt_account(launch) else {
        return Ok(CodexAuthWriteBack::NotApplicable);
    };
    if chatgpt_account(staged).as_deref() != Some(launch_account.as_str()) {
        return Err(anyhow!("staged codex auth account check failed"));
    }
    if auth_mode(staged) != auth_mode(launch) {
        return Err(anyhow!("staged codex auth mode check failed"));
    }
    let parent = source
        .parent()
        .ok_or_else(|| anyhow!("codex auth source has no parent directory"))?;
    let directory = lock_source_directory(parent)?;
    let current = read_bounded_no_follow(source).context("codex auth source read failed")?;
    if current != launch {
        return Ok(CodexAuthWriteBack::SourceChanged);
    }
    let temp = parent.join(format!(".auth.json.maco-writeback-{}", std::process::id()));
    write_temp_and_rename(&temp, source, staged)?;
    directory
        .sync_all()
        .context("codex auth source directory sync failed")?;
    Ok(CodexAuthWriteBack::Persisted)
}

/// Per-source lease state of the process-global registry.
#[derive(Default)]
struct CodexAuthLeaseEntry {
    /// Number of entered and not yet left leases for that source.
    active: usize,
    /// Pending `(launch bytes, staged bytes)` pair of a finished lease.
    pending: Option<(Vec<u8>, Vec<u8>)>,
    /// Whether a proactive refresh of that source is in progress (#1039).
    refreshing: bool,
}

/// Process-global registry of active Codex auth leases per source path.
static CODEX_AUTH_LEASES: Mutex<BTreeMap<PathBuf, CodexAuthLeaseEntry>> =
    Mutex::new(BTreeMap::new());

/// Signalled when a proactive refresh of a source ends (#1039).
static CODEX_AUTH_LEASES_CHANGED: Condvar = Condvar::new();

/// Locks the lease registry, recovering a poisoned lock.
fn lock_codex_auth_leases() -> MutexGuard<'static, BTreeMap<PathBuf, CodexAuthLeaseEntry>> {
    CODEX_AUTH_LEASES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Logs the outcome of a rotated Codex auth write-back.
fn log_write_back(outcome: Result<CodexAuthWriteBack>) {
    match outcome {
        Ok(CodexAuthWriteBack::Persisted) => tracing::info!(
            actor = "maco-external-agent",
            operation = "persist_rotated_codex_auth",
            "persisted rotated codex auth"
        ),
        Ok(CodexAuthWriteBack::SourceChanged) => tracing::warn!(
            actor = "maco-external-agent",
            operation = "persist_rotated_codex_auth",
            "codex auth source changed since launch"
        ),
        Ok(CodexAuthWriteBack::Unchanged) | Ok(CodexAuthWriteBack::NotApplicable) => {}
        Err(error) => tracing::warn!(
            actor = "maco-external-agent",
            operation = "persist_rotated_codex_auth",
            error = %format!("{error:#}"),
            "persisting rotated codex auth failed"
        ),
    }
}

/// A lease that delays the write-back of rotated Codex auth bytes until the
/// last invocation using the same source in this process has finished.
pub(super) struct CodexAuthLease {
    source: PathBuf,
    launch: Vec<u8>,
    staged_home: Option<PathBuf>,
    finished: bool,
}

impl CodexAuthLease {
    /// Enters a lease for `source`, which was staged from `launch` bytes.
    #[cfg(test)]
    pub(super) fn enter(source: &Path, launch: &[u8], staged_home: Option<&Path>) -> Self {
        let mut leases = lock_codex_auth_leases();
        Self::enter_locked(&mut leases, source, launch, staged_home)
    }

    /// Enters a lease for `source` and reports whether this launch claims the
    /// proactive refresh of its ChatGPT token (#1039): the launch bytes are due
    /// within the margin, the launch has a staged Codex home to refresh in, and no
    /// other lease, refresh or pending write-back of that source exists. The
    /// claiming launch refreshes in its staged home; overlapping launches keep
    /// their still-valid access tokens, and the last lease writes the rotated
    /// bytes back as usual.
    pub(super) fn enter_claiming_refresh(
        source: &Path,
        launch: &[u8],
        staged_home: Option<&Path>,
        now: SystemTime,
    ) -> (Self, bool) {
        let mut leases = lock_codex_auth_leases();
        let busy = leases
            .get(source)
            .is_some_and(|entry| entry.active > 0 || entry.refreshing || entry.pending.is_some());
        let claim = staged_home.is_some()
            && !busy
            && codex_auth_refresh_due(launch, now, CODEX_AUTH_PROACTIVE_REFRESH_MARGIN);
        (
            Self::enter_locked(&mut leases, source, launch, staged_home),
            claim,
        )
    }

    /// Enters a lease for `source` unless a proactive refresh of that source is
    /// in progress (#1039). While one is, waits until it ends and returns
    /// `Ok(None)`, so the caller reloads the source bytes and enters again; fails
    /// when `deadline` passes first.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn enter_unless_refreshing(
        source: &Path,
        launch: &[u8],
        staged_home: Option<&Path>,
        deadline: Instant,
    ) -> Result<Option<Self>> {
        let mut leases = lock_codex_auth_leases();
        if !leases.get(source).is_some_and(|entry| entry.refreshing) {
            return Ok(Some(Self::enter_locked(
                &mut leases,
                source,
                launch,
                staged_home,
            )));
        }
        while leases.get(source).is_some_and(|entry| entry.refreshing) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "timed out waiting for a proactive codex auth refresh of the same source"
                ));
            }
            leases = CODEX_AUTH_LEASES_CHANGED
                .wait_timeout(leases, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        Ok(None)
    }

    fn enter_locked(
        leases: &mut BTreeMap<PathBuf, CodexAuthLeaseEntry>,
        source: &Path,
        launch: &[u8],
        staged_home: Option<&Path>,
    ) -> Self {
        let entry = leases.entry(source.to_path_buf()).or_default();
        entry.active = entry.active.saturating_add(1);
        Self {
            source: source.to_path_buf(),
            launch: launch.to_vec(),
            staged_home: staged_home.map(Path::to_path_buf),
            finished: false,
        }
    }

    /// Leaves the lease with the captured staged auth bytes.
    pub(super) fn finish(mut self, staged: Result<Option<Vec<u8>>>) {
        self.finished = true;
        self.leave(staged);
    }

    /// Leaves the lease, storing a pending pair or writing back when this was
    /// the last lease of the source. Never panics.
    fn leave(&mut self, staged: Result<Option<Vec<u8>>>) {
        let mut leases = lock_codex_auth_leases();
        match staged {
            Ok(Some(staged)) if staged != self.launch => {
                let entry = leases.entry(self.source.clone()).or_default();
                entry.pending = Some((self.launch.clone(), staged));
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(
                actor = "maco-external-agent",
                operation = "persist_rotated_codex_auth",
                error = %format!("{error:#}"),
                "capture of staged codex auth failed"
            ),
        }
        let entry = leases.entry(self.source.clone()).or_default();
        entry.active = entry.active.saturating_sub(1);
        if entry.active == 0 {
            if let Some((launch, staged)) = leases.remove(&self.source).and_then(|e| e.pending) {
                log_write_back(write_back_rotated_codex_auth(
                    &self.source,
                    &launch,
                    &staged,
                ));
            }
        }
    }
}

impl Drop for CodexAuthLease {
    /// Leaves an unfinished lease exactly as `finish` would, capturing its
    /// staged home when one was given, so rotated tokens are not lost.
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let staged = match &self.staged_home {
            Some(home) => capture_staged_codex_auth(home),
            None => Ok(None),
        };
        self.leave(staged);
    }
}

/// Exclusive right to refresh the auth of one source while no lease of that
/// source is active (#1039). Dropping it ends the refresh and wakes the launches
/// that wait for it.
pub(super) struct CodexAuthRefreshGuard {
    source: PathBuf,
}

/// Begins a proactive refresh of `source` when no lease of that source is active
/// and no other refresh of it is in progress (#1039).
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn begin_codex_auth_refresh(source: &Path) -> Option<CodexAuthRefreshGuard> {
    let mut leases = lock_codex_auth_leases();
    let entry = leases.entry(source.to_path_buf()).or_default();
    if entry.active > 0 || entry.refreshing {
        return None;
    }
    entry.refreshing = true;
    Some(CodexAuthRefreshGuard {
        source: source.to_path_buf(),
    })
}

impl Drop for CodexAuthRefreshGuard {
    fn drop(&mut self) {
        let mut leases = lock_codex_auth_leases();
        if let Some(entry) = leases.get_mut(&self.source) {
            entry.refreshing = false;
            if entry.active == 0 && entry.pending.is_none() {
                leases.remove(&self.source);
            }
        }
        drop(leases);
        CODEX_AUTH_LEASES_CHANGED.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn auth_bytes(account: &str, refresh: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "account_id": account,
                "refresh_token": refresh,
                "access_token": format!("access-{refresh}"),
                "id_token": "id",
            },
            "last_refresh": "2026-11-01T00:00:00Z",
        }))
        .unwrap()
    }

    fn source_with_auth(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        (dir, path)
    }

    fn read_source(path: &Path) -> Vec<u8> {
        fs::read(path).unwrap()
    }

    #[test]
    fn rotated_tokens_replace_an_unchanged_source() {
        let launch = auth_bytes("acct-1", "old");
        let staged = auth_bytes("acct-1", "new");
        let (dir, source) = source_with_auth(&launch);
        let outcome = write_back_rotated_codex_auth(&source, &launch, &staged).unwrap();
        assert_eq!(outcome, CodexAuthWriteBack::Persisted);
        assert_eq!(read_source(&source), staged);
        let mode = fs::metadata(&source).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let mut entries: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["auth.json".to_string()]);
    }

    #[test]
    fn a_source_changed_since_launch_is_left_untouched() {
        let launch = auth_bytes("acct-1", "old");
        let other = auth_bytes("acct-1", "other");
        let (_dir, source) = source_with_auth(&other);
        let outcome =
            write_back_rotated_codex_auth(&source, &launch, &auth_bytes("acct-1", "new")).unwrap();
        assert_eq!(outcome, CodexAuthWriteBack::SourceChanged);
        assert_eq!(read_source(&source), other);
    }

    #[test]
    fn identical_or_api_key_auth_is_not_written() {
        let launch = auth_bytes("acct-1", "old");
        let (_dir, source) = source_with_auth(&launch);
        let outcome = write_back_rotated_codex_auth(&source, &launch, &launch).unwrap();
        assert_eq!(outcome, CodexAuthWriteBack::Unchanged);
        assert_eq!(read_source(&source), launch);
        let api_launch =
            serde_json::to_vec(&serde_json::json!({"OPENAI_API_KEY": "sk-test"})).unwrap();
        let api_staged =
            serde_json::to_vec(&serde_json::json!({"OPENAI_API_KEY": "sk-other"})).unwrap();
        let outcome = write_back_rotated_codex_auth(&source, &api_launch, &api_staged).unwrap();
        assert_eq!(outcome, CodexAuthWriteBack::NotApplicable);
        assert_eq!(read_source(&source), launch);
    }

    #[test]
    fn foreign_or_tokenless_staged_auth_is_refused() {
        let launch = auth_bytes("acct-1", "old");
        let (_dir, source) = source_with_auth(&launch);
        assert!(
            write_back_rotated_codex_auth(&source, &launch, &auth_bytes("acct-2", "new")).is_err()
        );
        let tokenless = serde_json::to_vec(&serde_json::json!({"auth_mode": "chatgpt"})).unwrap();
        assert!(write_back_rotated_codex_auth(&source, &launch, &tokenless).is_err());
        assert!(write_back_rotated_codex_auth(&source, &launch, b"not json").is_err());
        assert_eq!(read_source(&source), launch);
    }

    #[test]
    fn capture_reads_only_a_regular_staged_auth_file() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(capture_staged_codex_auth(home.path()).unwrap(), None);
        let bytes = auth_bytes("acct-1", "new");
        fs::write(home.path().join("auth.json"), &bytes).unwrap();
        assert_eq!(capture_staged_codex_auth(home.path()).unwrap(), Some(bytes));
        let target = tempfile::tempdir().unwrap();
        let target_file = target.path().join("auth.json");
        fs::write(&target_file, b"{}").unwrap();
        fs::remove_file(home.path().join("auth.json")).unwrap();
        std::os::unix::fs::symlink(&target_file, home.path().join("auth.json")).unwrap();
        assert!(capture_staged_codex_auth(home.path()).is_err());
    }

    fn jwt_auth_bytes(account: &str, payload: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "account_id": account,
                "refresh_token": "old",
                "access_token": format!("e30.{payload}.sig"),
                "id_token": "id",
            },
            "last_refresh": "2026-11-01T00:00:00Z",
        }))
        .unwrap()
    }

    fn epoch_plus(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn access_token_expiry_reads_the_jwt_exp_claim() {
        // {"exp":1700000000}, {"exp": 1700000000} (a partial last group) and {"exp":"soon"}.
        let exact = jwt_auth_bytes("acct-1", "eyJleHAiOjE3MDAwMDAwMDB9");
        let partial = jwt_auth_bytes("acct-1", "eyJleHAiOiAxNzAwMDAwMDAwfQ");
        let text = jwt_auth_bytes("acct-1", "eyJleHAiOiJzb29uIn0");
        assert_eq!(access_token_expiry(&exact), Some(epoch_plus(1_700_000_000)));
        assert_eq!(
            access_token_expiry(&partial),
            Some(epoch_plus(1_700_000_000))
        );
        assert_eq!(access_token_expiry(&text), None);
        assert_eq!(access_token_expiry(&jwt_auth_bytes("acct-1", "e30+")), None);
        assert_eq!(access_token_expiry(&auth_bytes("acct-1", "old")), None);
        assert_eq!(access_token_expiry(b"not json"), None);
    }

    #[test]
    fn a_refresh_is_due_only_within_the_margin() {
        let bytes = jwt_auth_bytes("acct-1", "eyJleHAiOjE3MDAwMDAwMDB9");
        let margin = CODEX_AUTH_PROACTIVE_REFRESH_MARGIN;
        let day = 24 * 60 * 60;
        assert!(codex_auth_refresh_due(
            &bytes,
            epoch_plus(1_700_000_000 - 2 * day),
            margin
        ));
        assert!(codex_auth_refresh_due(
            &bytes,
            epoch_plus(1_700_000_000 - 3 * day),
            margin
        ));
        assert!(!codex_auth_refresh_due(
            &bytes,
            epoch_plus(1_700_000_000 - 4 * day),
            margin
        ));
        assert!(codex_auth_refresh_due(
            &bytes,
            epoch_plus(1_700_000_000 + day),
            margin
        ));
        let api = serde_json::to_vec(&serde_json::json!({"OPENAI_API_KEY": "sk-test"})).unwrap();
        assert!(!codex_auth_refresh_due(
            &api,
            epoch_plus(1_700_000_000),
            margin
        ));
        let unreadable = auth_bytes("acct-1", "old");
        assert!(!codex_auth_refresh_due(
            &unreadable,
            epoch_plus(1_700_000_000),
            margin
        ));
    }

    #[test]
    fn a_refresh_begins_only_without_active_leases_or_refreshes() {
        let launch = auth_bytes("acct-1", "old");
        let (_dir, source) = source_with_auth(&launch);
        let lease = CodexAuthLease::enter(&source, &launch, None);
        assert!(begin_codex_auth_refresh(&source).is_none());
        lease.finish(Ok(None));
        let guard = begin_codex_auth_refresh(&source).expect("no active lease");
        assert!(begin_codex_auth_refresh(&source).is_none());
        drop(guard);
        assert!(begin_codex_auth_refresh(&source).is_some());
    }

    #[test]
    fn a_launch_waits_for_a_refresh_and_then_reloads() {
        let launch = auth_bytes("acct-1", "old");
        let (_dir, source) = source_with_auth(&launch);
        let guard = begin_codex_auth_refresh(&source).expect("no active lease");
        let expired = Instant::now() + Duration::from_millis(50);
        assert!(CodexAuthLease::enter_unless_refreshing(&source, &launch, None, expired).is_err());
        let waiter = {
            let source = source.clone();
            let launch = launch.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                CodexAuthLease::enter_unless_refreshing(&source, &launch, None, deadline)
                    .map(|lease| lease.is_none())
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        drop(guard);
        assert!(waiter.join().unwrap().unwrap());
        let deadline = Instant::now() + Duration::from_secs(1);
        let lease = CodexAuthLease::enter_unless_refreshing(&source, &launch, None, deadline)
            .unwrap()
            .expect("no refresh in progress");
        assert!(begin_codex_auth_refresh(&source).is_none());
        lease.finish(Ok(None));
    }

    #[test]
    fn a_lone_due_launch_claims_the_refresh() {
        let day = 24 * 60 * 60;
        let due = jwt_auth_bytes("acct-1", "eyJleHAiOjE3MDAwMDAwMDB9");
        let (dir, source) = source_with_auth(&due);
        let home = Some(dir.path());
        let now = epoch_plus(1_700_000_000 - day);
        let (first, claimed) = CodexAuthLease::enter_claiming_refresh(&source, &due, home, now);
        assert!(claimed);
        let (second, overlapping) =
            CodexAuthLease::enter_claiming_refresh(&source, &due, home, now);
        assert!(!overlapping);
        second.finish(Ok(None));
        first.finish(Ok(None));
        let early = epoch_plus(1_700_000_000 - 4 * day);
        let (lease, not_due) = CodexAuthLease::enter_claiming_refresh(&source, &due, home, early);
        assert!(!not_due);
        lease.finish(Ok(None));
        let (lease, unstaged) = CodexAuthLease::enter_claiming_refresh(&source, &due, None, now);
        assert!(!unstaged);
        lease.finish(Ok(None));
        let guard = begin_codex_auth_refresh(&source).expect("no active lease");
        let (lease, refreshing) = CodexAuthLease::enter_claiming_refresh(&source, &due, home, now);
        assert!(!refreshing);
        lease.finish(Ok(None));
        drop(guard);
        let (lease, again) = CodexAuthLease::enter_claiming_refresh(&source, &due, home, now);
        assert!(again);
        lease.finish(Ok(None));
    }

    #[test]
    fn the_last_lease_of_a_source_writes_back() {
        let launch = auth_bytes("acct-1", "old");
        let rotated = auth_bytes("acct-1", "new");
        let (_dir, source) = source_with_auth(&launch);
        let first = CodexAuthLease::enter(&source, &launch, None);
        let second = CodexAuthLease::enter(&source, &launch, None);
        first.finish(Ok(Some(rotated.clone())));
        assert_eq!(read_source(&source), launch);
        second.finish(Ok(None));
        assert_eq!(read_source(&source), rotated);
    }

    #[test]
    fn a_dropped_lease_releases_a_pending_write_back() {
        let launch = auth_bytes("acct-1", "old");
        let rotated = auth_bytes("acct-1", "new");
        let (_dir, source) = source_with_auth(&launch);
        let first = CodexAuthLease::enter(&source, &launch, None);
        let second = CodexAuthLease::enter(&source, &launch, None);
        first.finish(Ok(Some(rotated.clone())));
        drop(second);
        assert_eq!(read_source(&source), rotated);
    }

    #[test]
    fn a_dropped_lease_captures_its_staged_home() {
        let launch = auth_bytes("acct-1", "old");
        let rotated = auth_bytes("acct-1", "new");
        let (_dir, source) = source_with_auth(&launch);
        let staged_home = tempfile::tempdir().unwrap();
        fs::write(staged_home.path().join("auth.json"), &rotated).unwrap();
        let lease = CodexAuthLease::enter(&source, &launch, Some(staged_home.path()));
        drop(lease);
        assert_eq!(read_source(&source), rotated);
    }
}
