//! Crash-safe two-file Claude Code switch helpers.
//!
//! Identity is split across `~/.claude/.credentials.json` (`claudeAiOauth`)
//! and `~/.claude.json` (`oauthAccount`) [verified-local]. The two vendor
//! files have independent locks and no cross-file transaction, so a switch
//! is one backup/journal/rollback unit owned by this Claude adapter.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::backup::{BackupId, BackupStore};
use crate::error::{Error, Result};
use crate::fsx;

pub(super) const CREDENTIALS_FILE: &str = ".credentials.json";
pub(super) const IDENTITY_FILE: &str = ".claude.json";
pub(super) const OAUTH_KEY: &str = "claudeAiOauth";
pub(super) const ACCOUNT_KEY: &str = "oauthAccount";

const JOURNAL_SCHEMA_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "switch.journal";

/// Test-only injection that fires during `activate_account`.
///
/// Production builds do not carry this type on the adapter. Unit tests use
/// it to pin backup-before-write, mid-pair restore, and restore-on-failure
/// (`docs/TESTING.md` §2, `NFR-4`).
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum SwitchFault {
    #[default]
    None,
    AfterSnapshot,
    AfterFirstWrite,
    AfterWrite,
}

#[derive(Debug, Serialize, Deserialize)]
struct SwitchJournal {
    schema_version: u32,
    backup_id: String,
}

pub(super) struct LivePaths {
    pub credentials: PathBuf,
    pub identity: PathBuf,
}

pub(super) struct LiveDocuments {
    pub credentials: Map<String, Value>,
    pub identity: Map<String, Value>,
}

pub(super) struct StoredPair {
    pub oauth: Value,
    pub account: Value,
    pub credentials: Map<String, Value>,
}

pub(super) fn live_paths(home: &Path) -> LivePaths {
    LivePaths {
        credentials: home.join(".claude").join(CREDENTIALS_FILE),
        identity: home.join(IDENTITY_FILE),
    }
}

pub(super) fn stored_paths(dir: &Path) -> LivePaths {
    LivePaths {
        credentials: dir.join(CREDENTIALS_FILE),
        identity: dir.join(IDENTITY_FILE),
    }
}

pub(super) fn journal_path(data_dir: &Path) -> PathBuf {
    data_dir.join("claude-code").join(JOURNAL_FILE)
}

pub(super) fn config_read(provider: &str, reason: impl Into<String>) -> Error {
    Error::ConfigRead {
        provider: provider.to_string(),
        reason: reason.into(),
    }
}

pub(super) fn config_write(provider: &str, reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: provider.to_string(),
        reason: reason.into(),
    }
}

/// Read a JSON object if the file exists.
///
/// Missing → `Ok(None)`. Present but unreadable, not JSON, or not an
/// object → `Error::ConfigRead`. Reason strings name the path and the
/// kind of failure only. The serde error text can echo a token from the
/// file; never include it (NFR-1).
pub(super) fn read_optional_object(
    path: &Path,
    provider: &str,
) -> Result<Option<Map<String, Value>>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(config_read(
                provider,
                format!("{} ({})", path.display(), error.kind()),
            ));
        }
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| config_read(provider, format!("{} is not valid JSON", path.display())))?;
    match value {
        Value::Object(object) => Ok(Some(object)),
        _ => Err(config_read(
            provider,
            format!("{} is not a JSON object", path.display()),
        )),
    }
}

pub(super) fn require_object_member<'a>(
    document: &'a Map<String, Value>,
    key: &str,
    path: &Path,
    provider: &str,
) -> Result<&'a Map<String, Value>> {
    match document.get(key) {
        Some(Value::Object(object)) => Ok(object),
        Some(_) => Err(config_read(
            provider,
            format!("{} {key} is not an object", path.display()),
        )),
        None => Err(config_read(
            provider,
            format!("{} is missing {key}", path.display()),
        )),
    }
}

pub(super) fn apply_member(
    document: &Map<String, Value>,
    key: &str,
    value: Value,
) -> Map<String, Value> {
    let mut next = document.clone();
    next.insert(key.to_string(), value);
    next
}

pub(super) fn write_json_object(
    path: &Path,
    object: &Map<String, Value>,
    provider: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fsx::create_dir_all_private(parent).map_err(|error| {
            config_write(
                provider,
                format!("could not create {}: {error}", parent.display()),
            )
        })?;
    }
    let mut bytes = serde_json::to_vec_pretty(&Value::Object(object.clone()))
        .map_err(|_| config_write(provider, format!("could not serialize {}", path.display())))?;
    bytes.push(b'\n');
    fsx::write_atomic(path, &bytes).map_err(|error| {
        config_write(
            provider,
            format!("could not write {}: {error}", path.display()),
        )
    })
}

pub(super) fn verify_json_object(
    path: &Path,
    expected: &Map<String, Value>,
    provider: &str,
) -> Result<()> {
    let got = read_optional_object(path, provider)?.ok_or_else(|| {
        config_write(
            provider,
            format!("{} was missing after write", path.display()),
        )
    })?;
    if &got != expected {
        return Err(config_write(
            provider,
            format!(
                "{} did not match the intended document after write",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Live documents a switch may edit. A missing credentials file is an
/// empty object (create only `claudeAiOauth`). A missing identity file
/// is refused so this adapter does not invent `userID` / `machineID`.
pub(super) fn load_live_for_switch(paths: &LivePaths, provider: &str) -> Result<LiveDocuments> {
    let credentials = match read_optional_object(&paths.credentials, provider)? {
        Some(object) => object,
        None => Map::new(),
    };
    let identity = match read_optional_object(&paths.identity, provider)? {
        Some(object) => object,
        None => {
            return Err(config_write(
                provider,
                format!(
                    "{} is missing; refusing to invent Claude machine identity fields",
                    paths.identity.display()
                ),
            ));
        }
    };
    Ok(LiveDocuments {
        credentials,
        identity,
    })
}

pub(super) fn stored_pair_from_objects(
    credentials: &Map<String, Value>,
    identity: &Map<String, Value>,
    credentials_path: &Path,
    identity_path: &Path,
    provider: &str,
) -> Result<StoredPair> {
    let oauth = require_object_member(credentials, OAUTH_KEY, credentials_path, provider)?;
    if !oauth.get("accessToken").is_some_and(Value::is_string) {
        return Err(config_read(
            provider,
            format!(
                "{} {OAUTH_KEY} is missing an accessToken string",
                credentials_path.display()
            ),
        ));
    }
    let account = require_object_member(identity, ACCOUNT_KEY, identity_path, provider)?;
    Ok(StoredPair {
        oauth: Value::Object(oauth.clone()),
        account: Value::Object(account.clone()),
        credentials: credentials.clone(),
    })
}

/// Load a complete managed pair. `None` means the slot is missing or
/// incomplete (no credentials file). Unreadable files stay errors so a
/// switch does not guess.
pub(super) fn load_stored_pair(dir: &Path, provider: &str) -> Result<Option<StoredPair>> {
    let paths = stored_paths(dir);
    let credentials = match read_optional_object(&paths.credentials, provider)? {
        Some(object) => object,
        None => return Ok(None),
    };
    let identity = match read_optional_object(&paths.identity, provider)? {
        Some(object) => object,
        None => return Ok(None),
    };
    stored_pair_from_objects(
        &credentials,
        &identity,
        &paths.credentials,
        &paths.identity,
        provider,
    )
    .map(Some)
}

pub(super) fn write_journal(path: &Path, backup_id: &BackupId, provider: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fsx::create_dir_all_private(parent).map_err(|error| {
            config_write(
                provider,
                format!("could not create {}: {error}", parent.display()),
            )
        })?;
    }
    let journal = SwitchJournal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        backup_id: backup_id.as_str().to_string(),
    };
    let mut bytes = serde_json::to_vec(&journal)
        .map_err(|_| config_write(provider, format!("could not serialize {}", path.display())))?;
    bytes.push(b'\n');
    fsx::write_atomic(path, &bytes).map_err(|error| {
        config_write(
            provider,
            format!("could not write {}: {error}", path.display()),
        )
    })
}

pub(super) fn clear_journal(path: &Path, provider: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(config_write(
            provider,
            format!(
                "could not remove switch journal {} ({})",
                path.display(),
                error.kind()
            ),
        )),
    }
}

/// Restore both live files from the journaled backup, then drop the journal.
///
/// A missing journal is a no-op. A journal that cannot be parsed or whose
/// backup cannot be restored is left in place so the next operation retries.
pub(super) fn recover(store: &BackupStore, journal: &Path, provider: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(journal) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(config_read(
                provider,
                format!("{} ({})", journal.display(), error.kind()),
            ));
        }
    };
    if !metadata.is_file() {
        return Err(config_read(
            provider,
            format!("{} is not a regular file", journal.display()),
        ));
    }
    let bytes = fs::read(journal).map_err(|error| {
        config_read(
            provider,
            format!("{} ({})", journal.display(), error.kind()),
        )
    })?;
    let parsed: SwitchJournal = serde_json::from_slice(&bytes).map_err(|_| {
        config_read(
            provider,
            format!("{} is not a valid switch journal", journal.display()),
        )
    })?;
    if parsed.schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(config_read(
            provider,
            format!(
                "{} has unsupported schema version {}; refusing to guess",
                journal.display(),
                parsed.schema_version
            ),
        ));
    }
    let backup_id = BackupId::parse(&parsed.backup_id).map_err(|_| {
        config_read(
            provider,
            format!("{} names an invalid backup id", journal.display()),
        )
    })?;
    store.restore(&backup_id).map_err(|error| {
        config_write(
            provider,
            format!(
                "could not restore the paired Claude files from backup {}: {error}",
                backup_id.as_str()
            ),
        )
    })?;
    clear_journal(journal, provider)
}

/// Restore both files from `backup` and keep or clear the journal so a
/// failed switch never leaves a half-applied pair.
pub(super) fn abort_switch(
    store: &BackupStore,
    backup: &BackupId,
    journal: &Path,
    provider: &str,
    reason: impl Into<String>,
) -> Error {
    let reason = reason.into();
    match store.restore(backup) {
        Ok(()) => match clear_journal(journal, provider) {
            Ok(()) => config_write(
                provider,
                format!("{reason}; the previous account is still active"),
            ),
            Err(clear_error) => config_write(
                provider,
                format!(
                    "{reason}; the previous account was restored but the switch journal remains: {clear_error}"
                ),
            ),
        },
        Err(restore_error) => config_write(
            provider,
            format!("{reason}; restore of the previous account also failed: {restore_error}"),
        ),
    }
}

/// Whether the live documents hold the same identity objects as `stored`.
pub(super) fn live_matches_stored(
    credentials: &Map<String, Value>,
    identity: Option<&Map<String, Value>>,
    stored: &StoredPair,
) -> bool {
    let Some(live_oauth) = credentials.get(OAUTH_KEY) else {
        return false;
    };
    let Some(identity) = identity else {
        return false;
    };
    let Some(live_account) = identity.get(ACCOUNT_KEY) else {
        return false;
    };
    live_oauth == &stored.oauth && live_account == &stored.account
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BackupStore;
    use serde_json::json;

    fn write_file(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, body).expect("write");
    }

    #[test]
    fn apply_member_replaces_only_the_named_key() {
        let live = json!({
            "claudeAiOauth": {"accessToken": "old"},
            "keep": 1
        })
        .as_object()
        .unwrap()
        .clone();
        let next = apply_member(&live, OAUTH_KEY, json!({"accessToken": "new"}));
        assert_eq!(next.get("keep"), Some(&json!(1)));
        assert_eq!(next.get(OAUTH_KEY), Some(&json!({"accessToken": "new"})));
        assert_eq!(next.len(), 2);
    }

    #[test]
    fn recover_restores_both_files_and_clears_the_journal() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("home");
        let data = root.path().join("data");
        let paths = live_paths(&home);
        write_file(&paths.credentials, r#"{"keep":"credentials"}"#);
        write_file(&paths.identity, r#"{"keep":"identity"}"#);

        let store = BackupStore::new(data.join("backups"));
        let backup = store
            .snapshot(
                "claude-code",
                &[paths.credentials.clone(), paths.identity.clone()],
            )
            .expect("snapshot");
        write_file(&paths.credentials, r#"{"keep":"partial"}"#);
        write_file(&paths.identity, r#"{"keep":"partial"}"#);

        let journal = journal_path(&data);
        write_journal(&journal, &backup, "claude-code").expect("journal");
        recover(&store, &journal, "claude-code").expect("recover");

        let credentials = read_optional_object(&paths.credentials, "claude-code")
            .expect("read credentials")
            .expect("credentials");
        let identity = read_optional_object(&paths.identity, "claude-code")
            .expect("read identity")
            .expect("identity");
        assert_eq!(credentials.get("keep"), Some(&json!("credentials")));
        assert_eq!(identity.get("keep"), Some(&json!("identity")));
        assert!(fs::symlink_metadata(&journal).is_err());
    }

    #[test]
    fn recover_is_a_noop_when_the_journal_is_missing() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = BackupStore::new(root.path().join("backups"));
        recover(&store, &journal_path(root.path()), "claude-code").expect("missing journal");
    }

    #[test]
    fn recover_refuses_an_unknown_journal_version() {
        let root = tempfile::tempdir().expect("tempdir");
        let journal = journal_path(root.path());
        write_file(
            &journal,
            r#"{"schema_version":2,"backup_id":"claude-code-1"}"#,
        );
        let store = BackupStore::new(root.path().join("backups"));
        let error = recover(&store, &journal, "claude-code").expect_err("unknown version");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert!(
            error.to_string().contains("unsupported schema version"),
            "{error}"
        );
        assert!(journal.is_file(), "unreadable journal must remain");
    }
}
