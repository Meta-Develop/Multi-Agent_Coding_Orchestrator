//! Shared helpers for the integration-test suites.
//!
//! Used by the M1 exit-criteria suite and the adapter contract suite. Kept
//! out of the test bodies so the tests can stay about the property they pin
//! down, not about walking directories.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, FileType};
use std::path::{Path, PathBuf};

use coding_agent_manager_lib::backup::BackupStore;
use tempfile::TempDir;

/// Every secret-shaped fixture value starts with this prefix.
///
/// `docs/TESTING.md` §3 and the `secret-hygiene` CI job both depend on it
/// meaning what it says: never attach it to a real credential.
pub const FAKE_PREFIX: &str = "FAKE-";

/// On-disk fixture home, derived from `docs/research/codex-cli.md` §2–§3.
pub const FIXTURE_HOME: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codex-cli/home");

/// Auth document written by the simulated switch. Distinct from the fixture
/// so a no-op mutation cannot hide a broken restore.
pub const SWITCHED_AUTH: &str = r#"{
  "auth_mode": "plan",
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "FAKE-id-token-0002",
    "access_token": "FAKE-access-token-0002",
    "refresh_token": "FAKE-refresh-token-0002",
    "account_id": "FAKE-account-0002"
  },
  "last_refresh": "2026-08-18T00:00:00.000Z"
}
"#;

/// Second file the simulated switch creates. Absent in the fixture, so a
/// restore that forgets captured-absent paths would leave it behind.
pub const SWITCHED_PENDING: &str = r#"{"status":"created-by-switch"}"#;

/// A disposable copy of the fixture tree plus a backup root beside it.
///
/// The copy lives in a `TempDir` so no test ever touches a real `$HOME`
/// (`docs/TESTING.md` §3).
pub struct Fixture {
    pub temp: TempDir,
    pub home: PathBuf,
    pub backups: PathBuf,
    pub auth_json: PathBuf,
    pub config_toml: PathBuf,
    pub history: PathBuf,
    /// Listed in `config_paths` and missing on disk before the switch.
    pub pending: PathBuf,
}

impl Fixture {
    pub fn materialise() -> Self {
        let temp = TempDir::new().expect("tempdir");
        let home = temp.path().join("home");
        copy_tree(Path::new(FIXTURE_HOME), &home);

        let auth_json = home.join(".codex/auth.json");
        let config_toml = home.join(".codex/config.toml");
        let history = home.join(".codex/sessions/history.jsonl");
        let pending = home.join(".codex/credentials.pending.json");

        // Modes are part of "byte-identical". Set them explicitly: Git and the
        // NTFS checkout do not preserve a credential file's 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(home.join(".codex"), fs::Permissions::from_mode(0o700))
                .expect("chmod .codex");
            fs::set_permissions(&auth_json, fs::Permissions::from_mode(0o600)).expect("chmod auth");
            fs::set_permissions(&config_toml, fs::Permissions::from_mode(0o644))
                .expect("chmod config");
            fs::set_permissions(
                home.join(".codex/sessions"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("chmod sessions");
            fs::set_permissions(&history, fs::Permissions::from_mode(0o644))
                .expect("chmod history");
        }

        assert!(
            !pending.exists(),
            "the pending path must be absent in the fixture"
        );

        Self {
            backups: temp.path().join("backups"),
            temp,
            home,
            auth_json,
            config_toml,
            history,
            pending,
        }
    }

    /// Paths a Codex-shaped switch would hand to the backup subsystem.
    ///
    /// The directory covers the nested tree (credential document, sibling
    /// settings, session history). The pending path is listed so its absence
    /// is captured, matching `docs/ARCHITECTURE.md` §4: `config_paths()`
    /// returns existing and missing paths alike.
    pub fn config_paths(&self) -> Vec<PathBuf> {
        vec![self.home.join(".codex"), self.pending.clone()]
    }

    pub fn store(&self) -> BackupStore {
        BackupStore::new(&self.backups)
    }

    pub fn digest(&self) -> TreeDigest {
        tree_digest(&self.home)
    }

    /// The two writes a multi-file switch performs after the snapshot.
    pub fn switch_writes(&self) -> [(&Path, &[u8]); 2] {
        [
            (self.auth_json.as_path(), SWITCHED_AUTH.as_bytes()),
            (self.pending.as_path(), SWITCHED_PENDING.as_bytes()),
        ]
    }
}

/// Deterministic description of a directory tree.
///
/// Equality is the mechanical form of "byte-identical": relative path, kind,
/// file bytes, and Unix permission bits. File bytes are never shown in
/// `Debug`/`Display` — they are the secret material this suite exists to keep
/// out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeDigest {
    entries: BTreeMap<String, Node>,
}

#[derive(Clone, PartialEq, Eq)]
enum Node {
    Directory { mode: u32 },
    File { mode: u32, bytes: Vec<u8> },
    Other { mode: u32, kind: String },
}

impl TreeDigest {
    /// Path, kind, and bytes only. Used to separate a content-restore failure
    /// from a permission-only mismatch in assertion messages.
    pub fn content_identity(&self) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .map(|(path, node)| {
                let summary = match node {
                    Node::Directory { .. } => "dir".to_owned(),
                    Node::File { bytes, .. } => {
                        format!("file {}b fnv={}", bytes.len(), fnv1a64(bytes))
                    }
                    Node::Other { kind, .. } => kind.clone(),
                };
                (path.clone(), summary)
            })
            .collect()
    }

    pub fn diff(&self, other: &Self) -> String {
        let mut lines = Vec::new();
        for (path, left) in &self.entries {
            match other.entries.get(path) {
                None => lines.push(format!("- {path} ({})", left.brief())),
                Some(right) if left == right => {}
                Some(right) => {
                    lines.push(format!("~ {path}: {} -> {}", left.brief(), right.brief()));
                }
            }
        }
        for (path, right) in &other.entries {
            if !self.entries.contains_key(path) {
                lines.push(format!("+ {path} ({})", right.brief()));
            }
        }
        if lines.is_empty() {
            "(no difference)".to_owned()
        } else {
            lines.join("\n")
        }
    }
}

impl Node {
    fn brief(&self) -> String {
        match self {
            Self::Directory { mode } => format!("dir mode={mode:03o}"),
            Self::File { mode, bytes } => {
                format!(
                    "file mode={mode:03o} {}b fnv={}",
                    bytes.len(),
                    fnv1a64(bytes)
                )
            }
            Self::Other { mode, kind } => format!("{kind} mode={mode:03o}"),
        }
    }
}

impl fmt::Debug for TreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for TreeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (path, node) in &self.entries {
            writeln!(f, "{} {path}", node.brief())?;
        }
        Ok(())
    }
}

pub fn tree_digest(root: &Path) -> TreeDigest {
    let mut entries = BTreeMap::new();
    collect(root, root, &mut entries);
    TreeDigest { entries }
}

fn collect(root: &Path, path: &Path, out: &mut BTreeMap<String, Node>) {
    let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
        panic!("digest metadata for {}: {error}", path.display());
    });
    let mode = unix_mode(&metadata);
    if path != root {
        let rel = normalise(path.strip_prefix(root).expect("path under root"));
        if metadata.file_type().is_dir() {
            out.insert(rel, Node::Directory { mode });
        } else if metadata.file_type().is_file() {
            let bytes = fs::read(path).unwrap_or_else(|error| {
                panic!("digest read {}: {error}", path.display());
            });
            out.insert(rel, Node::File { mode, bytes });
        } else {
            out.insert(
                rel,
                Node::Other {
                    mode,
                    kind: describe_type(metadata.file_type()),
                },
            );
        }
    }
    if metadata.file_type().is_dir() {
        for entry in fs::read_dir(path).unwrap_or_else(|error| {
            panic!("digest read_dir {}: {error}", path.display());
        }) {
            collect(root, &entry.expect("dirent").path(), out);
        }
    }
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn describe_type(file_type: FileType) -> String {
    if file_type.is_symlink() {
        "symlink".to_owned()
    } else {
        "special".to_owned()
    }
}

fn normalise(path: &Path) -> String {
    path.iter()
        .map(|component| component.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Recursively copy a directory tree of regular files.
///
/// The adapter contract suite stages fixture homes with this so no test
/// resolves the real user home (`docs/TESTING.md` §4). Behaviour is
/// unchanged from the M1 helper: special files are rejected, not followed.
pub fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|error| {
        panic!("create {}: {error}", dst.display());
    });
    for entry in fs::read_dir(src).unwrap_or_else(|error| {
        panic!("read_dir {}: {error}", src.display());
    }) {
        let entry = entry.expect("dirent");
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type().expect("file type");
        if file_type.is_dir() {
            copy_tree(&entry.path(), &to);
        } else if file_type.is_file() {
            fs::copy(entry.path(), &to).unwrap_or_else(|error| {
                panic!(
                    "copy {} -> {}: {error}",
                    entry.path().display(),
                    to.display()
                );
            });
        } else {
            panic!(
                "fixture {} is not a regular file or directory",
                entry.path().display()
            );
        }
    }
}

/// Fail with an actionable message if a fixture secret escaped.
///
/// The prefix is the whole rule. A test that greps for one hard-coded token
/// and then gets ignored when a new fixture value is added protects nothing.
pub fn assert_no_fake(where_: &str, text: &str) {
    if let Some(index) = text.find(FAKE_PREFIX) {
        let leaked = take_token(&text[index..]);
        panic!(
            "{where_} leaked fixture secret material.\n\
             leaked value: {leaked}\n\
             in: {text}\n\
             A `{FAKE_PREFIX}` prefix in a fixture exists so this assertion can \
             grep for it. Redact the value at the source; do not weaken this \
             check or rename the fixture to hide the leak."
        );
    }
}

fn take_token(text: &str) -> &str {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .next()
        .unwrap_or(text)
}

/// Files the application wrote that are not backup payloads.
///
/// Blobs under `files/` are copies of managed config and *should* contain
/// secrets. Everything else — the manifest, any state file — must not.
pub fn sidecar_texts(backups: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    collect_sidecars(backups, backups, &mut found);
    found
}

fn collect_sidecars(root: &Path, path: &Path, out: &mut Vec<(PathBuf, String)>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };
    if metadata.is_dir() {
        let skip_children = path.file_name().is_some_and(|name| name == "files")
            && path
                .parent()
                .is_some_and(|parent| parent.join("manifest.json").is_file());
        if skip_children {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect_sidecars(root, &entry.path(), out);
        }
        return;
    }
    if metadata.is_file() {
        if let Ok(bytes) = fs::read(path) {
            out.push((
                path.strip_prefix(root).unwrap_or(path).to_path_buf(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
