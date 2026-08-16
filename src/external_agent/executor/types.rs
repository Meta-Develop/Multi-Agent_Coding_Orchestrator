use super::checksum::sha256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, fmt, num::NonZeroU16};
use thiserror::Error;

pub const EXECUTOR_PROTOCOL_VERSION: u32 = 1;
const MAX_OPAQUE_ID_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 255;
const MAX_REMOTE_USER_BYTES: usize = 64;
const MAX_REMOTE_PATH_BYTES: usize = 1024;
const MAX_LOGICAL_PATH_BYTES: usize = 512;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARGV_BYTES: usize = 16 * 1024;
const MAX_MANIFEST_ENTRIES: usize = 1024;
const MAX_INPUT_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUT_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_DECLARED_OUTPUTS: usize = 128;
const MAX_PATCH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OUTPUT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OUTPUT_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_OUTPUT_MEDIA_TYPE_BYTES: usize = 128;
const MAX_CHANGED_PATHS: usize = 4096;
const MAX_WAIT_MILLIS: u64 = 24 * 60 * 60 * 1000;
const MAX_LINUX_PROCESS_SIGNAL: u16 = 64;
// Conservative wire-accounting overheads. The fixed allowance covers the complete
// maximum-width execution identity, receipt keys/digests, scalar fields, container
// counts, and their length prefixes. Per-item allowances cover their own framing
// and blob digest/declared-size metadata; payload bytes are budgeted separately.
const RECEIPT_FIXED_FRAMING_BYTES: u64 = 4 * 1024;
const RECEIPT_CHANGED_PATH_FRAMING_BYTES: u64 = 16;
const RECEIPT_OUTPUT_FRAMING_BYTES: u64 = 128;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("{what} exceeds its limit of {limit}")]
    LimitExceeded { what: &'static str, limit: u64 },
    #[error("duplicate {what}: {value}")]
    Duplicate { what: &'static str, value: String },
    #[error("transport lost during {operation}: {detail}")]
    TransportLost {
        operation: Operation,
        detail: String,
    },
    #[error("malformed {operation} receipt: {reason}")]
    MalformedReceipt {
        operation: Operation,
        reason: String,
    },
    #[error("checksum mismatch for {object}")]
    ChecksumMismatch { object: String },
    #[error("remote output path is undeclared: {0}")]
    UndeclaredOutput(String),
    #[error("changed path is outside assignment scope: {0}")]
    ChangedPathOutsideScope(String),
    #[error("remote collection was rejected: {reason}")]
    CollectionRejected {
        reason: String,
        cleanup: Box<Effect<CleanupReceipt>>,
    },
}

pub type ExecutorResult<T> = Result<T, ExecutorError>;

fn invalid(field: &'static str, reason: impl Into<String>) -> ExecutorError {
    ExecutorError::InvalidField {
        field,
        reason: reason.into(),
    }
}

fn validate_opaque(field: &'static str, value: &str) -> ExecutorResult<()> {
    if value.is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if value.len() > MAX_OPAQUE_ID_BYTES {
        return Err(invalid(field, "is too long"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid(
            field,
            "must contain only ASCII letters, digits, '.', '-', or '_'",
        ));
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
                let value = value.into();
                validate_opaque($field, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

opaque_id!(HostId, "host id");
opaque_id!(RunId, "run id");
opaque_id!(AssignmentId, "assignment id");
opaque_id!(SessionId, "session id");
opaque_id!(WorkspaceId, "workspace id");
opaque_id!(Nonce, "nonce");
opaque_id!(StartToken, "process start token");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(invalid(
                "digest",
                "must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value))
    }

    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(&sha256(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let digest = Digest::new(value)?;
        Ok(Self(digest.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for IdempotencyKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn derive_key<'a>(phase: &str, parts: impl IntoIterator<Item = &'a str>) -> IdempotencyKey {
    let mut material = Vec::new();
    append_framed(&mut material, phase.as_bytes());
    for part in parts {
        append_framed(&mut material, part.as_bytes());
    }
    IdempotencyKey(hex_encode(&sha256(&material)))
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
            return Err(invalid("SSH endpoint", "must be nonempty and bounded"));
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        }) {
            return Err(invalid(
                "SSH endpoint",
                "contains whitespace or unsupported characters",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteUser(String);

impl RemoteUser {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_REMOTE_USER_BYTES {
            return Err(invalid("SSH user", "must be nonempty and bounded"));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid("SSH user", "contains unsupported characters"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemoteUser {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteAbsolutePath(String);

impl RemoteAbsolutePath {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.len() < 2 || value.len() > MAX_REMOTE_PATH_BYTES || !value.starts_with('/') {
            return Err(invalid(
                "remote absolute path",
                "must be a bounded non-root absolute path",
            ));
        }
        if value.contains('\\')
            || value.contains('\0')
            || value.contains('%')
            || value.ends_with('/')
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid(
                "remote absolute path",
                "contains a backslash, control byte, ambiguous encoding, or trailing separator",
            ));
        }
        for component in value[1..].split('/') {
            if component.is_empty() || matches!(component, "." | "..") {
                return Err(invalid(
                    "remote absolute path",
                    "contains an empty, dot, or parent component",
                ));
            }
            if !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err(invalid(
                    "remote absolute path",
                    "contains unsupported or ambiguous characters",
                ));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemoteAbsolutePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshTargetConfig {
    pub host_id: HostId,
    pub endpoint: Endpoint,
    pub user: RemoteUser,
    pub port: NonZeroU16,
    pub helper: RemoteAbsolutePath,
    pub root: RemoteAbsolutePath,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalPath(String);

impl LogicalPath {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_LOGICAL_PATH_BYTES {
            return Err(invalid("logical path", "must be nonempty and bounded"));
        }
        if value.starts_with('/') || value.starts_with('\\') || value.contains('\\') {
            return Err(invalid(
                "logical path",
                "absolute and Windows-style paths are forbidden",
            ));
        }
        let lower = value.to_ascii_lowercase();
        if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
            return Err(invalid(
                "logical path",
                "encoded path-separator and dot spellings are forbidden",
            ));
        }
        for component in value.split('/') {
            if component.is_empty() || matches!(component, "." | "..") {
                return Err(invalid(
                    "logical path",
                    "contains an empty, dot, or parent component",
                ));
            }
            if !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err(invalid(
                    "logical path",
                    "contains unsupported or ambiguous characters",
                ));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_within(&self, scope: &Self) -> bool {
        self == scope
            || self
                .0
                .strip_prefix(&scope.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for LogicalPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LogicalPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLiteral(String);

impl BoundedLiteral {
    pub fn new(value: impl Into<String>) -> ExecutorResult<Self> {
        let value = value.into();
        if value.len() > MAX_ARG_BYTES
            || value.contains('\0')
            || value.contains('/')
            || value.contains('\\')
            || value.contains('%')
            || value == "."
            || value == ".."
            || value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        {
            return Err(invalid(
                "literal argument",
                "is oversized, contains NUL, or resembles an unmapped path",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedArg {
    Literal(BoundedLiteral),
    ManifestPath(LogicalPath),
    FinalStdinMarker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedArgv(Vec<TypedArg>);

impl TypedArgv {
    pub fn new(arguments: Vec<TypedArg>) -> ExecutorResult<Self> {
        if arguments.is_empty() || arguments.len() > MAX_ARG_COUNT {
            return Err(invalid("typed argv", "must be nonempty and bounded"));
        }
        let mut total_bytes = 0_usize;
        let mut stdin_markers = 0_usize;
        for (index, argument) in arguments.iter().enumerate() {
            match argument {
                TypedArg::Literal(value) => total_bytes = total_bytes.saturating_add(value.0.len()),
                TypedArg::ManifestPath(path) => {
                    total_bytes = total_bytes.saturating_add(path.0.len())
                }
                TypedArg::FinalStdinMarker => {
                    stdin_markers = stdin_markers.saturating_add(1);
                    if index + 1 != arguments.len() {
                        return Err(invalid(
                            "typed argv",
                            "the stdin marker must be the final argument",
                        ));
                    }
                    total_bytes = total_bytes.saturating_add(1);
                }
            }
        }
        if stdin_markers != 1 {
            return Err(invalid(
                "typed argv",
                "must contain exactly one final stdin marker",
            ));
        }
        if total_bytes > MAX_ARGV_BYTES {
            return Err(ExecutorError::LimitExceeded {
                what: "typed argv bytes",
                limit: MAX_ARGV_BYTES as u64,
            });
        }
        Ok(Self(arguments))
    }

    pub fn arguments(&self) -> &[TypedArg] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestPurpose {
    Prompt,
    Schema,
    WorkspaceInput,
    FinalMessageOutput,
    JsonLogOutput,
    DeclaredOutput,
}

impl ManifestPurpose {
    fn canonical_name(self) -> &'static [u8] {
        match self {
            Self::Prompt => b"prompt",
            Self::Schema => b"schema",
            Self::WorkspaceInput => b"workspace-input",
            Self::FinalMessageOutput => b"final-message-output",
            Self::JsonLogOutput => b"json-log-output",
            Self::DeclaredOutput => b"declared-output",
        }
    }

    pub fn is_input(self) -> bool {
        matches!(self, Self::Prompt | Self::Schema | Self::WorkspaceInput)
    }

    pub fn is_output(self) -> bool {
        !self.is_input()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestEntryKind {
    Input { bytes: Vec<u8>, digest: Digest },
    Output { max_bytes: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    path: LogicalPath,
    purpose: ManifestPurpose,
    kind: ManifestEntryKind,
}

impl ManifestEntry {
    pub fn input_file(
        path: LogicalPath,
        purpose: ManifestPurpose,
        bytes: Vec<u8>,
    ) -> ExecutorResult<Self> {
        if !purpose.is_input() {
            return Err(invalid(
                "manifest input purpose",
                "must be prompt, schema, or workspace input",
            ));
        }
        if bytes.len() > MAX_INPUT_FILE_BYTES {
            return Err(ExecutorError::LimitExceeded {
                what: "staged input file bytes",
                limit: MAX_INPUT_FILE_BYTES as u64,
            });
        }
        let digest = Digest::for_bytes(&bytes);
        Ok(Self {
            path,
            purpose,
            kind: ManifestEntryKind::Input { bytes, digest },
        })
    }

    pub fn output_path(
        path: LogicalPath,
        purpose: ManifestPurpose,
        max_bytes: u64,
    ) -> ExecutorResult<Self> {
        if !purpose.is_output() {
            return Err(invalid(
                "manifest output purpose",
                "must be final-message, JSON-log, or declared output",
            ));
        }
        if max_bytes == 0 || max_bytes > MAX_OUTPUT_FILE_BYTES {
            return Err(invalid(
                "manifest output byte limit",
                "is zero or exceeds the protocol maximum",
            ));
        }
        Ok(Self {
            path,
            purpose,
            kind: ManifestEntryKind::Output { max_bytes },
        })
    }

    pub fn path(&self) -> &LogicalPath {
        &self.path
    }

    pub fn purpose(&self) -> ManifestPurpose {
        self.purpose
    }

    pub fn input_bytes(&self) -> Option<&[u8]> {
        match &self.kind {
            ManifestEntryKind::Input { bytes, .. } => Some(bytes),
            ManifestEntryKind::Output { .. } => None,
        }
    }

    pub fn input_digest(&self) -> Option<&Digest> {
        match &self.kind {
            ManifestEntryKind::Input { digest, .. } => Some(digest),
            ManifestEntryKind::Output { .. } => None,
        }
    }

    pub fn output_max_bytes(&self) -> Option<u64> {
        match self.kind {
            ManifestEntryKind::Input { .. } => None,
            ManifestEntryKind::Output { max_bytes } => Some(max_bytes),
        }
    }

    fn revalidate(&self) -> ExecutorResult<()> {
        match &self.kind {
            ManifestEntryKind::Input { bytes, digest } => {
                if !self.purpose.is_input() {
                    return Err(invalid(
                        "manifest input purpose",
                        "does not match its input direction",
                    ));
                }
                if bytes.len() > MAX_INPUT_FILE_BYTES {
                    return Err(ExecutorError::LimitExceeded {
                        what: "staged input file bytes",
                        limit: MAX_INPUT_FILE_BYTES as u64,
                    });
                }
                if &Digest::for_bytes(bytes) != digest {
                    return Err(ExecutorError::ChecksumMismatch {
                        object: self.path.to_string(),
                    });
                }
            }
            ManifestEntryKind::Output { max_bytes } => {
                if !self.purpose.is_output()
                    || *max_bytes == 0
                    || *max_bytes > MAX_OUTPUT_FILE_BYTES
                {
                    return Err(invalid(
                        "manifest output entry",
                        "has a mismatched direction or invalid byte limit",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputManifest {
    entries: Vec<ManifestEntry>,
    digest: Digest,
}

impl InputManifest {
    pub fn new(mut entries: Vec<ManifestEntry>) -> ExecutorResult<Self> {
        let digest = Self::canonicalize(&mut entries)?;
        Ok(Self { entries, digest })
    }

    fn canonicalize(entries: &mut [ManifestEntry]) -> ExecutorResult<Digest> {
        if entries.is_empty() || entries.len() > MAX_MANIFEST_ENTRIES {
            return Err(invalid("input manifest", "must be nonempty and bounded"));
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let mut total = 0_usize;
        let mut previous: Option<&LogicalPath> = None;
        let mut canonical = Vec::new();
        for entry in entries.iter() {
            entry.revalidate()?;
            if previous == Some(&entry.path) {
                return Err(ExecutorError::Duplicate {
                    what: "manifest path",
                    value: entry.path.to_string(),
                });
            }
            previous = Some(&entry.path);
            let input_length = entry.input_bytes().map_or(0, <[u8]>::len);
            total = total
                .checked_add(input_length)
                .ok_or(ExecutorError::LimitExceeded {
                    what: "staged input aggregate bytes",
                    limit: MAX_INPUT_TOTAL_BYTES as u64,
                })?;
            if total > MAX_INPUT_TOTAL_BYTES {
                return Err(ExecutorError::LimitExceeded {
                    what: "staged input aggregate bytes",
                    limit: MAX_INPUT_TOTAL_BYTES as u64,
                });
            }
            append_framed(&mut canonical, entry.path.as_str().as_bytes());
            append_framed(&mut canonical, entry.purpose.canonical_name());
            match &entry.kind {
                ManifestEntryKind::Input { bytes, digest } => {
                    append_framed(&mut canonical, b"input");
                    append_framed(&mut canonical, digest.as_str().as_bytes());
                    append_framed(&mut canonical, &(bytes.len() as u64).to_be_bytes());
                }
                ManifestEntryKind::Output { max_bytes } => {
                    append_framed(&mut canonical, b"output");
                    append_framed(&mut canonical, &max_bytes.to_be_bytes());
                }
            }
        }
        Ok(Digest::for_bytes(&canonical))
    }

    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn declares(&self, path: &LogicalPath) -> bool {
        self.entries.iter().any(|entry| &entry.path == path)
    }

    pub fn entry(&self, path: &LogicalPath) -> Option<&ManifestEntry> {
        self.entries.iter().find(|entry| &entry.path == path)
    }

    pub fn revalidate(&self) -> ExecutorResult<()> {
        let mut entries = self.entries.clone();
        let digest = Self::canonicalize(&mut entries)?;
        if entries != self.entries || digest != self.digest {
            return Err(invalid(
                "input manifest",
                "stored canonical ordering or digest was modified",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn tamper_first_input_digest_for_test(&mut self) {
        if let Some(ManifestEntry {
            kind: ManifestEntryKind::Input { digest, .. },
            ..
        }) = self
            .entries
            .iter_mut()
            .find(|entry| matches!(entry.kind, ManifestEntryKind::Input { .. }))
        {
            *digest = Digest::for_bytes(b"tampered");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentIdentity {
    pub host_id: HostId,
    pub run_id: RunId,
    pub assignment_id: AssignmentId,
    pub nonce: Nonce,
}

impl AssignmentIdentity {
    pub fn new(host_id: HostId, run_id: RunId, assignment_id: AssignmentId, nonce: Nonce) -> Self {
        Self {
            host_id,
            run_id,
            assignment_id,
            nonce,
        }
    }

    pub fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn assignment_id(&self) -> &AssignmentId {
        &self.assignment_id
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRequest {
    pub(super) identity: AssignmentIdentity,
    pub(super) manifest: InputManifest,
    pub(super) key: IdempotencyKey,
}

impl StageRequest {
    pub fn new(identity: AssignmentIdentity, manifest: InputManifest) -> Self {
        let key = derive_assignment_key("stage", &identity, manifest.digest());
        Self {
            identity,
            manifest,
            key,
        }
    }

    pub fn identity(&self) -> &AssignmentIdentity {
        &self.identity
    }

    pub fn manifest(&self) -> &InputManifest {
        &self.manifest
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    #[cfg(test)]
    pub(crate) fn tamper_key_for_test(&mut self, key: IdempotencyKey) {
        self.key = key;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageTransportRequest {
    pub target: SshTargetConfig,
    pub stage: StageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageTransportReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: AssignmentIdentity,
    pub(super) staged_digest: Digest,
    pub(super) session_id: SessionId,
    pub(super) workspace_id: WorkspaceId,
}

impl StageTransportReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: AssignmentIdentity,
        staged_digest: Digest,
        session_id: SessionId,
        workspace_id: WorkspaceId,
    ) -> Self {
        Self {
            protocol_version,
            key,
            identity,
            staged_digest,
            session_id,
            workspace_id,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn identity(&self) -> &AssignmentIdentity {
        &self.identity
    }

    pub fn staged_digest(&self) -> &Digest {
        &self.staged_digest
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StagedAssignment {
    pub(super) identity: AssignmentIdentity,
    pub(super) staged_digest: Digest,
    pub(super) session_id: SessionId,
    pub(super) workspace_id: WorkspaceId,
    pub(super) manifest: InputManifest,
}

impl StagedAssignment {
    pub fn identity(&self) -> &AssignmentIdentity {
        &self.identity
    }

    pub fn staged_digest(&self) -> &Digest {
        &self.staged_digest
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn manifest(&self) -> &InputManifest {
        &self.manifest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedMillis(u64);

impl BoundedMillis {
    pub fn new(value: u64) -> ExecutorResult<Self> {
        if value == 0 || value > MAX_WAIT_MILLIS {
            return Err(invalid(
                "duration milliseconds",
                "must be positive and no more than 24 hours",
            ));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub(super) argv: TypedArgv,
    pub(super) stdin: LogicalPath,
    pub(super) deadline: BoundedMillis,
    digest: Digest,
}

impl LaunchSpec {
    pub fn new(argv: TypedArgv, stdin: LogicalPath, deadline: BoundedMillis) -> Self {
        let digest = digest_launch_spec(&argv, &stdin, deadline);
        Self {
            argv,
            stdin,
            deadline,
            digest,
        }
    }

    pub fn argv(&self) -> &TypedArgv {
        &self.argv
    }

    pub fn stdin(&self) -> &LogicalPath {
        &self.stdin
    }

    pub fn deadline(&self) -> BoundedMillis {
        self.deadline
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn revalidate(&self) -> ExecutorResult<()> {
        if digest_launch_spec(&self.argv, &self.stdin, self.deadline) == self.digest {
            Ok(())
        } else {
            Err(invalid(
                "launch spec",
                "stored canonical digest was modified",
            ))
        }
    }
}

fn digest_launch_spec(argv: &TypedArgv, stdin: &LogicalPath, deadline: BoundedMillis) -> Digest {
    let mut canonical = Vec::new();
    for argument in argv.arguments() {
        match argument {
            TypedArg::Literal(value) => {
                append_framed(&mut canonical, b"literal");
                append_framed(&mut canonical, value.as_str().as_bytes());
            }
            TypedArg::ManifestPath(path) => {
                append_framed(&mut canonical, b"manifest-path");
                append_framed(&mut canonical, path.as_str().as_bytes());
            }
            TypedArg::FinalStdinMarker => append_framed(&mut canonical, b"stdin-marker"),
        }
    }
    append_framed(&mut canonical, b"stdin");
    append_framed(&mut canonical, stdin.as_str().as_bytes());
    append_framed(&mut canonical, b"deadline-ms");
    append_framed(&mut canonical, &deadline.get().to_be_bytes());
    Digest::for_bytes(&canonical)
}

#[derive(Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    pub(super) staged: StagedAssignment,
    pub(super) spec: LaunchSpec,
}

impl LaunchRequest {
    pub fn new(staged: StagedAssignment, spec: LaunchSpec) -> Self {
        Self { staged, spec }
    }

    pub fn spec(&self) -> &LaunchSpec {
        &self.spec
    }

    pub fn staged(&self) -> &StagedAssignment {
        &self.staged
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedLaunchIdentity {
    pub(super) assignment: AssignmentIdentity,
    pub(super) staged_digest: Digest,
    pub(super) session_id: SessionId,
    pub(super) workspace_id: WorkspaceId,
    pub(super) launch_spec_digest: Digest,
    pub(super) launch_key: IdempotencyKey,
}

impl SubmittedLaunchIdentity {
    pub(super) fn for_launch(staged: &StagedAssignment, spec: &LaunchSpec) -> Self {
        let launch_key = derive_staged_key("launch", staged, spec.digest());
        Self {
            assignment: staged.identity.clone(),
            staged_digest: staged.staged_digest.clone(),
            session_id: staged.session_id.clone(),
            workspace_id: staged.workspace_id.clone(),
            launch_spec_digest: spec.digest().clone(),
            launch_key,
        }
    }

    pub fn assignment(&self) -> &AssignmentIdentity {
        &self.assignment
    }

    pub fn staged_digest(&self) -> &Digest {
        &self.staged_digest
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn launch_key(&self) -> &IdempotencyKey {
        &self.launch_key
    }

    pub fn launch_spec_digest(&self) -> &Digest {
        &self.launch_spec_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchTransportRequest {
    pub target: SshTargetConfig,
    pub submitted: SubmittedLaunchIdentity,
    pub argv: TypedArgv,
    pub stdin: LogicalPath,
    pub deadline: BoundedMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub(super) host_id: HostId,
    pub(super) run_id: RunId,
    pub(super) assignment_id: AssignmentId,
    pub(super) nonce: Nonce,
    pub(super) staged_digest: Digest,
    pub(super) session_id: SessionId,
    pub(super) workspace_id: WorkspaceId,
    pub(super) launch_spec_digest: Digest,
    pub(super) pid: u32,
    pub(super) pgid: u32,
    pub(super) start_token: StartToken,
    pub(super) launch_key: IdempotencyKey,
}

impl ExecutionIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn from_wire(
        host_id: HostId,
        run_id: RunId,
        assignment_id: AssignmentId,
        nonce: Nonce,
        staged_digest: Digest,
        session_id: SessionId,
        workspace_id: WorkspaceId,
        launch_spec_digest: Digest,
        pid: u32,
        pgid: u32,
        start_token: StartToken,
        launch_key: IdempotencyKey,
    ) -> ExecutorResult<Self> {
        if pid == 0 || pgid == 0 {
            return Err(invalid(
                "execution identity",
                "PID and PGID must be nonzero",
            ));
        }
        Ok(Self {
            host_id,
            run_id,
            assignment_id,
            nonce,
            staged_digest,
            session_id,
            workspace_id,
            launch_spec_digest,
            pid,
            pgid,
            start_token,
            launch_key,
        })
    }

    pub fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn assignment_id(&self) -> &AssignmentId {
        &self.assignment_id
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn staged_digest(&self) -> &Digest {
        &self.staged_digest
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn launch_key(&self) -> &IdempotencyKey {
        &self.launch_key
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn launch_spec_digest(&self) -> &Digest {
        &self.launch_spec_digest
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn pgid(&self) -> u32 {
        self.pgid
    }

    pub fn start_token(&self) -> &StartToken {
        &self.start_token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: ExecutionIdentity,
}

impl LaunchReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
    ) -> Self {
        Self {
            protocol_version,
            key,
            identity,
        }
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    #[cfg(test)]
    pub(crate) fn set_protocol_version_for_test(&mut self, value: u32) {
        self.protocol_version = value;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionQuery {
    Submitted(SubmittedLaunchIdentity),
    Known(ExecutionIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequest {
    pub query: ExecutionQuery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusTransportRequest {
    pub target: SshTargetConfig,
    pub key: IdempotencyKey,
    pub query: ExecutionQuery,
}

/// Signal reported by a completed process on the remote Linux execution target.
///
/// This is deliberately distinct from [`ControlSignal`]: process status may report
/// any standard or real-time Linux signal, while control requests are restricted to
/// the protocol's TERM-then-KILL policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSignal(NonZeroU16);

impl ProcessSignal {
    pub fn new(value: u16) -> ExecutorResult<Self> {
        let value = NonZeroU16::new(value).ok_or_else(|| {
            invalid(
                "process terminal signal",
                "must be a nonzero Linux signal number",
            )
        })?;
        if value.get() > MAX_LINUX_PROCESS_SIGNAL {
            return Err(invalid(
                "process terminal signal",
                "exceeds the Linux signal range",
            ));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u16 {
        self.0.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    NotFound,
    Running(ExecutionIdentity),
    Exited {
        identity: ExecutionIdentity,
        code: i32,
    },
    Signaled {
        identity: ExecutionIdentity,
        signal: ProcessSignal,
    },
}

impl ExecutionStatus {
    pub fn identity(&self) -> Option<&ExecutionIdentity> {
        match self {
            Self::NotFound => None,
            Self::Running(identity)
            | Self::Exited { identity, .. }
            | Self::Signaled { identity, .. } => Some(identity),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) query: ExecutionQuery,
    pub(super) status: ExecutionStatus,
}

impl StatusReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        query: ExecutionQuery,
        status: ExecutionStatus,
    ) -> Self {
        Self {
            protocol_version,
            key,
            query,
            status,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn query(&self) -> &ExecutionQuery {
        &self.query
    }

    pub fn status(&self) -> &ExecutionStatus {
        &self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitSpec {
    pub(super) max_wait: BoundedMillis,
}

impl WaitSpec {
    pub fn new(max_wait: BoundedMillis) -> Self {
        Self { max_wait }
    }

    pub fn max_wait(&self) -> BoundedMillis {
        self.max_wait
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitRequest {
    pub(super) identity: ExecutionIdentity,
    pub(super) spec: WaitSpec,
}

impl WaitRequest {
    pub fn new(identity: ExecutionIdentity, spec: WaitSpec) -> Self {
        Self { identity, spec }
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn spec(&self) -> &WaitSpec {
        &self.spec
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitTransportRequest {
    pub target: SshTargetConfig,
    pub key: IdempotencyKey,
    pub identity: ExecutionIdentity,
    pub max_wait: BoundedMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    Exited { code: i32 },
    Signaled { signal: ProcessSignal },
    TimedOut,
    RunningAtDeadline,
}

impl WaitOutcome {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::TimedOut | Self::RunningAtDeadline)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: ExecutionIdentity,
    pub(super) outcome: WaitOutcome,
}

impl WaitReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        outcome: WaitOutcome,
    ) -> Self {
        Self {
            protocol_version,
            key,
            identity,
            outcome,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn outcome(&self) -> &WaitOutcome {
        &self.outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlSignal {
    Term,
    Kill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTransportRequest {
    pub target: SshTargetConfig,
    pub key: IdempotencyKey,
    pub identity: ExecutionIdentity,
    pub signal: ControlSignal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: ExecutionIdentity,
    pub(super) signal: ControlSignal,
}

impl ControlReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        signal: ControlSignal,
    ) -> Self {
        Self {
            protocol_version,
            key,
            identity,
            signal,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn signal(&self) -> ControlSignal {
        self.signal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationPolicy {
    pub(super) term_grace: BoundedMillis,
    pub(super) kill_wait: BoundedMillis,
    digest: Digest,
}

impl TerminationPolicy {
    pub fn new(term_grace: BoundedMillis, kill_wait: BoundedMillis) -> Self {
        let mut canonical = Vec::new();
        append_framed(&mut canonical, &term_grace.get().to_be_bytes());
        append_framed(&mut canonical, &kill_wait.get().to_be_bytes());
        Self {
            term_grace,
            kill_wait,
            digest: Digest::for_bytes(&canonical),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn term_grace(&self) -> BoundedMillis {
        self.term_grace
    }

    pub fn kill_wait(&self) -> BoundedMillis {
        self.kill_wait
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminateRequest {
    pub(super) identity: ExecutionIdentity,
    pub(super) policy: TerminationPolicy,
}

impl TerminateRequest {
    pub fn new(identity: ExecutionIdentity, policy: TerminationPolicy) -> Self {
        Self { identity, policy }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationReceipt {
    pub term: ControlReceipt,
    pub after_term: WaitOutcome,
    pub kill: Option<ControlReceipt>,
    pub after_kill: Option<WaitOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredOutput {
    pub(super) path: LogicalPath,
    pub(super) media_type: String,
    pub(super) max_bytes: u64,
}

impl DeclaredOutput {
    pub fn new(
        path: LogicalPath,
        media_type: impl Into<String>,
        max_bytes: u64,
    ) -> ExecutorResult<Self> {
        let media_type = media_type.into();
        if media_type.is_empty()
            || media_type.len() > MAX_OUTPUT_MEDIA_TYPE_BYTES
            || !media_type.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.')
            })
        {
            return Err(invalid("output media type", "is empty or malformed"));
        }
        if max_bytes == 0 || max_bytes > MAX_OUTPUT_FILE_BYTES {
            return Err(invalid(
                "output byte limit",
                "is zero or exceeds the protocol maximum",
            ));
        }
        Ok(Self {
            path,
            media_type,
            max_bytes,
        })
    }

    pub fn path(&self) -> &LogicalPath {
        &self.path
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn revalidate(&self) -> ExecutorResult<()> {
        Self::new(self.path.clone(), self.media_type.clone(), self.max_bytes).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPolicy {
    pub(super) patch_max_bytes: u64,
    pub(super) changed_paths_max: usize,
    pub(super) assignment_scopes: Vec<LogicalPath>,
    pub(super) declared_outputs: Vec<DeclaredOutput>,
    pub(super) output_aggregate_max_bytes: u64,
    digest: Digest,
}

impl OutputPolicy {
    pub fn new(
        patch_max_bytes: u64,
        changed_paths_max: usize,
        mut assignment_scopes: Vec<LogicalPath>,
        mut declared_outputs: Vec<DeclaredOutput>,
        output_aggregate_max_bytes: u64,
    ) -> ExecutorResult<Self> {
        if patch_max_bytes == 0 || patch_max_bytes > MAX_PATCH_BYTES {
            return Err(invalid(
                "patch byte limit",
                "is zero or exceeds the protocol maximum",
            ));
        }
        if changed_paths_max == 0 || changed_paths_max > MAX_CHANGED_PATHS {
            return Err(invalid(
                "changed path limit",
                "is zero or exceeds the protocol maximum",
            ));
        }
        if assignment_scopes.is_empty() || assignment_scopes.len() > MAX_CHANGED_PATHS {
            return Err(invalid("assignment scopes", "must be nonempty and bounded"));
        }
        if declared_outputs.len() > MAX_DECLARED_OUTPUTS {
            return Err(ExecutorError::LimitExceeded {
                what: "declared output count",
                limit: MAX_DECLARED_OUTPUTS as u64,
            });
        }
        if output_aggregate_max_bytes == 0 || output_aggregate_max_bytes > MAX_OUTPUT_TOTAL_BYTES {
            return Err(invalid(
                "output aggregate byte limit",
                "is zero or exceeds the protocol maximum",
            ));
        }
        let mut declared_max_total = 0_u64;
        for output in &declared_outputs {
            output.revalidate()?;
            declared_max_total = declared_max_total.checked_add(output.max_bytes).ok_or(
                ExecutorError::LimitExceeded {
                    what: "declared output aggregate bounds",
                    limit: output_aggregate_max_bytes,
                },
            )?;
        }
        if declared_max_total > output_aggregate_max_bytes {
            return Err(ExecutorError::LimitExceeded {
                what: "declared output aggregate bounds",
                limit: output_aggregate_max_bytes,
            });
        }
        assignment_scopes.sort();
        reject_duplicates("assignment scope", assignment_scopes.iter())?;
        declared_outputs.sort_by(|left, right| left.path.cmp(&right.path));
        reject_duplicates(
            "declared output path",
            declared_outputs.iter().map(|output| &output.path),
        )?;
        let digest = digest_output_policy(
            patch_max_bytes,
            changed_paths_max,
            &assignment_scopes,
            &declared_outputs,
            output_aggregate_max_bytes,
        );
        Ok(Self {
            patch_max_bytes,
            changed_paths_max,
            assignment_scopes,
            declared_outputs,
            output_aggregate_max_bytes,
            digest,
        })
    }

    pub fn patch_max_bytes(&self) -> u64 {
        self.patch_max_bytes
    }

    pub fn changed_paths_max(&self) -> usize {
        self.changed_paths_max
    }

    pub fn assignment_scopes(&self) -> &[LogicalPath] {
        &self.assignment_scopes
    }

    pub fn declared_outputs(&self) -> &[DeclaredOutput] {
        &self.declared_outputs
    }

    pub fn output_aggregate_max_bytes(&self) -> u64 {
        self.output_aggregate_max_bytes
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn revalidate(&self) -> ExecutorResult<()> {
        let reconstructed = Self::new(
            self.patch_max_bytes,
            self.changed_paths_max,
            self.assignment_scopes.clone(),
            self.declared_outputs.clone(),
            self.output_aggregate_max_bytes,
        )?;
        if reconstructed == *self {
            Ok(())
        } else {
            Err(invalid(
                "output policy",
                "stored canonical digest was modified",
            ))
        }
    }
}

fn digest_output_policy(
    patch_max_bytes: u64,
    changed_paths_max: usize,
    assignment_scopes: &[LogicalPath],
    declared_outputs: &[DeclaredOutput],
    output_aggregate_max_bytes: u64,
) -> Digest {
    let mut canonical = Vec::new();
    append_framed(&mut canonical, &patch_max_bytes.to_be_bytes());
    append_framed(&mut canonical, &(changed_paths_max as u64).to_be_bytes());
    for scope in assignment_scopes {
        append_framed(&mut canonical, b"scope");
        append_framed(&mut canonical, scope.as_str().as_bytes());
    }
    for output in declared_outputs {
        append_framed(&mut canonical, b"output");
        append_framed(&mut canonical, output.path.as_str().as_bytes());
        append_framed(&mut canonical, output.media_type.as_bytes());
        append_framed(&mut canonical, &output.max_bytes.to_be_bytes());
    }
    append_framed(&mut canonical, &output_aggregate_max_bytes.to_be_bytes());
    Digest::for_bytes(&canonical)
}

fn reject_duplicates<'a>(
    what: &'static str,
    values: impl IntoIterator<Item = &'a LogicalPath>,
) -> ExecutorResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(ExecutorError::Duplicate {
                what,
                value: value.to_string(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectRequest {
    pub(super) identity: ExecutionIdentity,
    pub(super) policy: OutputPolicy,
}

impl CollectRequest {
    pub fn new(identity: ExecutionIdentity, policy: OutputPolicy) -> Self {
        Self { identity, policy }
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn policy(&self) -> &OutputPolicy {
        &self.policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionTransportRequest {
    pub target: SshTargetConfig,
    pub key: IdempotencyKey,
    pub identity: ExecutionIdentity,
    pub policy: OutputPolicy,
    pub policy_digest: Digest,
    pub read_limits: TransportReadLimits,
}

/// Mandatory pre-allocation bounds for a transport decoder.
///
/// A production transport must reject an over-limit length prefix before allocating
/// or reading that object. Constructing a bounded artifact after an arbitrary
/// transport already allocated it is not a memory-safety boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportReadLimits {
    pub(super) receipt_max_bytes: u64,
    pub(super) patch_max_bytes: u64,
    pub(super) changed_paths_max: usize,
    pub(super) changed_path_max_bytes: usize,
    pub(super) outputs_max: usize,
    pub(super) output_file_max_bytes: u64,
    pub(super) output_aggregate_max_bytes: u64,
}

impl TransportReadLimits {
    pub(super) fn for_policy(policy: &OutputPolicy) -> ExecutorResult<Self> {
        policy.revalidate()?;
        let receipt_hard_max = receipt_protocol_hard_max()?;
        let changed_path_width = checked_receipt_add(
            MAX_LOGICAL_PATH_BYTES as u64,
            RECEIPT_CHANGED_PATH_FRAMING_BYTES,
            receipt_hard_max,
        )?;
        let changed_path_metadata = (policy.changed_paths_max as u64)
            .checked_mul(changed_path_width)
            .ok_or(ExecutorError::LimitExceeded {
                what: "transport receipt metadata bytes",
                limit: receipt_hard_max,
            })?;
        let mut receipt_max_bytes = RECEIPT_FIXED_FRAMING_BYTES;
        for component in [
            policy.patch_max_bytes,
            policy.output_aggregate_max_bytes,
            changed_path_metadata,
        ] {
            receipt_max_bytes =
                checked_receipt_add(receipt_max_bytes, component, receipt_hard_max)?;
        }
        for output in &policy.declared_outputs {
            for component in [
                RECEIPT_OUTPUT_FRAMING_BYTES,
                output.path.as_str().len() as u64,
                output.media_type.len() as u64,
            ] {
                receipt_max_bytes =
                    checked_receipt_add(receipt_max_bytes, component, receipt_hard_max)?;
            }
        }
        if receipt_max_bytes > receipt_hard_max {
            return Err(ExecutorError::LimitExceeded {
                what: "transport receipt metadata bytes",
                limit: receipt_hard_max,
            });
        }
        Ok(Self {
            receipt_max_bytes,
            patch_max_bytes: policy.patch_max_bytes,
            changed_paths_max: policy.changed_paths_max,
            changed_path_max_bytes: MAX_LOGICAL_PATH_BYTES,
            outputs_max: policy.declared_outputs.len(),
            output_file_max_bytes: policy
                .declared_outputs
                .iter()
                .map(|output| output.max_bytes)
                .max()
                .unwrap_or(1),
            output_aggregate_max_bytes: policy.output_aggregate_max_bytes,
        })
    }

    pub fn receipt_max_bytes(&self) -> u64 {
        self.receipt_max_bytes
    }

    pub fn patch_max_bytes(&self) -> u64 {
        self.patch_max_bytes
    }

    pub fn changed_paths_max(&self) -> usize {
        self.changed_paths_max
    }

    pub fn changed_path_max_bytes(&self) -> usize {
        self.changed_path_max_bytes
    }

    pub fn outputs_max(&self) -> usize {
        self.outputs_max
    }

    pub fn output_file_max_bytes(&self) -> u64 {
        self.output_file_max_bytes
    }

    pub fn output_aggregate_max_bytes(&self) -> u64 {
        self.output_aggregate_max_bytes
    }

    fn revalidate(&self) -> ExecutorResult<()> {
        let receipt_hard_max = receipt_protocol_hard_max()?;
        if self.receipt_max_bytes == 0 || self.receipt_max_bytes > receipt_hard_max {
            return Err(invalid(
                "transport receipt read limit",
                "is zero or exceeds the protocol hard maximum",
            ));
        }
        if self.patch_max_bytes == 0 || self.patch_max_bytes > MAX_PATCH_BYTES {
            return Err(invalid(
                "transport patch read limit",
                "is zero or exceeds the protocol hard maximum",
            ));
        }
        if self.changed_paths_max == 0
            || self.changed_paths_max > MAX_CHANGED_PATHS
            || self.changed_path_max_bytes == 0
            || self.changed_path_max_bytes > MAX_LOGICAL_PATH_BYTES
        {
            return Err(invalid(
                "transport changed-path read limits",
                "are zero or exceed the protocol hard maximum",
            ));
        }
        if self.outputs_max > MAX_DECLARED_OUTPUTS
            || self.output_file_max_bytes == 0
            || self.output_file_max_bytes > MAX_OUTPUT_FILE_BYTES
            || self.output_aggregate_max_bytes == 0
            || self.output_aggregate_max_bytes > MAX_OUTPUT_TOTAL_BYTES
        {
            return Err(invalid(
                "transport output read limits",
                "are inconsistent with the protocol hard maximum",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedBlob {
    pub(super) bytes: Vec<u8>,
    pub(super) declared_size: u64,
    pub(super) digest: Digest,
}

impl CollectedBlob {
    pub fn from_wire_bounded(
        bytes: Vec<u8>,
        declared_size: u64,
        digest: Digest,
        read_limit: u64,
    ) -> ExecutorResult<Self> {
        if read_limit == 0 || read_limit > MAX_PATCH_BYTES.max(MAX_OUTPUT_FILE_BYTES) {
            return Err(invalid(
                "transport blob read limit",
                "is zero or exceeds the protocol hard maximum",
            ));
        }
        if bytes.len() as u64 > read_limit || declared_size > read_limit {
            return Err(ExecutorError::LimitExceeded {
                what: "transport blob bytes",
                limit: read_limit,
            });
        }
        Ok(Self {
            bytes,
            declared_size,
            digest,
        })
    }

    pub fn checksummed(bytes: Vec<u8>, read_limit: u64) -> ExecutorResult<Self> {
        let declared_size = bytes.len() as u64;
        let digest = Digest::for_bytes(&bytes);
        Self::from_wire_bounded(bytes, declared_size, digest, read_limit)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[cfg(test)]
    pub(crate) fn set_digest_for_test(&mut self, digest: Digest) {
        self.digest = digest;
    }

    #[cfg(test)]
    pub(crate) fn set_declared_size_for_test(&mut self, size: u64) {
        self.declared_size = size;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedOutputEnvelope {
    pub(super) path: String,
    pub(super) media_type: String,
    pub(super) blob: CollectedBlob,
}

impl CollectedOutputEnvelope {
    pub fn from_wire(
        path: String,
        media_type: String,
        blob: CollectedBlob,
    ) -> ExecutorResult<Self> {
        if path.is_empty()
            || path.len() > MAX_LOGICAL_PATH_BYTES
            || media_type.len() > MAX_OUTPUT_MEDIA_TYPE_BYTES
        {
            return Err(invalid(
                "collected output envelope",
                "contains an empty or oversized path/media type",
            ));
        }
        Ok(Self {
            path,
            media_type,
            blob,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn blob(&self) -> &CollectedBlob {
        &self.blob
    }

    #[cfg(test)]
    pub(crate) fn set_path_for_test(&mut self, path: impl Into<String>) {
        self.path = path.into();
    }

    #[cfg(test)]
    pub(crate) fn blob_mut_for_test(&mut self) -> &mut CollectedBlob {
        &mut self.blob
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: ExecutionIdentity,
    pub(super) policy_digest: Digest,
    pub(super) patch: CollectedBlob,
    pub(super) changed_paths: Vec<String>,
    pub(super) outputs: Vec<CollectedOutputEnvelope>,
    pub(super) manifest_digest: Digest,
}

impl CollectionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn from_wire_bounded(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        policy_digest: Digest,
        patch: CollectedBlob,
        changed_paths: Vec<String>,
        outputs: Vec<CollectedOutputEnvelope>,
        manifest_digest: Digest,
        limits: &TransportReadLimits,
    ) -> ExecutorResult<Self> {
        limits.revalidate()?;
        if patch.bytes.len() as u64 > limits.patch_max_bytes {
            return Err(ExecutorError::LimitExceeded {
                what: "transport patch bytes",
                limit: limits.patch_max_bytes,
            });
        }
        if changed_paths.len() > limits.changed_paths_max
            || changed_paths
                .iter()
                .any(|path| path.len() > limits.changed_path_max_bytes)
        {
            return Err(ExecutorError::LimitExceeded {
                what: "transport changed-path manifest",
                limit: limits.changed_paths_max as u64,
            });
        }
        if outputs.len() > limits.outputs_max {
            return Err(ExecutorError::LimitExceeded {
                what: "transport output count",
                limit: limits.outputs_max as u64,
            });
        }
        let mut aggregate = 0_u64;
        for output in &outputs {
            if output.blob.bytes.len() as u64 > limits.output_file_max_bytes {
                return Err(ExecutorError::LimitExceeded {
                    what: "transport output file bytes",
                    limit: limits.output_file_max_bytes,
                });
            }
            aggregate = aggregate
                .checked_add(output.blob.bytes.len() as u64)
                .ok_or(ExecutorError::LimitExceeded {
                    what: "transport output aggregate bytes",
                    limit: limits.output_aggregate_max_bytes,
                })?;
        }
        if aggregate > limits.output_aggregate_max_bytes {
            return Err(ExecutorError::LimitExceeded {
                what: "transport output aggregate bytes",
                limit: limits.output_aggregate_max_bytes,
            });
        }
        let mut decoded_payload_bytes = checked_receipt_add(
            RECEIPT_FIXED_FRAMING_BYTES,
            patch.bytes.len() as u64,
            limits.receipt_max_bytes,
        )?;
        for path in &changed_paths {
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                RECEIPT_CHANGED_PATH_FRAMING_BYTES,
                limits.receipt_max_bytes,
            )?;
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                path.len() as u64,
                limits.receipt_max_bytes,
            )?;
        }
        for output in &outputs {
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                RECEIPT_OUTPUT_FRAMING_BYTES,
                limits.receipt_max_bytes,
            )?;
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                output.path.len() as u64,
                limits.receipt_max_bytes,
            )?;
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                output.media_type.len() as u64,
                limits.receipt_max_bytes,
            )?;
            decoded_payload_bytes = checked_receipt_add(
                decoded_payload_bytes,
                output.blob.bytes.len() as u64,
                limits.receipt_max_bytes,
            )?;
        }
        if decoded_payload_bytes > limits.receipt_max_bytes {
            return Err(ExecutorError::LimitExceeded {
                what: "transport receipt bytes",
                limit: limits.receipt_max_bytes,
            });
        }
        Ok(Self {
            protocol_version,
            key,
            identity,
            policy_digest,
            patch,
            changed_paths,
            outputs,
            manifest_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn canonical_manifest_digest(
        protocol_version: u32,
        key: &IdempotencyKey,
        identity: &ExecutionIdentity,
        policy_digest: &Digest,
        patch: &CollectedBlob,
        changed_paths: &[String],
        outputs: &[CollectedOutputEnvelope],
    ) -> Digest {
        digest_collection_manifest(
            protocol_version,
            key,
            identity,
            policy_digest,
            patch,
            changed_paths,
            outputs,
        )
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn patch(&self) -> &CollectedBlob {
        &self.patch
    }

    pub fn changed_paths(&self) -> &[String] {
        &self.changed_paths
    }

    pub fn outputs(&self) -> &[CollectedOutputEnvelope] {
        &self.outputs
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    #[cfg(test)]
    pub(crate) fn patch_mut_for_test(&mut self) -> &mut CollectedBlob {
        &mut self.patch
    }

    #[cfg(test)]
    pub(crate) fn set_changed_paths_for_test(&mut self, paths: Vec<String>) {
        self.changed_paths = paths;
    }

    #[cfg(test)]
    pub(crate) fn outputs_mut_for_test(&mut self) -> &mut Vec<CollectedOutputEnvelope> {
        &mut self.outputs
    }

    #[cfg(test)]
    pub(crate) fn recompute_manifest_digest_for_test(&mut self) {
        self.manifest_digest = digest_collection_manifest(
            self.protocol_version,
            &self.key,
            &self.identity,
            &self.policy_digest,
            &self.patch,
            &self.changed_paths,
            &self.outputs,
        );
    }
}

fn checked_receipt_add(total: u64, addend: u64, limit: u64) -> ExecutorResult<u64> {
    total
        .checked_add(addend)
        .ok_or(ExecutorError::LimitExceeded {
            what: "transport receipt bytes",
            limit,
        })
}

fn receipt_protocol_hard_max() -> ExecutorResult<u64> {
    let changed_path_width = (MAX_LOGICAL_PATH_BYTES as u64)
        .checked_add(RECEIPT_CHANGED_PATH_FRAMING_BYTES)
        .ok_or(ExecutorError::LimitExceeded {
            what: "transport receipt protocol hard maximum",
            limit: u64::MAX,
        })?;
    let changed_path_metadata = (MAX_CHANGED_PATHS as u64)
        .checked_mul(changed_path_width)
        .ok_or(ExecutorError::LimitExceeded {
            what: "transport receipt protocol hard maximum",
            limit: u64::MAX,
        })?;
    let output_width = (MAX_LOGICAL_PATH_BYTES as u64)
        .checked_add(MAX_OUTPUT_MEDIA_TYPE_BYTES as u64)
        .and_then(|value| value.checked_add(RECEIPT_OUTPUT_FRAMING_BYTES))
        .ok_or(ExecutorError::LimitExceeded {
            what: "transport receipt protocol hard maximum",
            limit: u64::MAX,
        })?;
    let output_metadata = (MAX_DECLARED_OUTPUTS as u64)
        .checked_mul(output_width)
        .ok_or(ExecutorError::LimitExceeded {
            what: "transport receipt protocol hard maximum",
            limit: u64::MAX,
        })?;
    [
        MAX_PATCH_BYTES,
        MAX_OUTPUT_TOTAL_BYTES,
        changed_path_metadata,
        output_metadata,
    ]
    .into_iter()
    .try_fold(RECEIPT_FIXED_FRAMING_BYTES, |total, component| {
        total
            .checked_add(component)
            .ok_or(ExecutorError::LimitExceeded {
                what: "transport receipt protocol hard maximum",
                limit: u64::MAX,
            })
    })
}

fn digest_collection_manifest(
    protocol_version: u32,
    key: &IdempotencyKey,
    identity: &ExecutionIdentity,
    policy_digest: &Digest,
    patch: &CollectedBlob,
    changed_paths: &[String],
    outputs: &[CollectedOutputEnvelope],
) -> Digest {
    let mut canonical = Vec::new();
    append_framed(&mut canonical, &protocol_version.to_be_bytes());
    append_framed(&mut canonical, key.as_str().as_bytes());
    append_execution_identity(&mut canonical, identity);
    append_framed(&mut canonical, policy_digest.as_str().as_bytes());
    append_blob(&mut canonical, patch);
    for path in changed_paths {
        append_framed(&mut canonical, b"changed");
        append_framed(&mut canonical, path.as_bytes());
    }
    for output in outputs {
        append_framed(&mut canonical, b"output");
        append_framed(&mut canonical, output.path.as_bytes());
        append_framed(&mut canonical, output.media_type.as_bytes());
        append_blob(&mut canonical, &output.blob);
    }
    Digest::for_bytes(&canonical)
}

fn append_blob(canonical: &mut Vec<u8>, blob: &CollectedBlob) {
    append_framed(canonical, &blob.declared_size.to_be_bytes());
    append_framed(canonical, blob.digest.as_str().as_bytes());
    append_framed(canonical, blob.bytes.as_slice());
}

fn append_execution_identity(canonical: &mut Vec<u8>, identity: &ExecutionIdentity) {
    for value in [
        identity.host_id.as_str(),
        identity.run_id.as_str(),
        identity.assignment_id.as_str(),
        identity.nonce.as_str(),
        identity.staged_digest.as_str(),
        identity.session_id.as_str(),
        identity.workspace_id.as_str(),
        identity.launch_spec_digest.as_str(),
        identity.start_token.as_str(),
        identity.launch_key.as_str(),
    ] {
        append_framed(canonical, value.as_bytes());
    }
    append_framed(canonical, &identity.pid.to_be_bytes());
    append_framed(canonical, &identity.pgid.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedOutput {
    pub(super) path: LogicalPath,
    pub(super) media_type: String,
    pub(super) bytes: Vec<u8>,
    pub(super) digest: Digest,
}

impl CollectedOutput {
    pub fn path(&self) -> &LogicalPath {
        &self.path
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedResult {
    pub(super) identity: ExecutionIdentity,
    pub(super) patch: Vec<u8>,
    pub(super) patch_digest: Digest,
    pub(super) changed_paths: Vec<LogicalPath>,
    pub(super) outputs: Vec<CollectedOutput>,
    pub(super) cleanup: Effect<CleanupReceipt>,
    /// Remote output is candidate evidence only. It is never local containment,
    /// review, validation, merge, or apply evidence.
    pub(super) candidate_evidence_only: bool,
}

impl CollectedResult {
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn patch(&self) -> &[u8] {
        &self.patch
    }

    pub fn patch_digest(&self) -> &Digest {
        &self.patch_digest
    }

    pub fn changed_paths(&self) -> &[LogicalPath] {
        &self.changed_paths
    }

    pub fn outputs(&self) -> &[CollectedOutput] {
        &self.outputs
    }

    pub fn cleanup(&self) -> &Effect<CleanupReceipt> {
        &self.cleanup
    }

    pub fn is_candidate_evidence_only(&self) -> bool {
        self.candidate_evidence_only
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupTransportRequest {
    pub target: SshTargetConfig,
    pub key: IdempotencyKey,
    pub identity: ExecutionIdentity,
    pub workspace_id: WorkspaceId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReceipt {
    pub(super) protocol_version: u32,
    pub(super) key: IdempotencyKey,
    pub(super) identity: ExecutionIdentity,
    pub(super) workspace_id: WorkspaceId,
    pub(super) workspace_removed: bool,
}

impl CleanupReceipt {
    pub fn from_wire(
        protocol_version: u32,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        workspace_id: WorkspaceId,
        workspace_removed: bool,
    ) -> Self {
        Self {
            protocol_version,
            key,
            identity,
            workspace_id,
            workspace_removed,
        }
    }

    pub fn workspace_removed(&self) -> bool {
        self.workspace_removed
    }

    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Stage,
    Launch,
    Status,
    Wait,
    TerminateTerm,
    TerminateGraceWait,
    TerminateKill,
    TerminateKillWait,
    Collect,
    Cleanup,
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stage => "stage",
            Self::Launch => "launch",
            Self::Status => "status",
            Self::Wait => "wait",
            Self::TerminateTerm => "terminate-term",
            Self::TerminateGraceWait => "terminate-grace-wait",
            Self::TerminateKill => "terminate-kill",
            Self::TerminateKillWait => "terminate-kill-wait",
            Self::Collect => "collect",
            Self::Cleanup => "cleanup",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageLookup {
    pub identity: AssignmentIdentity,
    pub manifest_digest: Digest,
    pub stage_key: IdempotencyKey,
    /// Stage has no automatic replay path in wave 1. An operator or a future
    /// helper status endpoint must reconcile this exact binding.
    pub operator_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupLookup {
    pub identity: ExecutionIdentity,
    pub workspace_id: WorkspaceId,
    pub cleanup_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionLookup {
    pub identity: ExecutionIdentity,
    pub policy_digest: Digest,
    pub collection_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationTarget {
    StageOperator(StageLookup),
    Execution(ExecutionQuery),
    Collection(CollectionLookup),
    Cleanup(CleanupLookup),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncertainEffect {
    pub operation: Operation,
    pub key: IdempotencyKey,
    pub reconciliation: ReconciliationTarget,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect<T> {
    Confirmed(T),
    Uncertain(Box<UncertainEffect>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportCall<T> {
    Response(T),
    LostResponse { detail: String },
}

pub(crate) fn derive_assignment_key(
    phase: &str,
    identity: &AssignmentIdentity,
    staged_digest: &Digest,
) -> IdempotencyKey {
    derive_key(
        phase,
        [
            identity.host_id.as_str(),
            identity.run_id.as_str(),
            identity.assignment_id.as_str(),
            identity.nonce.as_str(),
            staged_digest.as_str(),
        ],
    )
}

pub(crate) fn derive_staged_key(
    phase: &str,
    staged: &StagedAssignment,
    launch_spec_digest: &Digest,
) -> IdempotencyKey {
    derive_key(
        phase,
        [
            staged.identity.host_id.as_str(),
            staged.identity.run_id.as_str(),
            staged.identity.assignment_id.as_str(),
            staged.identity.nonce.as_str(),
            staged.staged_digest.as_str(),
            staged.session_id.as_str(),
            staged.workspace_id.as_str(),
            launch_spec_digest.as_str(),
        ],
    )
}

pub(crate) fn derive_submitted_key(
    phase: &str,
    submitted: &SubmittedLaunchIdentity,
) -> IdempotencyKey {
    derive_key(
        phase,
        [
            submitted.assignment.host_id.as_str(),
            submitted.assignment.run_id.as_str(),
            submitted.assignment.assignment_id.as_str(),
            submitted.assignment.nonce.as_str(),
            submitted.staged_digest.as_str(),
            submitted.session_id.as_str(),
            submitted.workspace_id.as_str(),
            submitted.launch_spec_digest.as_str(),
            submitted.launch_key.as_str(),
        ],
    )
}

pub(crate) fn derive_execution_key(phase: &str, identity: &ExecutionIdentity) -> IdempotencyKey {
    let pid = identity.pid.to_string();
    let pgid = identity.pgid.to_string();
    derive_key(
        phase,
        [
            identity.host_id.as_str(),
            identity.run_id.as_str(),
            identity.assignment_id.as_str(),
            identity.nonce.as_str(),
            identity.staged_digest.as_str(),
            identity.session_id.as_str(),
            identity.workspace_id.as_str(),
            identity.launch_spec_digest.as_str(),
            pid.as_str(),
            pgid.as_str(),
            identity.start_token.as_str(),
            identity.launch_key.as_str(),
        ],
    )
}

pub(crate) fn derive_wait_key(
    phase: &str,
    identity: &ExecutionIdentity,
    max_wait: BoundedMillis,
) -> IdempotencyKey {
    let identity_key = derive_execution_key("identity", identity);
    let duration = max_wait.get().to_string();
    derive_key(phase, [identity_key.as_str(), duration.as_str()])
}

pub(crate) fn derive_control_key(
    phase: &str,
    identity: &ExecutionIdentity,
    signal: ControlSignal,
    policy: &TerminationPolicy,
) -> IdempotencyKey {
    let identity_key = derive_execution_key("identity", identity);
    let signal = match signal {
        ControlSignal::Term => "term",
        ControlSignal::Kill => "kill",
    };
    derive_key(
        phase,
        [identity_key.as_str(), signal, policy.digest().as_str()],
    )
}

pub(crate) fn derive_collection_key(
    identity: &ExecutionIdentity,
    policy_digest: &Digest,
) -> IdempotencyKey {
    let identity_key = derive_execution_key("identity", identity);
    derive_key("collect", [identity_key.as_str(), policy_digest.as_str()])
}

pub(crate) fn derive_query_key(phase: &str, query: &ExecutionQuery) -> IdempotencyKey {
    match query {
        ExecutionQuery::Submitted(submitted) => derive_submitted_key(phase, submitted),
        ExecutionQuery::Known(identity) => derive_execution_key(phase, identity),
    }
}
