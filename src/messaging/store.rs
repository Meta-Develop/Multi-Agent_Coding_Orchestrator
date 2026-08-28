//! Strict, bounded append-only storage for durable inter-agent messaging.
//!
//! This journal authenticates corruption, reordering, and content changes with
//! a deterministic HMAC-SHA256 chain under a caller-supplied process-local key.
//! Sender authentication happens before an envelope reaches this storage
//! boundary, and credentials and integrity-key bytes are deliberately absent
//! from every persisted type in this module.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, FromRawFd},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    artifacts::state_auth::sha256_hex,
    hierarchy_ledger::RoleCategory,
    messaging::envelope::{
        GovernedChannel, MessageAddress, MessageEnvelope, MessageId, MessagingLimits,
    },
};

const JOURNAL_FORMAT_VERSION: u32 = 1;
const GENESIS_CHECKSUM: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CHECKSUM_DOMAIN: &[u8] = b"MACO\0messaging-journal-record\0hmac-sha256\0v1\0";
const TAIL_ANCHOR_FORMAT_VERSION: u32 = 1;
const TAIL_ANCHOR_DOMAIN: &[u8] = b"MACO\0messaging-journal-tail-anchor\0hmac-sha256\0v1\0";
const MAX_TAIL_ANCHOR_BYTES: usize = 4_096;
const STORE_INTEGRITY_KEY_BYTES: usize = 32;
const SHA256_BYTES: usize = 32;
const HMAC_BLOCK_BYTES: usize = 64;
const MAX_BROKER_INSTANCE_ID_BYTES: usize = 128;
const MAX_AUTHORITY_IDENTITIES: usize = 65_536;
const HARD_MAX_JOURNAL_RECORDS: usize = 1_000_000;
const HARD_MAX_JOURNAL_BYTES: usize = 512 * 1024 * 1024;

/// Immutable identity and resource limits established by the creation record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreHeader {
    pub(crate) broker_instance_id: String,
    pub(crate) authority_binding: BTreeMap<String, RoleCategory>,
    pub(crate) limits: MessagingLimits,
}

/// Process-local key that authenticates every durable journal record.
///
/// This type deliberately implements neither `Debug`, `Clone`, nor
/// serialization. Callers must derive it from authenticated, non-persisted
/// material and present the same key again when reopening a journal.
pub(crate) struct StoreIntegrityKey([u8; STORE_INTEGRITY_KEY_BYTES]);

impl StoreIntegrityKey {
    pub(crate) fn new(bytes: [u8; STORE_INTEGRITY_KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl Drop for StoreIntegrityKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

/// Events persisted by the messaging broker.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StoreEvent {
    Created {
        broker_instance_id: String,
        authority_binding: BTreeMap<String, RoleCategory>,
        limits: MessagingLimits,
    },
    ChannelCreated {
        channel: GovernedChannel,
    },
    MessageSent {
        envelope: MessageEnvelope,
    },
    DeliveryAttempted {
        message_id: MessageId,
        recipient_id: String,
        attempt: u32,
    },
    Acknowledged {
        message_id: MessageId,
        recipient_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    version: u32,
    sequence: u64,
    previous_checksum: String,
    event: StoreEvent,
    checksum: String,
}

#[derive(Serialize)]
struct ChecksumMaterial<'a> {
    version: u32,
    sequence: u64,
    previous_checksum: &'a str,
    event: &'a StoreEvent,
}

#[derive(Serialize)]
struct BorrowedJournalRecord<'a> {
    version: u32,
    sequence: u64,
    previous_checksum: &'a str,
    event: &'a StoreEvent,
    checksum: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TailAnchor {
    version: u32,
    journal_bytes: u64,
    last_sequence: u64,
    last_checksum: String,
    authentication_tag: String,
}

#[derive(Serialize)]
struct TailAnchorMaterial<'a> {
    version: u32,
    journal_bytes: u64,
    last_sequence: u64,
    last_checksum: &'a str,
}

struct JournalCheckpoint {
    journal_bytes: usize,
    sequence: u64,
    checksum: String,
}

struct PreparedTailAnchor {
    temp_path: PathBuf,
    file: File,
    identity: DataFileIdentity,
    bytes: usize,
}

struct PublishedTailAnchor {
    file: File,
    identity: DataFileIdentity,
    bytes: usize,
}

/// Durable messaging journal errors. Every validation failure is fail-closed.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(
        "messaging journal path is not a normal direct child of an existing directory: {path}"
    )]
    InvalidStorePath { path: PathBuf },
    #[error("messaging journal filesystem safety operation is unsupported: {operation}")]
    UnsupportedFilesystemSafety { operation: &'static str },
    #[error("messaging journal already exists at {path}")]
    AlreadyExists { path: PathBuf },
    #[error("messaging journal is missing at {path}")]
    Missing { path: PathBuf },
    #[error("messaging journal path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("messaging journal is already locked by another writer: {path}")]
    WriterAlreadyActive { path: PathBuf },
    #[error("messaging journal path no longer names the originally opened data file: {path}")]
    DataFileIdentityChanged { path: PathBuf },
    #[error("messaging journal data file has {links} hard links; exactly one is required: {path}")]
    MultipleDataLinks { path: PathBuf, links: u64 },
    #[error("messaging journal tail anchor already exists at {path}")]
    TailAnchorAlreadyExists { path: PathBuf },
    #[error("messaging journal tail-anchor publication is blocked by stale state at {path}")]
    TailAnchorTemporaryExists { path: PathBuf },
    #[error("messaging journal tail anchor is missing at {path}")]
    MissingTailAnchor { path: PathBuf },
    #[error("messaging journal tail anchor is malformed or non-canonical: {detail}")]
    MalformedTailAnchor { detail: String },
    #[error("messaging journal tail anchor authentication failed")]
    TailAnchorAuthenticationFailed,
    #[error("messaging journal tail anchor does not bind an authenticated journal prefix")]
    TailAnchorMismatch,
    #[error("messaging journal I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("messaging journal is empty")]
    EmptyJournal,
    #[error("messaging journal final record is truncated at record index {record_index}")]
    TruncatedFinalRecord { record_index: usize },
    #[error("messaging journal record {record_index} is empty or malformed: {detail}")]
    MalformedRecord { record_index: usize, detail: String },
    #[error("messaging journal record {record_index} is not in canonical byte representation")]
    NonCanonicalRecord { record_index: usize },
    #[error(
        "messaging journal record {record_index} uses unsupported version {found}; expected {expected}"
    )]
    UnsupportedVersion {
        record_index: usize,
        found: u64,
        expected: u32,
    },
    #[error("messaging journal must begin with a Created record")]
    FirstRecordNotCreated,
    #[error("messaging journal has a duplicate Created record at index {record_index}")]
    DuplicateCreated { record_index: usize },
    #[error(
        "messaging journal record {record_index} has sequence {found}; expected deterministic sequence {expected}"
    )]
    OutOfOrderSequence {
        record_index: usize,
        expected: u64,
        found: u64,
    },
    #[error("messaging journal checksum chain mismatch at sequence {sequence}")]
    ChecksumMismatch { sequence: u64 },
    #[error("messaging journal authentication helper returned malformed SHA-256 output")]
    InvalidHashOutput,
    #[error("messaging broker instance identity is not a bounded canonical identifier")]
    InvalidBrokerIdentity,
    #[error("messaging broker instance identity does not match the expected store binding")]
    BrokerBindingMismatch,
    #[error("messaging hierarchy authority identity {agent_id:?} is not bounded canonical text")]
    InvalidAuthorityIdentity { agent_id: String },
    #[error("messaging hierarchy authority binding is empty or exceeds its hard bound")]
    InvalidAuthorityBinding,
    #[error("messaging journal hierarchy authority binding does not match the expected snapshot")]
    AuthorityBindingMismatch,
    #[error("messaging journal limits do not match the expected limits")]
    LimitsMismatch,
    #[error("messaging limits are invalid: {detail}")]
    InvalidLimits { detail: String },
    #[error("messaging journal event is structurally invalid: {detail}")]
    InvalidEvent { detail: String },
    #[error("messaging journal event violates durable state transitions: {detail}")]
    InvalidStateTransition { detail: &'static str },
    #[error("messaging journal event names identity {agent_id:?} outside its authority binding")]
    UnknownEventIdentity { agent_id: String },
    #[error(
        "messaging journal event binds sender {sender_id:?} to a role inconsistent with its authority binding"
    )]
    SenderRoleMismatch { sender_id: String },
    #[error("messaging journal record count {actual} exceeds limit {max}")]
    RecordLimitExceeded { actual: usize, max: usize },
    #[error("messaging journal size {actual} bytes exceeds limit {max} bytes")]
    JournalByteLimitExceeded { actual: usize, max: usize },
    #[error("messaging journal record sequence is exhausted")]
    SequenceExhausted,
    #[error("messaging journal serialization failed: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(
        "messaging journal changed outside this store (expected {expected_bytes} bytes, found {actual_bytes})"
    )]
    ExternalModification {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    #[error(
        "messaging journal contents changed outside this store while retaining its expected {expected_bytes}-byte length"
    )]
    ExternalContentModification { expected_bytes: usize },
    #[error("messaging journal is poisoned after an uncertain write and must be reopened")]
    Poisoned,
}

/// One exclusively managed append handle plus its fully validated replay.
pub(crate) struct MessagingStore {
    binding: StorePathBinding,
    path: PathBuf,
    file: File,
    data_identity: DataFileIdentity,
    anchor_path: PathBuf,
    anchor_file: File,
    anchor_identity: DataFileIdentity,
    anchor_bytes: usize,
    integrity_key: StoreIntegrityKey,
    header: StoreHeader,
    events: Vec<StoreEvent>,
    last_sequence: u64,
    last_checksum: String,
    authenticated_journal_bytes: Vec<u8>,
    journal_bytes: usize,
    poisoned: bool,
    replayed: ReplayedState,
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DataFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DataFileIdentity {
    device: u64,
    file: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DataFileIdentity;

struct StorePathBinding {
    parent_path: PathBuf,
    parent: File,
    parent_identity: DataFileIdentity,
    data_name: OsString,
    anchor_name: OsString,
    temp_name: OsString,
}

impl StorePathBinding {
    fn bind(path: &Path) -> Result<(Self, PathBuf, PathBuf), StoreError> {
        let data_path = absolute_normalized_store_path(path)?;
        let data_name = data_path
            .file_name()
            .filter(|name| is_single_path_component(name))
            .ok_or_else(|| StoreError::InvalidStorePath {
                path: path.to_path_buf(),
            })?
            .to_os_string();
        let parent_path = data_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let anchor_path = tail_anchor_path(&data_path);
        let anchor_name = anchor_path
            .file_name()
            .filter(|name| is_single_path_component(name))
            .ok_or_else(|| StoreError::InvalidStorePath {
                path: path.to_path_buf(),
            })?
            .to_os_string();
        let temp_path = tail_anchor_temp_path(&anchor_path);
        let temp_name = temp_path
            .file_name()
            .filter(|name| is_single_path_component(name))
            .ok_or_else(|| StoreError::InvalidStorePath {
                path: path.to_path_buf(),
            })?
            .to_os_string();
        let parent = open_bound_parent(&parent_path)?;
        let parent_identity = file_identity(&parent, &parent_path)?;
        let binding = Self {
            parent_path,
            parent,
            parent_identity,
            data_name,
            anchor_name,
            temp_name,
        };
        binding.verify_parent()?;
        Ok((binding, data_path, anchor_path))
    }

    fn verify_parent(&self) -> Result<(), StoreError> {
        validate_directory_handle(&self.parent, &self.parent_path)?;
        if file_identity(&self.parent, &self.parent_path)? != self.parent_identity {
            return Err(StoreError::DataFileIdentityChanged {
                path: self.parent_path.clone(),
            });
        }
        let rebound = open_bound_parent(&self.parent_path)?;
        validate_directory_handle(&rebound, &self.parent_path)?;
        if file_identity(&rebound, &self.parent_path)? != self.parent_identity {
            return Err(StoreError::DataFileIdentityChanged {
                path: self.parent_path.clone(),
            });
        }
        Ok(())
    }

    fn child_path(&self, name: &OsStr) -> PathBuf {
        self.parent_path.join(name)
    }

    fn child_exists(&self, name: &OsStr) -> Result<bool, StoreError> {
        self.verify_parent()?;
        #[cfg(unix)]
        {
            let result = unix_child_stat(self.parent.as_raw_fd(), name)?;
            self.verify_parent()?;
            Ok(result.is_some())
        }
        #[cfg(windows)]
        {
            let path = self.child_path(name);
            let result = match std::fs::symlink_metadata(&path) {
                Ok(_) => true,
                Err(source) if source.kind() == io::ErrorKind::NotFound => false,
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "inspecting direct child at",
                        path,
                        source,
                    })
                }
            };
            self.verify_parent()?;
            Ok(result)
        }
        #[cfg(not(any(unix, windows)))]
        Err(StoreError::UnsupportedFilesystemSafety {
            operation: "descriptor-bound child inspection",
        })
    }

    fn validate_child_regular_before_open(
        &self,
        name: &OsStr,
        path: &Path,
    ) -> Result<(), StoreError> {
        self.verify_parent()?;
        #[cfg(unix)]
        {
            let stat =
                unix_child_stat(self.parent.as_raw_fd(), name)?.ok_or_else(|| StoreError::Io {
                    operation: "opening direct child at",
                    path: path.to_path_buf(),
                    source: io::Error::from(io::ErrorKind::NotFound),
                })?;
            validate_unix_regular_single_link(&stat, path)?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            let rebound =
                crate::file_identity::open_windows_path_identity(path).map_err(|source| {
                    StoreError::Io {
                        operation: "opening reparse-resistant direct child at",
                        path: path.to_path_buf(),
                        source,
                    }
                })?;
            if !rebound.metadata.file_type().is_file()
                || rebound.metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(StoreError::NotRegularFile {
                    path: path.to_path_buf(),
                });
            }
            if rebound.number_of_links != 1 {
                return Err(StoreError::MultipleDataLinks {
                    path: path.to_path_buf(),
                    links: u64::from(rebound.number_of_links),
                });
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err(StoreError::UnsupportedFilesystemSafety {
            operation: "no-follow direct-child validation",
        });
        self.verify_parent()
    }

    fn open_data(&self, create_new: bool) -> Result<File, io::Error> {
        self.open_direct(&self.data_name, create_new, true)
    }

    fn open_anchor(&self, name: &OsStr, create_new: bool) -> Result<File, io::Error> {
        self.open_direct(name, create_new, false)
    }

    fn open_direct(&self, name: &OsStr, create_new: bool, append: bool) -> Result<File, io::Error> {
        #[cfg(unix)]
        {
            let name = unix_name(name)?;
            let mut flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            if append {
                flags |= libc::O_APPEND;
            }
            if create_new {
                flags |= libc::O_CREAT | libc::O_EXCL;
            }
            let fd = unsafe { libc::openat(self.parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_fd(fd) })
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(!append)
                .append(append)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            if create_new {
                options.create_new(true);
            }
            options.open(self.child_path(name))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (name, create_new, append);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "descriptor-bound direct-child opens are unsupported",
            ))
        }
    }

    fn validate_named_file(
        &self,
        name: &OsStr,
        file: &File,
        expected_identity: &DataFileIdentity,
    ) -> Result<(), StoreError> {
        self.verify_parent()?;
        let path = self.child_path(name);
        validate_regular_single_link(file, &path)?;
        if file_identity(file, &path)? != *expected_identity {
            return Err(StoreError::DataFileIdentityChanged { path });
        }

        #[cfg(unix)]
        {
            let stat = unix_child_stat(self.parent.as_raw_fd(), name)?
                .ok_or_else(|| StoreError::DataFileIdentityChanged { path: path.clone() })?;
            validate_unix_regular_single_link(&stat, &path)?;
            if DataFileIdentity::from_stat(&stat) != *expected_identity {
                return Err(StoreError::DataFileIdentityChanged { path });
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            let rebound =
                crate::file_identity::open_windows_path_identity(&path).map_err(|source| {
                    StoreError::Io {
                        operation: "reopening direct child without following reparse points at",
                        path: path.clone(),
                        source,
                    }
                })?;
            if !rebound.metadata.file_type().is_file()
                || rebound.metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(StoreError::NotRegularFile { path });
            }
            if rebound.number_of_links != 1 {
                return Err(StoreError::MultipleDataLinks {
                    path,
                    links: u64::from(rebound.number_of_links),
                });
            }
            let rebound_identity = DataFileIdentity {
                device: rebound.identity.device,
                file: rebound.identity.file,
            };
            if rebound_identity != *expected_identity {
                return Err(StoreError::DataFileIdentityChanged { path });
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err(StoreError::UnsupportedFilesystemSafety {
            operation: "name-to-handle identity validation",
        });

        self.verify_parent()
    }

    fn sync_parent(&self) -> Result<(), StoreError> {
        #[cfg(any(unix, windows))]
        self.parent.sync_all().map_err(|source| StoreError::Io {
            operation: "synchronizing bound parent directory",
            path: self.parent_path.clone(),
            source,
        })?;
        #[cfg(not(any(unix, windows)))]
        return Err(StoreError::UnsupportedFilesystemSafety {
            operation: "durable parent-directory synchronization",
        });
        self.verify_parent()
    }

    fn rename_child(
        &self,
        source: &OsStr,
        destination: &OsStr,
        destination_path: &Path,
    ) -> Result<(), StoreError> {
        self.verify_parent()?;
        #[cfg(unix)]
        {
            let source_name = unix_name(source).map_err(|io_error| StoreError::Io {
                operation: "encoding tail-anchor publication source at",
                path: self.child_path(source),
                source: io_error,
            })?;
            let destination_name = unix_name(destination).map_err(|source| StoreError::Io {
                operation: "encoding tail-anchor publication destination at",
                path: destination_path.to_path_buf(),
                source,
            })?;
            if unsafe {
                libc::renameat(
                    self.parent.as_raw_fd(),
                    source_name.as_ptr(),
                    self.parent.as_raw_fd(),
                    destination_name.as_ptr(),
                )
            } != 0
            {
                return Err(StoreError::Io {
                    operation: "atomically replacing tail anchor at",
                    path: destination_path.to_path_buf(),
                    source: io::Error::last_os_error(),
                });
            }
        }
        #[cfg(windows)]
        std::fs::rename(self.child_path(source), destination_path).map_err(|source| {
            StoreError::Io {
                operation: "atomically replacing tail anchor at",
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
        #[cfg(not(any(unix, windows)))]
        return Err(StoreError::UnsupportedFilesystemSafety {
            operation: "bound tail-anchor replacement",
        });
        self.sync_parent()
    }

    fn remove_bound_child(
        &self,
        name: &OsStr,
        file: &File,
        expected_identity: &DataFileIdentity,
    ) -> Result<(), StoreError> {
        let path = self.child_path(name);
        self.validate_named_file(name, file, expected_identity)?;
        #[cfg(target_os = "linux")]
        {
            let source = unix_name(name).map_err(|source| StoreError::Io {
                operation: "encoding recoverable publication name at",
                path: path.clone(),
                source,
            })?;
            let quarantine_name = OsString::from(format!(
                ".maco-messaging-recovery-{:016x}-{:016x}",
                expected_identity.device, expected_identity.inode
            ));
            let quarantine = unix_name(&quarantine_name).map_err(|source| StoreError::Io {
                operation: "encoding recovery quarantine name at",
                path: self.child_path(&quarantine_name),
                source,
            })?;
            if unix_child_stat(self.parent.as_raw_fd(), &quarantine_name)?.is_some() {
                return Err(StoreError::TailAnchorTemporaryExists {
                    path: self.child_path(&quarantine_name),
                });
            }
            if unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    source.as_ptr(),
                    self.parent.as_raw_fd(),
                    quarantine.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(StoreError::Io {
                    operation: "quarantining interrupted tail-anchor publication at",
                    path,
                    source: io::Error::last_os_error(),
                });
            }
            self.validate_named_file(&quarantine_name, file, expected_identity)?;
            if unix_child_stat(self.parent.as_raw_fd(), name)?.is_some() {
                return Err(StoreError::TailAnchorTemporaryExists { path });
            }
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), quarantine.as_ptr(), 0) } != 0 {
                return Err(StoreError::Io {
                    operation: "removing quarantined tail-anchor publication at",
                    path: self.child_path(&quarantine_name),
                    source: io::Error::last_os_error(),
                });
            }
            let handle_stat = unix_file_stat(file).map_err(|source| StoreError::Io {
                operation: "revalidating removed tail-anchor publication handle for",
                path: path.clone(),
                source,
            })?;
            if DataFileIdentity::from_stat(&handle_stat) != *expected_identity
                || handle_stat.st_nlink != 0
            {
                return Err(StoreError::DataFileIdentityChanged { path });
            }
            if unix_child_stat(self.parent.as_raw_fd(), name)?.is_some()
                || unix_child_stat(self.parent.as_raw_fd(), &quarantine_name)?.is_some()
            {
                return Err(StoreError::TailAnchorTemporaryExists { path });
            }
            self.sync_parent()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, file, expected_identity);
            Err(StoreError::UnsupportedFilesystemSafety {
                operation: "identity-bound interrupted-publication removal",
            })
        }
    }
}

pub(crate) fn absolute_normalized_store_path(path: &Path) -> Result<PathBuf, StoreError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| StoreError::Io {
                operation: "resolving current directory for",
                path: path.to_path_buf(),
                source,
            })?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(StoreError::InvalidStorePath {
                        path: path.to_path_buf(),
                    });
                }
            }
        }
    }
    if normalized.file_name().is_none() {
        return Err(StoreError::InvalidStorePath {
            path: path.to_path_buf(),
        });
    }
    Ok(normalized)
}

fn is_single_path_component(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(unix)]
fn unix_name(name: &OsStr) -> Result<std::ffi::CString, io::Error> {
    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem component contains a NUL byte",
        )
    })
}

#[cfg(unix)]
fn unix_file_stat(file: &File) -> Result<libc::stat, io::Error> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn unix_child_stat(parent_fd: i32, name: &OsStr) -> Result<Option<libc::stat>, StoreError> {
    let path = PathBuf::from(name);
    let name = unix_name(name).map_err(|source| StoreError::Io {
        operation: "encoding direct child name at",
        path: path.clone(),
        source,
    })?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(StoreError::Io {
            operation: "inspecting direct child at",
            path,
            source,
        })
    }
}

#[cfg(unix)]
impl DataFileIdentity {
    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

#[cfg(unix)]
fn open_bound_parent(path: &Path) -> Result<File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path).map_err(|source| StoreError::Io {
        operation: "opening bound parent directory at",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(windows)]
fn open_bound_parent(path: &Path) -> Result<File, StoreError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(|source| StoreError::Io {
        operation: "opening reparse-resistant bound parent directory at",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_bound_parent(_path: &Path) -> Result<File, StoreError> {
    Err(StoreError::UnsupportedFilesystemSafety {
        operation: "stable parent-directory binding",
    })
}

fn validate_directory_handle(file: &File, path: &Path) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting bound parent directory at",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(StoreError::InvalidStorePath {
            path: path.to_path_buf(),
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(StoreError::InvalidStorePath {
                path: path.to_path_buf(),
            });
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(StoreError::UnsupportedFilesystemSafety {
        operation: "stable parent-directory validation",
    });
    Ok(())
}

#[cfg(unix)]
fn file_identity(file: &File, path: &Path) -> Result<DataFileIdentity, StoreError> {
    let stat = unix_file_stat(file).map_err(|source| StoreError::Io {
        operation: "inspecting open file identity for",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(DataFileIdentity::from_stat(&stat))
}

#[cfg(windows)]
fn file_identity(file: &File, path: &Path) -> Result<DataFileIdentity, StoreError> {
    let identity =
        crate::file_identity::windows_file_identity(file).map_err(|source| StoreError::Io {
            operation: "inspecting stable Windows file identity for",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(DataFileIdentity {
        device: identity.device,
        file: identity.file,
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File, _path: &Path) -> Result<DataFileIdentity, StoreError> {
    Err(StoreError::UnsupportedFilesystemSafety {
        operation: "stable open-handle identity",
    })
}

fn validate_regular_single_link(file: &File, path: &Path) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting managed regular file for",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    validate_single_data_link(&metadata, path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(StoreError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        let links = crate::file_identity::windows_file_link_count(file).map_err(|source| {
            StoreError::Io {
                operation: "inspecting Windows hard-link count for",
                path: path.to_path_buf(),
                source,
            }
        })?;
        if links != 1 {
            return Err(StoreError::MultipleDataLinks {
                path: path.to_path_buf(),
                links: u64::from(links),
            });
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(StoreError::UnsupportedFilesystemSafety {
        operation: "regular single-link validation",
    });
    Ok(())
}

#[cfg(unix)]
fn validate_unix_regular_single_link(stat: &libc::stat, path: &Path) -> Result<(), StoreError> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(StoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if stat.st_nlink != 1 {
        return Err(StoreError::MultipleDataLinks {
            path: path.to_path_buf(),
            links: stat.st_nlink,
        });
    }
    Ok(())
}

#[derive(Default)]
struct ReplayedState {
    channels: BTreeMap<String, GovernedChannel>,
    messages: BTreeMap<MessageId, ReplayedMessageState>,
    next_message_sequence: u64,
}

struct ReplayedMessageState {
    recipients: BTreeMap<String, crate::messaging::envelope::RecipientDeliveryState>,
}

impl ReplayedState {
    fn new() -> Self {
        Self {
            next_message_sequence: 1,
            ..Self::default()
        }
    }

    fn validate_transition(
        &self,
        event: &StoreEvent,
        header: &StoreHeader,
    ) -> Result<(), StoreError> {
        validate_event_shape(event, header)?;
        match event {
            StoreEvent::Created { .. } => {
                return Err(StoreError::DuplicateCreated { record_index: 0 })
            }
            StoreEvent::ChannelCreated { channel } => {
                if self.channels.contains_key(&channel.channel_id) {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "channel creation is duplicated",
                    });
                }
                if self.channels.len() >= header.limits.max_channels {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "channel count exceeds the configured bound",
                    });
                }
                if !channel.publishers.iter().any(|publisher| {
                    header.authority_binding.get(publisher)
                        == Some(&RoleCategory::DelegatingCoordinator)
                }) {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "channel policy has no delegating coordinator publisher",
                    });
                }
            }
            StoreEvent::MessageSent { envelope } => {
                if self.messages.len() >= header.limits.max_messages {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "message count exceeds the configured bound",
                    });
                }
                if envelope.sequence != self.next_message_sequence {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "message sequence is missing, duplicated, or out of order",
                    });
                }
                let expected_id =
                    format!("{}-{:020}", header.broker_instance_id, envelope.sequence);
                if envelope.id.as_str() != expected_id || self.messages.contains_key(&envelope.id) {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "message id is duplicated or inconsistent with its sequence",
                    });
                }
                if envelope
                    .recipients
                    .values()
                    .any(|state| state.delivery_attempts != 0 || state.acknowledged)
                {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "new message contains pre-mutated delivery state",
                    });
                }
                if let MessageAddress::Channel { channel_id } = &envelope.address {
                    let Some(channel) = self.channels.get(channel_id) else {
                        return Err(StoreError::InvalidStateTransition {
                            detail: "channel message references an unknown channel",
                        });
                    };
                    envelope
                        .validate_for_channel(channel, &header.limits)
                        .map_err(|_| StoreError::InvalidStateTransition {
                            detail: "channel message fan-out differs from channel membership",
                        })?;
                    if !channel.publishers.contains(&envelope.sender_id)
                        || !channel.members.contains(&envelope.sender_id)
                    {
                        return Err(StoreError::InvalidStateTransition {
                            detail: "channel message sender is not an authorized member publisher",
                        });
                    }
                }
                self.next_message_sequence
                    .checked_add(1)
                    .ok_or(StoreError::SequenceExhausted)?;
            }
            StoreEvent::DeliveryAttempted {
                message_id,
                recipient_id,
                attempt,
            } => {
                let Some(message) = self.messages.get(message_id) else {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "delivery attempt references an unknown message",
                    });
                };
                let Some(delivery) = message.recipients.get(recipient_id) else {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "delivery attempt references a non-recipient, acknowledged recipient, or exhausted counter",
                    });
                };
                if delivery.acknowledged {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "delivery attempt references a non-recipient, acknowledged recipient, or exhausted counter",
                    });
                }
                let expected_attempt = delivery.delivery_attempts.checked_add(1).ok_or(
                    StoreError::InvalidStateTransition {
                        detail: "delivery attempt references a non-recipient, acknowledged recipient, or exhausted counter",
                    },
                )?;
                if !usize::try_from(expected_attempt)
                    .is_ok_and(|value| value <= header.limits.max_delivery_attempts)
                {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "delivery attempt references a non-recipient, acknowledged recipient, or exhausted counter",
                    });
                }
                if expected_attempt != *attempt {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "delivery attempts are duplicated or out of order",
                    });
                }
            }
            StoreEvent::Acknowledged {
                message_id,
                recipient_id,
            } => {
                let Some(message) = self.messages.get(message_id) else {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "acknowledgement references an unknown message",
                    });
                };
                let Some(delivery) = message.recipients.get(recipient_id) else {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "acknowledgement references a non-recipient or precedes delivery",
                    });
                };
                if delivery.delivery_attempts == 0 {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "acknowledgement references a non-recipient or precedes delivery",
                    });
                }
                if delivery.acknowledged {
                    return Err(StoreError::InvalidStateTransition {
                        detail: "acknowledgement is duplicated",
                    });
                }
            }
        }
        Ok(())
    }

    fn apply_validated(&mut self, event: &StoreEvent) -> Result<(), StoreError> {
        match event {
            StoreEvent::Created { .. } => {
                return Err(StoreError::DuplicateCreated { record_index: 0 })
            }
            StoreEvent::ChannelCreated { channel } => {
                self.channels
                    .insert(channel.channel_id.clone(), channel.clone());
            }
            StoreEvent::MessageSent { envelope } => {
                self.next_message_sequence = self
                    .next_message_sequence
                    .checked_add(1)
                    .ok_or(StoreError::SequenceExhausted)?;
                self.messages.insert(
                    envelope.id.clone(),
                    ReplayedMessageState {
                        recipients: envelope.recipients.clone(),
                    },
                );
            }
            StoreEvent::DeliveryAttempted {
                message_id,
                recipient_id,
                attempt,
            } => {
                let delivery = self
                    .messages
                    .get_mut(message_id)
                    .and_then(|message| message.recipients.get_mut(recipient_id))
                    .ok_or(StoreError::InvalidStateTransition {
                        detail: "validated delivery transition could not be applied",
                    })?;
                delivery.delivery_attempts = *attempt;
            }
            StoreEvent::Acknowledged {
                message_id,
                recipient_id,
            } => {
                let delivery = self
                    .messages
                    .get_mut(message_id)
                    .and_then(|message| message.recipients.get_mut(recipient_id))
                    .ok_or(StoreError::InvalidStateTransition {
                        detail: "validated acknowledgement transition could not be applied",
                    })?;
                delivery.acknowledged = true;
            }
        }
        Ok(())
    }
}

impl MessagingStore {
    /// Creates a new journal and durably publishes its `Created` record.
    pub(crate) fn create(
        path: impl AsRef<Path>,
        broker_instance_id: impl Into<String>,
        authority_binding: BTreeMap<String, RoleCategory>,
        limits: MessagingLimits,
        integrity_key: StoreIntegrityKey,
    ) -> Result<Self, StoreError> {
        let (binding, path, anchor_path) = StorePathBinding::bind(path.as_ref())?;
        let header = StoreHeader {
            broker_instance_id: broker_instance_id.into(),
            authority_binding,
            limits,
        };
        validate_header(&header)?;

        let created = StoreEvent::Created {
            broker_instance_id: header.broker_instance_id.clone(),
            authority_binding: header.authority_binding.clone(),
            limits: header.limits.clone(),
        };
        let initial_checksum = record_checksum(
            &integrity_key,
            JOURNAL_FORMAT_VERSION,
            0,
            GENESIS_CHECKSUM,
            &created,
        )?;
        let initial_bytes = encoded_record_bytes(&integrity_key, 0, GENESIS_CHECKSUM, &created)?;
        if initial_bytes.len() > header.limits.max_journal_bytes {
            return Err(StoreError::JournalByteLimitExceeded {
                actual: initial_bytes.len(),
                max: header.limits.max_journal_bytes,
            });
        }

        ensure_tail_anchor_temp_absent(&binding, &anchor_path)?;
        if binding.child_exists(&binding.anchor_name)? {
            return Err(StoreError::TailAnchorAlreadyExists { path: anchor_path });
        }

        let mut file = binding
            .open_data(true)
            .map_err(|source| match source.kind() {
                io::ErrorKind::AlreadyExists => StoreError::AlreadyExists { path: path.clone() },
                _ => StoreError::Io {
                    operation: "creating",
                    path: path.clone(),
                    source,
                },
            })?;
        validate_regular_single_link(&file, &path)?;
        acquire_data_lock(&file, &path)?;
        let initial_data_identity = file_identity(&file, &path)?;
        validate_named_file_identity(
            &binding,
            &binding.data_name,
            &path,
            &file,
            &initial_data_identity,
        )?;

        let mut anchor_file = match binding.open_anchor(&binding.anchor_name, true) {
            Ok(file) => file,
            Err(source) => {
                remove_new_empty_data_best_effort(
                    &binding,
                    &binding.data_name,
                    &path,
                    &file,
                    &initial_data_identity,
                );
                return Err(match source.kind() {
                    io::ErrorKind::AlreadyExists => {
                        StoreError::TailAnchorAlreadyExists { path: anchor_path }
                    }
                    _ => StoreError::Io {
                        operation: "creating tail anchor for",
                        path: anchor_path,
                        source,
                    },
                });
            }
        };
        validate_regular_single_link(&anchor_file, &anchor_path)?;

        let (anchor_bytes, anchor_identity) = write_new_tail_anchor(
            &binding,
            &binding.anchor_name,
            &mut anchor_file,
            &anchor_path,
            &integrity_key,
            initial_bytes.len(),
            0,
            &initial_checksum,
        )?;

        // Persist both directory entries and the fully authenticated anchor
        // before the initial journal record. Once the journal sync completes,
        // there is therefore never an empty/partial anchor to strand it.
        binding.sync_parent()?;
        validate_named_file_identity(
            &binding,
            &binding.data_name,
            &path,
            &file,
            &initial_data_identity,
        )?;
        file.write_all(&initial_bytes)
            .map_err(|source| StoreError::Io {
                operation: "writing initial record to",
                path: path.clone(),
                source,
            })?;
        file.flush().map_err(|source| StoreError::Io {
            operation: "flushing initial record to",
            path: path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            operation: "synchronizing initial record to",
            path: path.clone(),
            source,
        })?;
        validate_regular_single_link(&file, &path)?;
        let data_identity = file_identity(&file, &path)?;
        validate_named_file_identity(&binding, &binding.data_name, &path, &file, &data_identity)?;

        let journal_bytes = initial_bytes.len();
        let mut store = Self {
            binding,
            path,
            file,
            data_identity,
            anchor_path,
            anchor_file,
            anchor_identity,
            anchor_bytes,
            integrity_key,
            header,
            events: vec![created],
            last_sequence: 0,
            last_checksum: initial_checksum.clone(),
            authenticated_journal_bytes: initial_bytes,
            journal_bytes,
            poisoned: false,
            replayed: ReplayedState::new(),
        };
        store.binding.sync_parent()?;
        store.validate_journal_checkpoint(journal_bytes, None)?;
        store.verify_anchor_checkpoint(0, &initial_checksum, journal_bytes)?;
        Ok(store)
    }

    /// Opens and completely validates an existing journal before returning it.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        expected_broker_binding: &str,
        expected_authority_binding: &BTreeMap<String, RoleCategory>,
        expected_limits: &MessagingLimits,
        integrity_key: StoreIntegrityKey,
    ) -> Result<Self, StoreError> {
        let (binding, path, anchor_path) = StorePathBinding::bind(path.as_ref())?;
        validate_limits(expected_limits)?;
        validate_authority_binding(
            expected_authority_binding,
            expected_limits.max_identifier_bytes,
        )?;
        if !is_canonical_identifier(expected_broker_binding, MAX_BROKER_INSTANCE_ID_BYTES) {
            return Err(StoreError::InvalidBrokerIdentity);
        }

        if !binding.child_exists(&binding.data_name)? {
            return Err(StoreError::Missing { path });
        }
        binding.validate_child_regular_before_open(&binding.data_name, &path)?;
        let mut file = binding.open_data(false).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                StoreError::Missing { path: path.clone() }
            } else {
                StoreError::Io {
                    operation: "opening no-follow journal at",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let metadata = file.metadata().map_err(|source| StoreError::Io {
            operation: "inspecting",
            path: path.clone(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(StoreError::NotRegularFile { path });
        }
        acquire_data_lock(&file, &path)?;
        validate_regular_single_link(&file, &path)?;
        let data_identity = file_identity(&file, &path)?;
        validate_named_file_identity(&binding, &binding.data_name, &path, &file, &data_identity)?;
        let file_bytes =
            usize::try_from(metadata.len()).map_err(|_| StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: expected_limits.max_journal_bytes,
            })?;
        if file_bytes > expected_limits.max_journal_bytes {
            return Err(StoreError::JournalByteLimitExceeded {
                actual: file_bytes,
                max: expected_limits.max_journal_bytes,
            });
        }
        if file_bytes == 0 {
            return Err(StoreError::EmptyJournal);
        }

        run_after_journal_metadata_hook(&path);
        let read_limit = expected_limits.max_journal_bytes.checked_add(1).ok_or(
            StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: expected_limits.max_journal_bytes,
            },
        )?;
        let read_limit =
            u64::try_from(read_limit).map_err(|_| StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: expected_limits.max_journal_bytes,
            })?;
        let mut bytes = Vec::with_capacity(file_bytes);
        Read::by_ref(&mut file)
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|source| StoreError::Io {
                operation: "reading",
                path: path.clone(),
                source,
            })?;
        if bytes.len() > expected_limits.max_journal_bytes {
            return Err(StoreError::JournalByteLimitExceeded {
                actual: bytes.len(),
                max: expected_limits.max_journal_bytes,
            });
        }
        if bytes.len() != file_bytes {
            return Err(StoreError::ExternalModification {
                expected_bytes: file_bytes,
                actual_bytes: bytes.len(),
            });
        }
        validate_named_file_identity(&binding, &binding.data_name, &path, &file, &data_identity)?;

        if !binding.child_exists(&binding.anchor_name)? {
            return Err(StoreError::MissingTailAnchor {
                path: anchor_path.clone(),
            });
        }
        binding.validate_child_regular_before_open(&binding.anchor_name, &anchor_path)?;
        let mut anchor_file =
            binding
                .open_anchor(&binding.anchor_name, false)
                .map_err(|source| {
                    if source.kind() == io::ErrorKind::NotFound {
                        StoreError::MissingTailAnchor {
                            path: anchor_path.clone(),
                        }
                    } else {
                        StoreError::Io {
                            operation: "opening no-follow tail anchor at",
                            path: anchor_path.clone(),
                            source,
                        }
                    }
                })?;
        let anchor_metadata = anchor_file.metadata().map_err(|source| StoreError::Io {
            operation: "inspecting tail anchor for",
            path: anchor_path.clone(),
            source,
        })?;
        if !anchor_metadata.is_file() {
            return Err(StoreError::NotRegularFile { path: anchor_path });
        }
        validate_regular_single_link(&anchor_file, &anchor_path)?;
        let mut anchor_identity = file_identity(&anchor_file, &anchor_path)?;
        validate_named_file_identity(
            &binding,
            &binding.anchor_name,
            &anchor_path,
            &anchor_file,
            &anchor_identity,
        )?;
        let newline_count = bytes.iter().filter(|byte| **byte == b'\n').count();
        if !bytes.ends_with(b"\n") {
            return Err(StoreError::TruncatedFinalRecord {
                record_index: newline_count,
            });
        }
        if newline_count > expected_limits.max_journal_records {
            return Err(StoreError::RecordLimitExceeded {
                actual: newline_count,
                max: expected_limits.max_journal_records,
            });
        }

        let mut events = Vec::with_capacity(newline_count);
        let mut header = None;
        let mut previous_checksum = GENESIS_CHECKSUM.to_string();
        let mut last_sequence = 0;
        let mut replayed = ReplayedState::new();
        let mut checkpoints = Vec::with_capacity(newline_count);
        let mut journal_offset = 0_usize;
        for (record_index, line) in bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .enumerate()
        {
            if line.is_empty() {
                return Err(StoreError::MalformedRecord {
                    record_index,
                    detail: "blank JSONL record".to_string(),
                });
            }
            let value: Value =
                serde_json::from_slice(line).map_err(|error| StoreError::MalformedRecord {
                    record_index,
                    detail: error.to_string(),
                })?;
            let version = value
                .get("version")
                .and_then(Value::as_u64)
                .ok_or_else(|| StoreError::MalformedRecord {
                    record_index,
                    detail: "missing or non-integer record version".to_string(),
                })?;
            if version != u64::from(JOURNAL_FORMAT_VERSION) {
                return Err(StoreError::UnsupportedVersion {
                    record_index,
                    found: version,
                    expected: JOURNAL_FORMAT_VERSION,
                });
            }
            let record: JournalRecord =
                serde_json::from_value(value).map_err(|error| StoreError::MalformedRecord {
                    record_index,
                    detail: error.to_string(),
                })?;
            let canonical = serde_json::to_vec(&record).map_err(StoreError::Serialization)?;
            if canonical != line {
                return Err(StoreError::NonCanonicalRecord { record_index });
            }
            let expected_sequence =
                u64::try_from(record_index).map_err(|_| StoreError::SequenceExhausted)?;
            if record.sequence != expected_sequence {
                return Err(StoreError::OutOfOrderSequence {
                    record_index,
                    expected: expected_sequence,
                    found: record.sequence,
                });
            }
            if !is_canonical_authentication_tag(&record.previous_checksum)
                || !constant_time_eq(
                    record.previous_checksum.as_bytes(),
                    previous_checksum.as_bytes(),
                )
            {
                return Err(StoreError::ChecksumMismatch {
                    sequence: record.sequence,
                });
            }
            let expected_checksum = record_checksum(
                &integrity_key,
                record.version,
                record.sequence,
                &record.previous_checksum,
                &record.event,
            )?;
            if !is_canonical_authentication_tag(&record.checksum)
                || !constant_time_eq(record.checksum.as_bytes(), expected_checksum.as_bytes())
            {
                return Err(StoreError::ChecksumMismatch {
                    sequence: record.sequence,
                });
            }

            if record_index == 0 {
                let StoreEvent::Created {
                    broker_instance_id,
                    authority_binding,
                    limits,
                } = &record.event
                else {
                    return Err(StoreError::FirstRecordNotCreated);
                };
                let recovered_header = StoreHeader {
                    broker_instance_id: broker_instance_id.clone(),
                    authority_binding: authority_binding.clone(),
                    limits: limits.clone(),
                };
                validate_header(&recovered_header)?;
                let generation = recovered_header
                    .broker_instance_id
                    .strip_prefix(expected_broker_binding)
                    .and_then(|suffix| suffix.strip_prefix('-'));
                if generation.is_none_or(str::is_empty) {
                    return Err(StoreError::BrokerBindingMismatch);
                }
                if recovered_header.authority_binding != *expected_authority_binding {
                    return Err(StoreError::AuthorityBindingMismatch);
                }
                if recovered_header.limits != *expected_limits {
                    return Err(StoreError::LimitsMismatch);
                }
                header = Some(recovered_header);
            } else {
                if matches!(record.event, StoreEvent::Created { .. }) {
                    return Err(StoreError::DuplicateCreated { record_index });
                }
                let recovered_header = header.as_ref().ok_or(StoreError::FirstRecordNotCreated)?;
                replayed.validate_transition(&record.event, recovered_header)?;
                replayed.apply_validated(&record.event)?;
            }

            journal_offset = journal_offset.checked_add(line.len() + 1).ok_or(
                StoreError::JournalByteLimitExceeded {
                    actual: usize::MAX,
                    max: expected_limits.max_journal_bytes,
                },
            )?;
            previous_checksum = record.checksum;
            last_sequence = record.sequence;
            checkpoints.push(JournalCheckpoint {
                journal_bytes: journal_offset,
                sequence: last_sequence,
                checksum: previous_checksum.clone(),
            });
            events.push(record.event);
        }
        let header = header.ok_or(StoreError::FirstRecordNotCreated)?;

        let anchor = read_tail_anchor(&mut anchor_file, &anchor_path, &integrity_key)?;
        validate_named_file_identity(
            &binding,
            &binding.anchor_name,
            &anchor_path,
            &anchor_file,
            &anchor_identity,
        )?;
        let latest = checkpoints
            .last()
            .ok_or(StoreError::FirstRecordNotCreated)?;
        let committed_anchor_matches_latest = tail_anchor_matches_checkpoint(&anchor, latest);
        let committed_anchor_matches_prefix = anchor.journal_bytes < file_bytes as u64
            && checkpoints
                .iter()
                .any(|checkpoint| tail_anchor_matches_checkpoint(&anchor, checkpoint));
        if !committed_anchor_matches_latest && !committed_anchor_matches_prefix {
            return Err(StoreError::TailAnchorMismatch);
        }

        let recovered_publication = recover_tail_anchor_temp(
            &binding,
            &anchor_file,
            &anchor_identity,
            &anchor_path,
            &integrity_key,
            &checkpoints,
        )?;
        let anchor_bytes = if let Some(published) = recovered_publication {
            anchor_file = published.file;
            anchor_identity = published.identity;
            published.bytes
        } else if committed_anchor_matches_latest {
            usize::try_from(anchor_metadata.len()).map_err(|_| StoreError::MalformedTailAnchor {
                detail: "tail anchor length is not representable".to_string(),
            })?
        } else {
            let published = replace_tail_anchor(
                &binding,
                &anchor_file,
                &anchor_identity,
                &anchor_path,
                &integrity_key,
                latest.journal_bytes,
                latest.sequence,
                &latest.checksum,
            )?;
            anchor_file = published.file;
            anchor_identity = published.identity;
            published.bytes
        };

        let mut store = Self {
            binding,
            path,
            file,
            data_identity,
            anchor_path,
            anchor_file,
            anchor_identity,
            anchor_bytes,
            integrity_key,
            header,
            events,
            last_sequence,
            last_checksum: previous_checksum.clone(),
            authenticated_journal_bytes: bytes,
            journal_bytes: file_bytes,
            poisoned: false,
            replayed,
        };
        store.validate_journal_checkpoint(file_bytes, None)?;
        store.verify_anchor_checkpoint(last_sequence, &previous_checksum, file_bytes)?;
        Ok(store)
    }

    /// Appends, flushes, and synchronizes one complete newline-terminated event.
    pub(crate) fn append(&mut self, event: StoreEvent) -> Result<(), StoreError> {
        if matches!(event, StoreEvent::Created { .. }) {
            return Err(StoreError::DuplicateCreated {
                record_index: self.events.len(),
            });
        }
        self.append_record(event)
    }

    pub(crate) fn header(&self) -> &StoreHeader {
        &self.header
    }

    /// Includes the initial `Created` event at index/sequence zero.
    pub(crate) fn events(&self) -> &[StoreEvent] {
        &self.events
    }

    pub(crate) fn exists(path: impl AsRef<Path>) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn append_record(&mut self, event: StoreEvent) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        self.verify_current_path_and_length()?;

        let next_count =
            self.events
                .len()
                .checked_add(1)
                .ok_or(StoreError::RecordLimitExceeded {
                    actual: usize::MAX,
                    max: self.header.limits.max_journal_records,
                })?;
        if next_count > self.header.limits.max_journal_records {
            return Err(StoreError::RecordLimitExceeded {
                actual: next_count,
                max: self.header.limits.max_journal_records,
            });
        }

        let sequence = self
            .last_sequence
            .checked_add(1)
            .ok_or(StoreError::SequenceExhausted)?;
        let checksum = record_checksum(
            &self.integrity_key,
            JOURNAL_FORMAT_VERSION,
            sequence,
            &self.last_checksum,
            &event,
        )?;
        let record = JournalRecord {
            version: JOURNAL_FORMAT_VERSION,
            sequence,
            previous_checksum: self.last_checksum.clone(),
            event,
            checksum,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(StoreError::Serialization)?;
        bytes.push(b'\n');
        let prospective_bytes = self.journal_bytes.checked_add(bytes.len()).ok_or(
            StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: self.header.limits.max_journal_bytes,
            },
        )?;
        if prospective_bytes > self.header.limits.max_journal_bytes {
            return Err(StoreError::JournalByteLimitExceeded {
                actual: prospective_bytes,
                max: self.header.limits.max_journal_bytes,
            });
        }
        self.replayed
            .validate_transition(&record.event, &self.header)?;

        if let Err(source) = self.file.write_all(&bytes) {
            self.poisoned = true;
            return Err(StoreError::Io {
                operation: "appending",
                path: self.path.clone(),
                source,
            });
        }
        if let Err(source) = self.file.flush() {
            self.poisoned = true;
            return Err(StoreError::Io {
                operation: "flushing",
                path: self.path.clone(),
                source,
            });
        }
        if let Err(source) = self.file.sync_all() {
            self.poisoned = true;
            return Err(StoreError::Io {
                operation: "synchronizing",
                path: self.path.clone(),
                source,
            });
        }
        run_after_journal_sync_hook(&self.path);
        if let Err(error) = self.validate_journal_checkpoint(prospective_bytes, Some(&bytes)) {
            self.poisoned = true;
            return Err(error);
        }

        let published = match replace_tail_anchor(
            &self.binding,
            &self.anchor_file,
            &self.anchor_identity,
            &self.anchor_path,
            &self.integrity_key,
            prospective_bytes,
            record.sequence,
            &record.checksum,
        ) {
            Ok(published) => published,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.anchor_file = published.file;
        self.anchor_identity = published.identity;
        self.anchor_bytes = published.bytes;

        if let Err(error) = self
            .validate_journal_checkpoint(prospective_bytes, Some(&bytes))
            .and_then(|()| {
                self.verify_anchor_checkpoint(record.sequence, &record.checksum, prospective_bytes)
            })
        {
            self.poisoned = true;
            return Err(error);
        }

        self.last_sequence = record.sequence;
        self.last_checksum = record.checksum;
        self.authenticated_journal_bytes.extend_from_slice(&bytes);
        self.journal_bytes = prospective_bytes;
        if let Err(error) = self.replayed.apply_validated(&record.event) {
            self.poisoned = true;
            return Err(error);
        }
        self.events.push(record.event);
        Ok(())
    }

    fn verify_current_path_and_length(&mut self) -> Result<(), StoreError> {
        if let Err(error) = self.validate_journal_checkpoint(self.journal_bytes, None) {
            self.poisoned = true;
            return Err(error);
        }

        if let Err(error) = self.verify_current_anchor() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn verify_current_anchor(&mut self) -> Result<(), StoreError> {
        let actual_bytes = usize::try_from(
            self.anchor_file
                .metadata()
                .map_err(|source| StoreError::Io {
                    operation: "revalidating tail anchor for",
                    path: self.anchor_path.clone(),
                    source,
                })?
                .len(),
        )
        .map_err(|_| StoreError::MalformedTailAnchor {
            detail: "tail anchor length is not representable".to_string(),
        })?;
        if actual_bytes != self.anchor_bytes {
            return Err(StoreError::TailAnchorMismatch);
        }
        validate_named_file_identity(
            &self.binding,
            &self.binding.anchor_name,
            &self.anchor_path,
            &self.anchor_file,
            &self.anchor_identity,
        )?;
        if self.events.is_empty() {
            if actual_bytes == 0 {
                return Ok(());
            }
            return Err(StoreError::TailAnchorMismatch);
        }
        let anchor = read_tail_anchor(
            &mut self.anchor_file,
            &self.anchor_path,
            &self.integrity_key,
        )?;
        validate_named_file_identity(
            &self.binding,
            &self.binding.anchor_name,
            &self.anchor_path,
            &self.anchor_file,
            &self.anchor_identity,
        )?;
        if anchor.journal_bytes != u64::try_from(self.journal_bytes).unwrap_or(u64::MAX)
            || anchor.last_sequence != self.last_sequence
            || !constant_time_eq(
                anchor.last_checksum.as_bytes(),
                self.last_checksum.as_bytes(),
            )
        {
            return Err(StoreError::TailAnchorMismatch);
        }
        Ok(())
    }

    fn validate_journal_checkpoint(
        &self,
        expected_bytes: usize,
        prospective_record: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        if expected_bytes > self.header.limits.max_journal_bytes
            || expected_bytes > HARD_MAX_JOURNAL_BYTES
        {
            return Err(StoreError::JournalByteLimitExceeded {
                actual: expected_bytes,
                max: self.header.limits.max_journal_bytes,
            });
        }
        let prospective_bytes = prospective_record.map_or(0, <[u8]>::len);
        let authenticated_bytes = self
            .authenticated_journal_bytes
            .len()
            .checked_add(prospective_bytes)
            .ok_or(StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: self.header.limits.max_journal_bytes,
            })?;
        if self.authenticated_journal_bytes.len() != self.journal_bytes
            || authenticated_bytes != expected_bytes
        {
            return Err(StoreError::InvalidStateTransition {
                detail: "authenticated in-memory journal checkpoint is inconsistent",
            });
        }
        validate_named_file_identity(
            &self.binding,
            &self.binding.data_name,
            &self.path,
            &self.file,
            &self.data_identity,
        )?;
        let actual_bytes = usize::try_from(
            self.file
                .metadata()
                .map_err(|source| StoreError::Io {
                    operation: "revalidating synchronized journal for",
                    path: self.path.clone(),
                    source,
                })?
                .len(),
        )
        .unwrap_or(usize::MAX);
        if actual_bytes != expected_bytes {
            return Err(StoreError::ExternalModification {
                expected_bytes,
                actual_bytes,
            });
        }

        let mut reader = self.file.try_clone().map_err(|source| StoreError::Io {
            operation: "cloning synchronized journal handle for authenticated verification of",
            path: self.path.clone(),
            source,
        })?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|source| StoreError::Io {
                operation: "seeking synchronized journal for authenticated verification of",
                path: self.path.clone(),
                source,
            })?;
        let bounded_read =
            expected_bytes
                .checked_add(1)
                .ok_or(StoreError::JournalByteLimitExceeded {
                    actual: usize::MAX,
                    max: self.header.limits.max_journal_bytes,
                })?;
        let bounded_read =
            u64::try_from(bounded_read).map_err(|_| StoreError::JournalByteLimitExceeded {
                actual: usize::MAX,
                max: self.header.limits.max_journal_bytes,
            })?;
        let mut reader = reader.take(bounded_read);
        self.compare_authenticated_bytes(
            &mut reader,
            &self.authenticated_journal_bytes,
            expected_bytes,
        )?;
        if let Some(record) = prospective_record {
            self.compare_authenticated_bytes(&mut reader, record, expected_bytes)?;
        }
        let mut extra = [0_u8; 1];
        match reader.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => {
                return Err(StoreError::ExternalModification {
                    expected_bytes,
                    actual_bytes: expected_bytes.saturating_add(1),
                })
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "checking authenticated journal bound for",
                    path: self.path.clone(),
                    source,
                })
            }
        }

        validate_named_file_identity(
            &self.binding,
            &self.binding.data_name,
            &self.path,
            &self.file,
            &self.data_identity,
        )?;
        let final_bytes = usize::try_from(
            self.file
                .metadata()
                .map_err(|source| StoreError::Io {
                    operation: "revalidating authenticated journal length for",
                    path: self.path.clone(),
                    source,
                })?
                .len(),
        )
        .unwrap_or(usize::MAX);
        if final_bytes != expected_bytes {
            return Err(StoreError::ExternalModification {
                expected_bytes,
                actual_bytes: final_bytes,
            });
        }
        self.binding.verify_parent()
    }

    fn compare_authenticated_bytes(
        &self,
        reader: &mut impl Read,
        expected: &[u8],
        expected_journal_bytes: usize,
    ) -> Result<(), StoreError> {
        let mut observed = [0_u8; 8 * 1024];
        for expected_chunk in expected.chunks(observed.len()) {
            let observed_chunk = &mut observed[..expected_chunk.len()];
            if let Err(source) = reader.read_exact(observed_chunk) {
                if source.kind() == io::ErrorKind::UnexpectedEof {
                    let actual_bytes = self
                        .file
                        .metadata()
                        .ok()
                        .and_then(|metadata| usize::try_from(metadata.len()).ok())
                        .unwrap_or(usize::MAX);
                    return Err(StoreError::ExternalModification {
                        expected_bytes: expected_journal_bytes,
                        actual_bytes,
                    });
                }
                return Err(StoreError::Io {
                    operation: "authenticating synchronized journal contents for",
                    path: self.path.clone(),
                    source,
                });
            }
            if observed_chunk != expected_chunk {
                return Err(StoreError::ExternalContentModification {
                    expected_bytes: expected_journal_bytes,
                });
            }
        }
        Ok(())
    }

    fn verify_anchor_checkpoint(
        &mut self,
        expected_sequence: u64,
        expected_checksum: &str,
        expected_journal_bytes: usize,
    ) -> Result<(), StoreError> {
        validate_named_file_identity(
            &self.binding,
            &self.binding.anchor_name,
            &self.anchor_path,
            &self.anchor_file,
            &self.anchor_identity,
        )?;
        let anchor = read_tail_anchor(
            &mut self.anchor_file,
            &self.anchor_path,
            &self.integrity_key,
        )?;
        validate_named_file_identity(
            &self.binding,
            &self.binding.anchor_name,
            &self.anchor_path,
            &self.anchor_file,
            &self.anchor_identity,
        )?;
        if usize::try_from(anchor.journal_bytes).ok() != Some(expected_journal_bytes)
            || anchor.last_sequence != expected_sequence
            || !constant_time_eq(
                anchor.last_checksum.as_bytes(),
                expected_checksum.as_bytes(),
            )
        {
            return Err(StoreError::TailAnchorMismatch);
        }
        self.binding.verify_parent()
    }
}

#[cfg(test)]
type AfterJournalSyncHook = Option<Box<dyn FnOnce(&Path)>>;

#[cfg(test)]
type AfterJournalMetadataHook = Option<Box<dyn FnOnce(&Path)>>;

#[cfg(test)]
thread_local! {
    static AFTER_JOURNAL_SYNC_HOOK: std::cell::RefCell<AfterJournalSyncHook> =
        std::cell::RefCell::new(None);
    static AFTER_JOURNAL_METADATA_HOOK: std::cell::RefCell<AfterJournalMetadataHook> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_after_journal_metadata_hook(hook: impl FnOnce(&Path) + 'static) {
    AFTER_JOURNAL_METADATA_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_journal_metadata_hook(path: &Path) {
    let hook = AFTER_JOURNAL_METADATA_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_after_journal_metadata_hook(_path: &Path) {}

#[cfg(test)]
fn set_after_journal_sync_hook(hook: impl FnOnce(&Path) + 'static) {
    AFTER_JOURNAL_SYNC_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_journal_sync_hook(path: &Path) {
    let hook = AFTER_JOURNAL_SYNC_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_after_journal_sync_hook(_path: &Path) {}

fn acquire_data_lock(file: &File, path: &Path) -> Result<(), StoreError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::WriterAlreadyActive {
            path: path.to_path_buf(),
        }),
        Err(std::fs::TryLockError::Error(source)) => Err(StoreError::Io {
            operation: "locking",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn validate_single_data_link(metadata: &std::fs::Metadata, path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt;

    let links = metadata.nlink();
    if links != 1 {
        return Err(StoreError::MultipleDataLinks {
            path: path.to_path_buf(),
            links,
        });
    }
    Ok(())
}

fn remove_new_empty_data_best_effort(
    binding: &StorePathBinding,
    name: &OsStr,
    path: &Path,
    file: &File,
    expected_identity: &DataFileIdentity,
) {
    let Ok(handle_metadata) = file.metadata() else {
        return;
    };
    if handle_metadata.len() == 0
        && binding
            .validate_named_file(name, file, expected_identity)
            .is_ok()
    {
        let _ = binding.remove_bound_child(name, file, expected_identity);
    }
    let _ = path;
}

fn tail_anchor_path(data_path: &Path) -> PathBuf {
    let mut path = OsString::from(data_path.as_os_str());
    path.push(".tail-anchor");
    PathBuf::from(path)
}

fn tail_anchor_temp_path(anchor_path: &Path) -> PathBuf {
    let mut path = OsString::from(anchor_path.as_os_str());
    path.push(".tmp");
    PathBuf::from(path)
}

fn ensure_tail_anchor_temp_absent(
    binding: &StorePathBinding,
    anchor_path: &Path,
) -> Result<(), StoreError> {
    if binding.child_exists(&binding.temp_name)? {
        Err(StoreError::TailAnchorTemporaryExists {
            path: tail_anchor_temp_path(anchor_path),
        })
    } else {
        Ok(())
    }
}

fn validate_named_file_identity(
    binding: &StorePathBinding,
    name: &OsStr,
    path: &Path,
    file: &File,
    expected_identity: &DataFileIdentity,
) -> Result<(), StoreError> {
    if binding.child_path(name) != path {
        return Err(StoreError::DataFileIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    binding.validate_named_file(name, file, expected_identity)
}

fn validate_header(header: &StoreHeader) -> Result<(), StoreError> {
    if !is_canonical_identifier(&header.broker_instance_id, MAX_BROKER_INSTANCE_ID_BYTES) {
        return Err(StoreError::InvalidBrokerIdentity);
    }
    validate_limits(&header.limits)?;
    validate_authority_binding(
        &header.authority_binding,
        header.limits.max_identifier_bytes,
    )
}

fn validate_authority_binding(
    authority_binding: &BTreeMap<String, RoleCategory>,
    max_identifier_bytes: usize,
) -> Result<(), StoreError> {
    if authority_binding.is_empty() || authority_binding.len() > MAX_AUTHORITY_IDENTITIES {
        return Err(StoreError::InvalidAuthorityBinding);
    }
    for agent_id in authority_binding.keys() {
        if !is_canonical_identifier(agent_id, max_identifier_bytes) {
            return Err(StoreError::InvalidAuthorityIdentity {
                agent_id: agent_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_limits(limits: &MessagingLimits) -> Result<(), StoreError> {
    limits
        .validate()
        .map_err(|error| StoreError::InvalidLimits {
            detail: error.to_string(),
        })?;
    if limits.max_journal_records == 0 || limits.max_journal_records > HARD_MAX_JOURNAL_RECORDS {
        return Err(StoreError::InvalidLimits {
            detail: format!("max_journal_records must be within 1..={HARD_MAX_JOURNAL_RECORDS}"),
        });
    }
    if limits.max_journal_bytes == 0 || limits.max_journal_bytes > HARD_MAX_JOURNAL_BYTES {
        return Err(StoreError::InvalidLimits {
            detail: format!("max_journal_bytes must be within 1..={HARD_MAX_JOURNAL_BYTES}"),
        });
    }
    Ok(())
}

fn validate_event_shape(event: &StoreEvent, header: &StoreHeader) -> Result<(), StoreError> {
    let limits = &header.limits;
    match event {
        StoreEvent::Created { .. } => Err(StoreError::DuplicateCreated { record_index: 0 }),
        StoreEvent::ChannelCreated { channel } => {
            channel
                .validate(limits)
                .map_err(|error| StoreError::InvalidEvent {
                    detail: error.to_string(),
                })?;
            validate_known_identities(channel.members.iter(), &header.authority_binding)
        }
        StoreEvent::MessageSent { envelope } => {
            envelope
                .validate(limits)
                .map_err(|error| StoreError::InvalidEvent {
                    detail: error.to_string(),
                })?;
            let Some(effective_role) = header.authority_binding.get(&envelope.sender_id) else {
                return Err(StoreError::UnknownEventIdentity {
                    agent_id: envelope.sender_id.clone(),
                });
            };
            if effective_role != &envelope.sender_role {
                return Err(StoreError::SenderRoleMismatch {
                    sender_id: envelope.sender_id.clone(),
                });
            }
            validate_known_identities(envelope.recipients.keys(), &header.authority_binding)
        }
        StoreEvent::DeliveryAttempted {
            message_id,
            recipient_id,
            attempt,
        } => {
            validate_message_and_recipient(message_id, recipient_id, limits)?;
            validate_known_identity(recipient_id, &header.authority_binding)?;
            if *attempt == 0
                || !usize::try_from(*attempt)
                    .is_ok_and(|value| value <= limits.max_delivery_attempts)
            {
                return Err(StoreError::InvalidEvent {
                    detail: "delivery attempt must be within the configured bound".to_string(),
                });
            }
            Ok(())
        }
        StoreEvent::Acknowledged {
            message_id,
            recipient_id,
        } => {
            validate_message_and_recipient(message_id, recipient_id, limits)?;
            validate_known_identity(recipient_id, &header.authority_binding)
        }
    }
}

fn validate_known_identities<'a>(
    identities: impl Iterator<Item = &'a String>,
    authority_binding: &BTreeMap<String, RoleCategory>,
) -> Result<(), StoreError> {
    for agent_id in identities {
        validate_known_identity(agent_id, authority_binding)?;
    }
    Ok(())
}

fn validate_known_identity(
    agent_id: &str,
    authority_binding: &BTreeMap<String, RoleCategory>,
) -> Result<(), StoreError> {
    if authority_binding.contains_key(agent_id) {
        Ok(())
    } else {
        Err(StoreError::UnknownEventIdentity {
            agent_id: agent_id.to_string(),
        })
    }
}

fn validate_message_and_recipient(
    message_id: &MessageId,
    recipient_id: &str,
    limits: &MessagingLimits,
) -> Result<(), StoreError> {
    message_id
        .validate(limits)
        .map_err(|error| StoreError::InvalidEvent {
            detail: error.to_string(),
        })?;
    if !is_canonical_identifier(recipient_id, limits.max_identifier_bytes) {
        return Err(StoreError::InvalidEvent {
            detail: "recipient id is not a bounded canonical identifier".to_string(),
        });
    }
    Ok(())
}

fn is_canonical_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn record_checksum(
    integrity_key: &StoreIntegrityKey,
    version: u32,
    sequence: u64,
    previous_checksum: &str,
    event: &StoreEvent,
) -> Result<String, StoreError> {
    let material = ChecksumMaterial {
        version,
        sequence,
        previous_checksum,
        event,
    };
    let bytes = serde_json::to_vec(&material).map_err(StoreError::Serialization)?;
    hmac_sha256_hex(&integrity_key.0, &[CHECKSUM_DOMAIN, &bytes])
}

fn encoded_record_bytes(
    integrity_key: &StoreIntegrityKey,
    sequence: u64,
    previous_checksum: &str,
    event: &StoreEvent,
) -> Result<Vec<u8>, StoreError> {
    let checksum = record_checksum(
        integrity_key,
        JOURNAL_FORMAT_VERSION,
        sequence,
        previous_checksum,
        event,
    )?;
    let record = BorrowedJournalRecord {
        version: JOURNAL_FORMAT_VERSION,
        sequence,
        previous_checksum,
        event,
        checksum: &checksum,
    };
    let mut bytes = serde_json::to_vec(&record).map_err(StoreError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn tail_anchor_authentication_tag(
    integrity_key: &StoreIntegrityKey,
    journal_bytes: u64,
    last_sequence: u64,
    last_checksum: &str,
) -> Result<String, StoreError> {
    let material = TailAnchorMaterial {
        version: TAIL_ANCHOR_FORMAT_VERSION,
        journal_bytes,
        last_sequence,
        last_checksum,
    };
    let bytes = serde_json::to_vec(&material).map_err(StoreError::Serialization)?;
    hmac_sha256_hex(&integrity_key.0, &[TAIL_ANCHOR_DOMAIN, &bytes])
}

fn encoded_tail_anchor(
    integrity_key: &StoreIntegrityKey,
    journal_bytes: usize,
    last_sequence: u64,
    last_checksum: &str,
) -> Result<Vec<u8>, StoreError> {
    if !is_canonical_authentication_tag(last_checksum) {
        return Err(StoreError::MalformedTailAnchor {
            detail: "last checksum is not a canonical authentication tag".to_string(),
        });
    }
    let journal_bytes =
        u64::try_from(journal_bytes).map_err(|_| StoreError::MalformedTailAnchor {
            detail: "journal byte length is not representable".to_string(),
        })?;
    let authentication_tag =
        tail_anchor_authentication_tag(integrity_key, journal_bytes, last_sequence, last_checksum)?;
    let anchor = TailAnchor {
        version: TAIL_ANCHOR_FORMAT_VERSION,
        journal_bytes,
        last_sequence,
        last_checksum: last_checksum.to_string(),
        authentication_tag,
    };
    let mut bytes = serde_json::to_vec(&anchor).map_err(StoreError::Serialization)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_TAIL_ANCHOR_BYTES {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail anchor exceeds its hard byte bound".to_string(),
        });
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn write_new_tail_anchor(
    binding: &StorePathBinding,
    name: &OsStr,
    file: &mut File,
    path: &Path,
    integrity_key: &StoreIntegrityKey,
    journal_bytes: usize,
    last_sequence: u64,
    last_checksum: &str,
) -> Result<(usize, DataFileIdentity), StoreError> {
    let bytes = encoded_tail_anchor(integrity_key, journal_bytes, last_sequence, last_checksum)?;
    let initial_metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting new tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    if !initial_metadata.is_file() || initial_metadata.len() != 0 {
        return Err(StoreError::MalformedTailAnchor {
            detail: "new tail anchor is not an empty regular file".to_string(),
        });
    }
    validate_regular_single_link(file, path)?;
    let initial_identity = file_identity(file, path)?;
    validate_named_file_identity(binding, name, path, file, &initial_identity)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| StoreError::Io {
            operation: "seeking tail anchor for",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(&bytes).map_err(|source| StoreError::Io {
        operation: "writing tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    file.flush().map_err(|source| StoreError::Io {
        operation: "flushing tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| StoreError::Io {
        operation: "synchronizing tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "revalidating synchronized tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    if usize::try_from(metadata.len()).ok() != Some(bytes.len()) {
        return Err(StoreError::MalformedTailAnchor {
            detail: "new tail anchor length changed during publication".to_string(),
        });
    }
    validate_regular_single_link(file, path)?;
    let identity = file_identity(file, path)?;
    validate_named_file_identity(binding, name, path, file, &identity)?;
    Ok((bytes.len(), identity))
}

fn prepare_tail_anchor_replacement(
    binding: &StorePathBinding,
    _anchor_path: &Path,
    integrity_key: &StoreIntegrityKey,
    journal_bytes: usize,
    last_sequence: u64,
    last_checksum: &str,
) -> Result<PreparedTailAnchor, StoreError> {
    let bytes = encoded_tail_anchor(integrity_key, journal_bytes, last_sequence, last_checksum)?;
    let temp_path = binding.child_path(&binding.temp_name);
    let mut file = binding
        .open_anchor(&binding.temp_name, true)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                StoreError::TailAnchorTemporaryExists {
                    path: temp_path.clone(),
                }
            } else {
                StoreError::Io {
                    operation: "creating tail-anchor publication file at",
                    path: temp_path.clone(),
                    source,
                }
            }
        })?;
    let initial_metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting new tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;
    if !initial_metadata.is_file() || initial_metadata.len() != 0 {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail-anchor publication file is not a new empty regular file".to_string(),
        });
    }
    validate_regular_single_link(&file, &temp_path)?;

    file.write_all(&bytes).map_err(|source| StoreError::Io {
        operation: "writing tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;
    file.flush().map_err(|source| StoreError::Io {
        operation: "flushing tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| StoreError::Io {
        operation: "synchronizing tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;

    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "revalidating tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;
    if usize::try_from(metadata.len()).ok() != Some(bytes.len()) {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail-anchor publication file length changed before replacement".to_string(),
        });
    }
    validate_regular_single_link(&file, &temp_path)?;
    let identity = file_identity(&file, &temp_path)?;
    validate_named_file_identity(binding, &binding.temp_name, &temp_path, &file, &identity)?;

    Ok(PreparedTailAnchor {
        temp_path,
        file,
        identity,
        bytes: bytes.len(),
    })
}

fn recover_tail_anchor_temp(
    binding: &StorePathBinding,
    current_file: &File,
    current_identity: &DataFileIdentity,
    anchor_path: &Path,
    integrity_key: &StoreIntegrityKey,
    checkpoints: &[JournalCheckpoint],
) -> Result<Option<PublishedTailAnchor>, StoreError> {
    let temp_path = binding.child_path(&binding.temp_name);
    if !binding.child_exists(&binding.temp_name)? {
        return Ok(None);
    }
    binding.validate_child_regular_before_open(&binding.temp_name, &temp_path)?;
    let mut file = binding
        .open_anchor(&binding.temp_name, false)
        .map_err(|source| StoreError::Io {
            operation: "opening recoverable tail-anchor publication file at",
            path: temp_path.clone(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting recoverable tail-anchor publication file at",
        path: temp_path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(StoreError::NotRegularFile { path: temp_path });
    }
    validate_regular_single_link(&file, &temp_path)?;
    let identity = file_identity(&file, &temp_path)?;
    validate_named_file_identity(binding, &binding.temp_name, &temp_path, &file, &identity)?;
    let latest = checkpoints
        .last()
        .ok_or(StoreError::FirstRecordNotCreated)?;
    let anchor = match read_tail_anchor(&mut file, &temp_path, integrity_key) {
        Ok(anchor) => anchor,
        Err(StoreError::MalformedTailAnchor { .. })
        | Err(StoreError::TailAnchorAuthenticationFailed) => {
            validate_named_file_identity(
                binding,
                &binding.temp_name,
                &temp_path,
                &file,
                &identity,
            )?;
            binding.remove_bound_child(&binding.temp_name, &file, &identity)?;
            return replace_tail_anchor(
                binding,
                current_file,
                current_identity,
                anchor_path,
                integrity_key,
                latest.journal_bytes,
                latest.sequence,
                &latest.checksum,
            )
            .map(Some);
        }
        Err(error) => return Err(error),
    };
    validate_named_file_identity(binding, &binding.temp_name, &temp_path, &file, &identity)?;
    let bytes = usize::try_from(metadata.len()).map_err(|_| StoreError::MalformedTailAnchor {
        detail: "recoverable tail-anchor publication length is not representable".to_string(),
    })?;
    let prepared = PreparedTailAnchor {
        temp_path,
        file,
        identity,
        bytes,
    };
    if tail_anchor_matches_checkpoint(&anchor, latest) {
        return publish_prepared_tail_anchor(
            binding,
            current_file,
            current_identity,
            anchor_path,
            prepared,
        )
        .map(Some);
    }

    if !checkpoints
        .iter()
        .any(|checkpoint| tail_anchor_matches_checkpoint(&anchor, checkpoint))
    {
        return Err(StoreError::TailAnchorMismatch);
    }

    // A fully authenticated but obsolete temp can only replay an already
    // committed prefix. Revalidate both reserved names before unlinking the
    // temp, fence the directory, and retain the valid committed anchor for
    // ordinary prefix healing below.
    validate_named_file_identity(
        binding,
        &binding.anchor_name,
        anchor_path,
        current_file,
        current_identity,
    )?;
    validate_named_file_identity(
        binding,
        &binding.temp_name,
        &prepared.temp_path,
        &prepared.file,
        &prepared.identity,
    )?;
    binding.remove_bound_child(&binding.temp_name, &prepared.file, &prepared.identity)?;
    validate_named_file_identity(
        binding,
        &binding.anchor_name,
        anchor_path,
        current_file,
        current_identity,
    )?;
    Ok(None)
}

fn publish_prepared_tail_anchor(
    binding: &StorePathBinding,
    current_file: &File,
    current_identity: &DataFileIdentity,
    anchor_path: &Path,
    prepared: PreparedTailAnchor,
) -> Result<PublishedTailAnchor, StoreError> {
    validate_named_file_identity(
        binding,
        &binding.anchor_name,
        anchor_path,
        current_file,
        current_identity,
    )?;
    validate_named_file_identity(
        binding,
        &binding.temp_name,
        &prepared.temp_path,
        &prepared.file,
        &prepared.identity,
    )?;

    binding.rename_child(&binding.temp_name, &binding.anchor_name, anchor_path)?;
    validate_named_file_identity(
        binding,
        &binding.anchor_name,
        anchor_path,
        &prepared.file,
        &prepared.identity,
    )?;
    let metadata = prepared.file.metadata().map_err(|source| StoreError::Io {
        operation: "revalidating published tail anchor at",
        path: anchor_path.to_path_buf(),
        source,
    })?;
    if usize::try_from(metadata.len()).ok() != Some(prepared.bytes) {
        return Err(StoreError::MalformedTailAnchor {
            detail: "published tail anchor length changed after replacement".to_string(),
        });
    }

    Ok(PublishedTailAnchor {
        file: prepared.file,
        identity: prepared.identity,
        bytes: prepared.bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn replace_tail_anchor(
    binding: &StorePathBinding,
    current_file: &File,
    current_identity: &DataFileIdentity,
    anchor_path: &Path,
    integrity_key: &StoreIntegrityKey,
    journal_bytes: usize,
    last_sequence: u64,
    last_checksum: &str,
) -> Result<PublishedTailAnchor, StoreError> {
    let prepared = prepare_tail_anchor_replacement(
        binding,
        anchor_path,
        integrity_key,
        journal_bytes,
        last_sequence,
        last_checksum,
    )?;
    publish_prepared_tail_anchor(
        binding,
        current_file,
        current_identity,
        anchor_path,
        prepared,
    )
}

fn read_tail_anchor(
    file: &mut File,
    path: &Path,
    integrity_key: &StoreIntegrityKey,
) -> Result<TailAnchor, StoreError> {
    let metadata = file.metadata().map_err(|source| StoreError::Io {
        operation: "inspecting tail anchor for",
        path: path.to_path_buf(),
        source,
    })?;
    let byte_len =
        usize::try_from(metadata.len()).map_err(|_| StoreError::MalformedTailAnchor {
            detail: "tail anchor length is not representable".to_string(),
        })?;
    if byte_len == 0 || byte_len > MAX_TAIL_ANCHOR_BYTES {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail anchor is empty or exceeds its hard byte bound".to_string(),
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| StoreError::Io {
            operation: "seeking tail anchor for",
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::with_capacity(byte_len);
    Read::by_ref(file)
        .take(MAX_TAIL_ANCHOR_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            operation: "reading tail anchor for",
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() != byte_len || bytes.len() > MAX_TAIL_ANCHOR_BYTES || !bytes.ends_with(b"\n") {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail anchor is truncated or changed while reading".to_string(),
        });
    }
    let anchor: TailAnchor =
        serde_json::from_slice(&bytes[..bytes.len() - 1]).map_err(|error| {
            StoreError::MalformedTailAnchor {
                detail: error.to_string(),
            }
        })?;
    let mut canonical = serde_json::to_vec(&anchor).map_err(StoreError::Serialization)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail anchor is not in canonical byte representation".to_string(),
        });
    }
    if anchor.version != TAIL_ANCHOR_FORMAT_VERSION
        || anchor.journal_bytes == 0
        || !is_canonical_authentication_tag(&anchor.last_checksum)
        || !is_canonical_authentication_tag(&anchor.authentication_tag)
    {
        return Err(StoreError::MalformedTailAnchor {
            detail: "tail anchor fields are outside the supported canonical form".to_string(),
        });
    }
    let expected_tag = tail_anchor_authentication_tag(
        integrity_key,
        anchor.journal_bytes,
        anchor.last_sequence,
        &anchor.last_checksum,
    )?;
    if !constant_time_eq(
        anchor.authentication_tag.as_bytes(),
        expected_tag.as_bytes(),
    ) {
        return Err(StoreError::TailAnchorAuthenticationFailed);
    }
    Ok(anchor)
}

fn tail_anchor_matches_checkpoint(anchor: &TailAnchor, checkpoint: &JournalCheckpoint) -> bool {
    usize::try_from(anchor.journal_bytes).ok() == Some(checkpoint.journal_bytes)
        && anchor.last_sequence == checkpoint.sequence
        && constant_time_eq(
            anchor.last_checksum.as_bytes(),
            checkpoint.checksum.as_bytes(),
        )
}

fn hmac_sha256_hex(key: &[u8], message_parts: &[&[u8]]) -> Result<String, StoreError> {
    let mut padded_key = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        let mut hashed = match decode_sha256_hex(&sha256_hex(key)) {
            Ok(hashed) => hashed,
            Err(error) => {
                zeroize_bytes(&mut padded_key);
                return Err(error);
            }
        };
        padded_key[..SHA256_BYTES].copy_from_slice(&hashed);
        zeroize_bytes(&mut hashed);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= padded_key[index];
        outer_pad[index] ^= padded_key[index];
    }

    let message_bytes = match message_parts.iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(StoreError::InvalidHashOutput)
    }) {
        Ok(message_bytes) => message_bytes,
        Err(error) => {
            zeroize_bytes(&mut padded_key);
            zeroize_bytes(&mut inner_pad);
            zeroize_bytes(&mut outer_pad);
            return Err(error);
        }
    };
    let mut inner = Vec::with_capacity(match HMAC_BLOCK_BYTES.checked_add(message_bytes) {
        Some(capacity) => capacity,
        None => {
            zeroize_bytes(&mut padded_key);
            zeroize_bytes(&mut inner_pad);
            zeroize_bytes(&mut outer_pad);
            return Err(StoreError::InvalidHashOutput);
        }
    });
    inner.extend_from_slice(&inner_pad);
    for part in message_parts {
        inner.extend_from_slice(part);
    }
    let mut inner_digest = match decode_sha256_hex(&sha256_hex(&inner)) {
        Ok(digest) => digest,
        Err(error) => {
            zeroize_bytes(&mut padded_key);
            zeroize_bytes(&mut inner_pad);
            zeroize_bytes(&mut outer_pad);
            zeroize_bytes(&mut inner);
            return Err(error);
        }
    };
    let mut outer = Vec::with_capacity(HMAC_BLOCK_BYTES + SHA256_BYTES);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    let output = sha256_hex(&outer);
    zeroize_bytes(&mut padded_key);
    zeroize_bytes(&mut inner_pad);
    zeroize_bytes(&mut outer_pad);
    zeroize_bytes(&mut inner_digest);
    zeroize_bytes(&mut inner);
    zeroize_bytes(&mut outer);
    Ok(output)
}

fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn decode_sha256_hex(value: &str) -> Result<[u8; SHA256_BYTES], StoreError> {
    if !is_canonical_authentication_tag(value) {
        return Err(StoreError::InvalidHashOutput);
    }
    let mut output = [0_u8; SHA256_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(StoreError::InvalidHashOutput)?;
        let low = decode_hex_nibble(pair[1]).ok_or(StoreError::InvalidHashOutput)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_canonical_authentication_tag(value: &str) -> bool {
    value.len() == SHA256_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        process::Command,
    };

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::messaging::envelope::{MessageAddress, MessageEnvelope};

    fn test_limits() -> MessagingLimits {
        MessagingLimits {
            max_credentials: 8,
            max_messages: 32,
            max_channels: 8,
            max_members_per_channel: 8,
            max_publishers_per_channel: 4,
            max_payload_bytes: 1_024,
            max_identifier_bytes: 64,
            max_journal_records: 64,
            max_journal_bytes: 64 * 1_024,
            max_delivery_attempts: 8,
        }
    }

    fn authority() -> BTreeMap<String, RoleCategory> {
        BTreeMap::from([
            (
                "coordinator".to_string(),
                RoleCategory::DelegatingCoordinator,
            ),
            (
                "worker".to_string(),
                RoleCategory::NonDelegatingTerminalWorker,
            ),
        ])
    }

    fn integrity_key() -> StoreIntegrityKey {
        StoreIntegrityKey::new([0x5a; STORE_INTEGRITY_KEY_BYTES])
    }

    fn overwrite_broker_identity_byte(path: &Path) {
        let bytes = fs::read(path).expect("read journal for same-length overwrite");
        let offset = bytes
            .windows(b"broker-one".len())
            .position(|window| window == b"broker-one")
            .expect("broker identity in journal");
        let mut attacker = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open journal outside advisory lock");
        attacker
            .seek(SeekFrom::Start(u64::try_from(offset).expect("offset")))
            .expect("seek to authenticated byte");
        attacker
            .write_all(b"B")
            .expect("overwrite one authenticated byte");
        attacker.sync_all().expect("sync same-length overwrite");
    }

    fn test_channel(limits: &MessagingLimits) -> GovernedChannel {
        GovernedChannel::new(
            "team",
            BTreeSet::from(["coordinator".to_string(), "worker".to_string()]),
            BTreeSet::from(["coordinator".to_string()]),
            limits,
        )
        .expect("valid test channel")
    }

    fn direct_envelope(limits: &MessagingLimits) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageId::new("broker-one-00000000000000000001").expect("valid message id"),
            MessageAddress::direct("worker", limits).expect("valid direct address"),
            "coordinator",
            RoleCategory::DelegatingCoordinator,
            1,
            json!({"body": "hello"}),
            BTreeSet::from(["worker".to_string()]),
            limits,
        )
        .expect("valid direct envelope")
    }

    fn legacy_unkeyed_checksum(
        version: u32,
        sequence: u64,
        previous_checksum: &str,
        event: &StoreEvent,
    ) -> String {
        let material = ChecksumMaterial {
            version,
            sequence,
            previous_checksum,
            event,
        };
        let bytes = serde_json::to_vec(&material).expect("checksum material");
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in b"MACO\0messaging-journal-record\0v1\0"
            .iter()
            .chain(bytes.iter())
        {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{hash:064x}")
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        let key = [0x0b; 20];
        assert_eq!(
            hmac_sha256_hex(&key, &[b"Hi There"]).expect("HMAC"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn open_rejects_wrong_integrity_key_and_legacy_recomputed_tamper() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        assert!(matches!(
            MessagingStore::open(
                &path,
                "broker",
                &authority,
                &limits,
                StoreIntegrityKey::new([0x6b; STORE_INTEGRITY_KEY_BYTES]),
            ),
            Err(StoreError::ChecksumMismatch { sequence: 0 })
        ));

        let bytes = fs::read(&path).expect("read journal");
        let mut record: JournalRecord =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("parse record");
        let StoreEvent::Created {
            broker_instance_id, ..
        } = &mut record.event
        else {
            panic!("first record must be Created");
        };
        *broker_instance_id = "broker-tampered".to_string();
        record.checksum = legacy_unkeyed_checksum(
            record.version,
            record.sequence,
            &record.previous_checksum,
            &record.event,
        );
        write_records(&path, &[record]);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::ChecksumMismatch { sequence: 0 })
        ));
    }

    #[test]
    fn create_preflights_initial_record_before_creating_data_file() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let mut limits = test_limits();
        limits.max_journal_bytes = 2_048;
        let authority = (0..32)
            .map(|index| {
                (
                    format!("coordinator-{index:02}-with-bounded-long-identity"),
                    RoleCategory::DelegatingCoordinator,
                )
            })
            .collect();

        assert!(matches!(
            MessagingStore::create(&path, "broker-one", authority, limits, integrity_key(),),
            Err(StoreError::JournalByteLimitExceeded { .. })
        ));
        assert!(!path.exists());
        let anchor_path = tail_anchor_path(&path);
        assert!(!anchor_path.exists());
        assert!(!tail_anchor_temp_path(&anchor_path).exists());
    }

    #[test]
    fn store_identifier_grammar_matches_envelope_and_hierarchy_ids() {
        assert!(is_canonical_identifier("worker:one", 64));
        assert!(is_canonical_identifier("worker-one_2.3", 64));
        assert!(!is_canonical_identifier("worker/one", 64));
        assert!(!is_canonical_identifier("worker\\one", 64));
    }

    #[test]
    fn append_reopen_preserves_exact_event_order() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let envelope = direct_envelope(&limits);
        let message_id = envelope.id.clone();

        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let original_anchor = fs::read(&anchor_path).expect("read original anchor");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append channel");
        store
            .append(StoreEvent::MessageSent { envelope })
            .expect("append message");
        store
            .append(StoreEvent::DeliveryAttempted {
                message_id: message_id.clone(),
                recipient_id: "worker".to_string(),
                attempt: 1,
            })
            .expect("append delivery");
        store
            .append(StoreEvent::Acknowledged {
                message_id,
                recipient_id: "worker".to_string(),
            })
            .expect("append acknowledgement");
        let expected = store.events().to_vec();
        let published_anchor = fs::read(&anchor_path).expect("read published anchor");
        assert_ne!(published_anchor, original_anchor);
        assert!(!tail_anchor_temp_path(&anchor_path).exists());
        drop(store);

        let reopened = MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("reopen store");
        assert_eq!(reopened.header().broker_instance_id, "broker-one");
        assert_eq!(reopened.events(), expected);
        assert_eq!(reopened.events().len(), 5);
    }

    #[test]
    fn prepared_tail_anchor_keeps_the_old_anchor_intact_until_replace() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let store =
            MessagingStore::create(&path, "broker-one", authority(), limits, integrity_key())
                .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let before = fs::read(&anchor_path).expect("read old anchor");

        let prepared = prepare_tail_anchor_replacement(
            &store.binding,
            &anchor_path,
            &store.integrity_key,
            store.journal_bytes + 1,
            store.last_sequence + 1,
            &store.last_checksum,
        )
        .expect("prepare replacement");

        assert_eq!(fs::read(&anchor_path).expect("reread old anchor"), before);
        assert!(prepared.temp_path.is_file());
        validate_named_file_identity(
            &store.binding,
            &store.binding.anchor_name,
            &anchor_path,
            &store.anchor_file,
            &store.anchor_identity,
        )
        .expect("old anchor identity remains bound");
    }

    #[test]
    fn unauthenticated_tail_anchor_temp_is_removed_and_latest_checkpoint_is_healed() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let temp_path = tail_anchor_temp_path(&anchor_path);
        fs::write(&temp_path, b"partial publication").expect("write stale temp");
        drop(store);

        let reopened = MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("recover interrupted anchor publication");
        assert_eq!(reopened.events().len(), 1);
        assert!(!temp_path.exists());
        assert!(anchor_path.is_file());
    }

    #[test]
    fn blocked_tail_anchor_publication_poisons_append_and_preserves_old_anchor() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let old_anchor = fs::read(&anchor_path).expect("read old anchor");
        let temp_path = tail_anchor_temp_path(&anchor_path);
        fs::write(&temp_path, b"blocked publication").expect("write blocking temp");

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::TailAnchorTemporaryExists { path }) if path == temp_path
        ));
        assert_eq!(
            fs::read(&anchor_path).expect("read preserved old anchor"),
            old_anchor
        );
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn authenticated_latest_tail_anchor_temp_is_published_on_open() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let old_anchor = fs::read(&anchor_path).expect("read old anchor");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append second record");
        let latest_anchor = fs::read(&anchor_path).expect("read latest anchor");
        drop(store);

        fs::write(&anchor_path, old_anchor).expect("restore committed prefix anchor");
        let temp_path = tail_anchor_temp_path(&anchor_path);
        fs::write(&temp_path, &latest_anchor).expect("restore prepared latest anchor");

        let reopened = MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("recover prepared latest anchor");
        assert_eq!(reopened.events().len(), 2);
        assert_eq!(
            fs::read(&anchor_path).expect("read recovered anchor"),
            latest_anchor
        );
        assert!(!temp_path.exists());
    }

    #[test]
    fn authenticated_obsolete_tail_anchor_temp_is_discarded_on_open() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let obsolete_anchor = fs::read(&anchor_path).expect("read obsolete anchor");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append second record");
        let committed_anchor = fs::read(&anchor_path).expect("read committed latest anchor");
        drop(store);

        let temp_path = tail_anchor_temp_path(&anchor_path);
        fs::write(&temp_path, obsolete_anchor).expect("restore obsolete prepared anchor");

        let reopened = MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("discard obsolete prepared anchor");
        assert_eq!(reopened.events().len(), 2);
        assert_eq!(
            fs::read(&anchor_path).expect("read retained committed anchor"),
            committed_anchor
        );
        assert!(!temp_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stale_tail_anchor_temp_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let temp_path = tail_anchor_temp_path(&anchor_path);
        symlink(&anchor_path, &temp_path).expect("create stale temp symlink");
        let before = fs::read(&anchor_path).expect("read anchor before open");
        drop(store);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::NotRegularFile { path }) if path == temp_path
        ));
        assert_eq!(
            fs::read(&anchor_path).expect("read anchor after refused open"),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_tail_anchor_temp_hard_link_is_refused() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let temp_path = tail_anchor_temp_path(&anchor_path);
        let attacker_file = temp.path().join("attacker-anchor");
        fs::write(&attacker_file, b"partial publication").expect("write attacker file");
        fs::hard_link(&attacker_file, &temp_path).expect("hard-link unsafe temp");
        drop(store);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::MultipleDataLinks { path, links: 2 }) if path == temp_path
        ));
        assert!(temp_path.exists());
        assert!(anchor_path.is_file());
    }

    #[test]
    fn open_rejects_truncated_final_record() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let mut bytes = fs::read(&path).expect("read journal");
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(&path, bytes).expect("truncate journal");
        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::TruncatedFinalRecord { record_index: 0 })
        ));
    }

    #[test]
    fn open_rejects_complete_newline_terminated_tail_removal() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append complete second record");
        drop(store);

        let mut bytes = fs::read(&path).expect("read journal");
        let first_record_bytes = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|position| position + 1)
            .expect("first complete record");
        bytes.truncate(first_record_bytes);
        assert!(bytes.ends_with(b"\n"));
        fs::write(&path, bytes).expect("remove complete tail record");

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::TailAnchorMismatch)
        ));
    }

    #[test]
    fn open_rejects_reordered_sequence_before_returning_state() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append channel");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let mut records: Vec<JournalRecord> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("parse record"))
            .collect();
        records[1].sequence = 0;
        write_records(&path, &records);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::OutOfOrderSequence {
                record_index: 1,
                expected: 1,
                found: 0
            })
        ));
    }

    #[test]
    fn open_rejects_checksum_tampering() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let mut record: JournalRecord =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("parse record");
        record.checksum = "ffffffffffffffff".to_string();
        write_records(&path, &[record]);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::ChecksumMismatch { sequence: 0 })
        ));
    }

    #[test]
    fn strict_schema_rejects_token_like_unknown_fields() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let mut value: Value =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("parse record");
        value
            .as_object_mut()
            .expect("record object")
            .insert("credential_token".to_string(), json!("must-not-load"));
        let mut encoded = serde_json::to_vec(&value).expect("encode modified record");
        encoded.push(b'\n');
        fs::write(&path, encoded).expect("write modified journal");

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::MalformedRecord {
                record_index: 0,
                ..
            })
        ));
    }

    #[test]
    fn open_rejects_duplicate_top_level_key_before_checksum_acceptance() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let line = String::from_utf8(bytes[..bytes.len() - 1].to_vec()).expect("UTF-8 record");
        let duplicated = line.replacen('{', r#"{"version":1,"#, 1);
        fs::write(&path, format!("{duplicated}\n")).expect("write duplicate-key record");

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::NonCanonicalRecord { record_index: 0 })
        ));
    }

    #[test]
    fn open_rejects_reordered_checksum_consistent_record_keys() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let record: JournalRecord =
            serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("parse record");
        let reordered = format!(
            "{{\"sequence\":{},\"version\":{},\"previous_checksum\":{},\"event\":{},\"checksum\":{}}}\n",
            record.sequence,
            record.version,
            serde_json::to_string(&record.previous_checksum).expect("previous checksum"),
            serde_json::to_string(&record.event).expect("event"),
            serde_json::to_string(&record.checksum).expect("checksum")
        );
        fs::write(&path, reordered).expect("write reordered record");

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::NonCanonicalRecord { record_index: 0 })
        ));
    }

    #[test]
    fn open_rejects_checksum_consistent_duplicate_channel_state() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        store
            .append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            })
            .expect("append channel");
        drop(store);

        let bytes = fs::read(&path).expect("read journal");
        let mut records: Vec<JournalRecord> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("parse record"))
            .collect();
        let previous_checksum = records[1].checksum.clone();
        let event = records[1].event.clone();
        let checksum = record_checksum(
            &integrity_key(),
            JOURNAL_FORMAT_VERSION,
            2,
            &previous_checksum,
            &event,
        )
        .expect("checksum");
        records.push(JournalRecord {
            version: JOURNAL_FORMAT_VERSION,
            sequence: 2,
            previous_checksum,
            event,
            checksum,
        });
        write_records(&path, &records);

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::InvalidStateTransition {
                detail: "channel creation is duplicated"
            })
        ));
    }

    #[test]
    fn append_rejects_identity_inconsistent_sender_without_writing() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let before = fs::metadata(&path).expect("journal metadata").len();
        let mut envelope = direct_envelope(&limits);
        envelope.sender_role = RoleCategory::ReadOnlyResearcher;

        assert!(matches!(
            store.append(StoreEvent::MessageSent { envelope }),
            Err(StoreError::SenderRoleMismatch { .. })
        ));
        assert_eq!(fs::metadata(&path).expect("journal metadata").len(), before);
        drop(store);
        assert_eq!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
                .expect("reopen unmodified store")
                .events()
                .len(),
            1
        );
    }

    #[test]
    fn append_rejects_zero_attempt_without_writing() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority,
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let before = fs::metadata(&path).expect("journal metadata").len();

        assert!(matches!(
            store.append(StoreEvent::DeliveryAttempted {
                message_id: MessageId::new("message-1").expect("valid message id"),
                recipient_id: "worker".to_string(),
                attempt: 0,
            }),
            Err(StoreError::InvalidEvent { .. })
        ));
        assert_eq!(fs::metadata(&path).expect("journal metadata").len(), before);
    }

    #[test]
    fn append_rejects_unknown_message_and_ack_before_delivery_without_writing() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let before_unknown = fs::metadata(&path).expect("journal metadata").len();
        let message_id =
            MessageId::new("broker-one-00000000000000000001").expect("valid message id");

        assert!(matches!(
            store.append(StoreEvent::DeliveryAttempted {
                message_id: message_id.clone(),
                recipient_id: "worker".to_string(),
                attempt: 1,
            }),
            Err(StoreError::InvalidStateTransition {
                detail: "delivery attempt references an unknown message"
            })
        ));
        assert_eq!(
            fs::metadata(&path).expect("journal metadata").len(),
            before_unknown
        );

        store
            .append(StoreEvent::MessageSent {
                envelope: direct_envelope(&limits),
            })
            .expect("append message after refused transition");
        let before_ack = fs::metadata(&path).expect("journal metadata").len();
        assert!(matches!(
            store.append(StoreEvent::Acknowledged {
                message_id,
                recipient_id: "worker".to_string(),
            }),
            Err(StoreError::InvalidStateTransition {
                detail: "acknowledgement references a non-recipient or precedes delivery"
            })
        ));
        assert_eq!(
            fs::metadata(&path).expect("journal metadata").len(),
            before_ack
        );
    }

    #[test]
    fn append_rejects_pre_mutated_message_delivery_state() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority,
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let before = fs::metadata(&path).expect("journal metadata").len();
        let mut envelope = direct_envelope(&limits);
        envelope
            .recipients
            .get_mut("worker")
            .expect("worker delivery state")
            .delivery_attempts = 1;

        assert!(matches!(
            store.append(StoreEvent::MessageSent { envelope }),
            Err(StoreError::InvalidStateTransition {
                detail: "new message contains pre-mutated delivery state"
            })
        ));
        assert_eq!(fs::metadata(&path).expect("journal metadata").len(), before);
    }

    #[test]
    fn equal_length_external_change_poisons_before_append() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let expected_bytes = fs::metadata(&path).expect("journal metadata").len() as usize;
        overwrite_broker_identity_byte(&path);

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::ExternalContentModification {
                expected_bytes: actual
            }) if actual == expected_bytes
        ));
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn open_bounds_growth_after_initial_metadata_observation() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);
        let initial_bytes = fs::metadata(&path).expect("journal metadata").len() as usize;
        let grown_bytes = limits.max_journal_bytes + 128;
        set_after_journal_metadata_hook(move |journal_path| {
            let growth = grown_bytes
                .checked_sub(initial_bytes)
                .expect("configured growth exceeds initial journal");
            let mut attacker = fs::OpenOptions::new()
                .append(true)
                .open(journal_path)
                .expect("open journal outside advisory lock");
            attacker
                .write_all(&vec![b' '; growth])
                .expect("grow journal beyond configured bound");
            attacker.sync_all().expect("sync concurrent growth");
        });

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::JournalByteLimitExceeded { actual, max })
                if actual == limits.max_journal_bytes + 1 && max == limits.max_journal_bytes
        ));
        assert_eq!(
            fs::metadata(&path).expect("grown journal metadata").len() as usize,
            grown_bytes
        );
    }

    #[test]
    fn external_length_change_poisons_the_open_writer() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority,
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let mut bytes = fs::read(&path).expect("read journal");
        bytes.push(b' ');
        fs::write(&path, bytes).expect("externally extend journal");

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::ExternalModification { .. })
        ));
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn data_name_substitution_poisons_without_publishing_an_anchor() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let moved_path = temp.path().join("original-messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let anchor_before = fs::read(&anchor_path).expect("read anchor before substitution");
        let original_bytes = fs::read(&path).expect("read original journal");
        fs::rename(&path, &moved_path).expect("move bound journal aside");
        fs::write(&path, original_bytes).expect("substitute journal pathname");

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::DataFileIdentityChanged { path: changed }) if changed == path
        ));
        assert_eq!(
            fs::read(&anchor_path).expect("read unchanged anchor"),
            anchor_before
        );
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn parent_directory_substitution_poisons_before_append() {
        let temp = TempDir::new().expect("tempdir");
        let parent = temp.path().join("state");
        let moved_parent = temp.path().join("original-state");
        fs::create_dir(&parent).expect("create store parent");
        let path = parent.join("messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        fs::rename(&parent, &moved_parent).expect("replace parent binding");
        fs::create_dir(&parent).expect("create substituted parent");

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::DataFileIdentityChanged { path: changed }) if changed == parent
        ));
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn external_append_after_journal_sync_poisons_before_anchor_publication() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let anchor_before = fs::read(&anchor_path).expect("read anchor before append");

        set_after_journal_sync_hook(|journal_path| {
            let mut attacker = fs::OpenOptions::new()
                .append(true)
                .open(journal_path)
                .expect("open journal outside advisory lock");
            attacker
                .write_all(b"external-byte")
                .expect("append external bytes");
            attacker.sync_all().expect("sync external append");
        });

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::ExternalModification { .. })
        ));
        assert_eq!(
            fs::read(&anchor_path).expect("read unchanged anchor"),
            anchor_before
        );
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn equal_length_overwrite_after_journal_sync_poisons_before_anchor_publication() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let mut store = MessagingStore::create(
            &path,
            "broker-one",
            authority(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        let anchor_path = tail_anchor_path(&path);
        let anchor_before = fs::read(&anchor_path).expect("read anchor before append");

        set_after_journal_sync_hook(overwrite_broker_identity_byte);

        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::ExternalContentModification { .. })
        ));
        assert_eq!(
            fs::read(&anchor_path).expect("read unchanged anchor"),
            anchor_before
        );
        assert!(matches!(
            store.append(StoreEvent::ChannelCreated {
                channel: test_channel(&limits),
            }),
            Err(StoreError::Poisoned)
        ));
    }

    #[test]
    fn open_refuses_a_concurrent_writer() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");

        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &limits, integrity_key()),
            Err(StoreError::WriterAlreadyActive { .. })
        ));
        drop(store);
        MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("lock released on drop");
    }

    #[test]
    fn data_file_lock_refuses_a_separate_process() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        assert!(path.is_file());
        assert!(tail_anchor_path(&path).is_file());

        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("messaging::store::tests::data_file_lock_child_probe")
            .arg("--nocapture")
            .env("MACO_MESSAGING_LOCK_CHILD", &path)
            .output()
            .expect("run child lock probe");
        assert!(
            output.status.success(),
            "child lock probe failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        drop(store);
        assert!(path.is_file());
        MessagingStore::open(&path, "broker", &authority, &limits, integrity_key())
            .expect("data-file lock is released on drop");
    }

    #[test]
    fn data_file_lock_child_probe() {
        let Some(path) = std::env::var_os("MACO_MESSAGING_LOCK_CHILD") else {
            return;
        };
        let path = PathBuf::from(path);
        assert!(matches!(
            MessagingStore::open(
                &path,
                "broker",
                &authority(),
                &test_limits(),
                integrity_key(),
            ),
            Err(StoreError::WriterAlreadyActive { .. })
        ));
    }

    #[test]
    fn open_rejects_authority_and_limit_mismatches() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("messages.jsonl");
        let limits = test_limits();
        let authority = authority();
        let store = MessagingStore::create(
            &path,
            "broker-one",
            authority.clone(),
            limits.clone(),
            integrity_key(),
        )
        .expect("create store");
        drop(store);

        let mut other_authority = authority.clone();
        other_authority.insert("researcher".to_string(), RoleCategory::ReadOnlyResearcher);
        assert!(matches!(
            MessagingStore::open(&path, "broker", &other_authority, &limits, integrity_key(),),
            Err(StoreError::AuthorityBindingMismatch)
        ));

        let mut other_limits = limits.clone();
        other_limits.max_messages += 1;
        assert!(matches!(
            MessagingStore::open(&path, "broker", &authority, &other_limits, integrity_key(),),
            Err(StoreError::LimitsMismatch)
        ));
    }

    fn write_records(path: &Path, records: &[JournalRecord]) {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend(serde_json::to_vec(record).expect("serialize record"));
            bytes.push(b'\n');
        }
        fs::write(path, bytes).expect("write records");
    }
}
