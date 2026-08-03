//! Repository-bound authentication for durable local state.
//!
//! The key bytes never leave this module. Consumers receive only repository
//! binding evidence and domain-separated sign/verify operations.

use crate::{
    field_guide::FIELD_GUIDE_STATE_NAMESPACE,
    follow_up_queue::GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME,
    safe_state::{
        identity_for_path, AtomicStateWriter, BoundedRegularReader, ExistingExclusiveLock,
        FileIdentity, KernelStateLock, SafeRoot,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt},
};

const AUTH_KEY_FILE: &str = "artifact_finalization_hmac_v1.key";
const AUTH_KEY_LOCK: &str = "artifact_finalization_hmac_v1.lock";
const AUTH_EPOCH_FILE: &str = "repository_auth_epoch_v1";
const AUTH_KEY_BYTES: usize = 32;
const AUTH_EPOCH_BYTES: usize = 32;
const AUTH_BINDING_VERSION: u32 = 1;
const MAX_AUTH_DOMAIN_BYTES: usize = 256;
const MAX_AUTH_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const AUTH_FRAME_MAGIC: &[u8] = b"MACO\0repository-auth\0hmac-sha256\0v1\0";
const LEGACY_ARTIFACT_DOMAIN: &[u8] = b"MACO\0artifact-finalization\0hmac-sha256\0v2\0";

/// Direct children that cannot safely survive generation of a replacement
/// repository authentication key. Keep this registry centralized so every
/// first-key writer fails closed as new authenticated state consumers arrive.
const AUTHENTICATED_STATE_CONSUMERS: &[(&str, &str)] = &[
    (
        "orchestration-checkpoints-v3",
        "orchestration checkpoint journals",
    ),
    ("authenticated-effect-wals-v1", "authenticated effect WALs"),
    (
        "authenticated-claims-state-v1",
        "authenticated claims state",
    ),
    (
        "authenticated-semantic-state-v1",
        "authenticated semantic coordination state",
    ),
    (
        FIELD_GUIDE_STATE_NAMESPACE,
        "authenticated field guide state",
    ),
    (
        "authenticated-managed-worktrees-v1",
        "authenticated managed worktree state",
    ),
    (
        "authenticated-megafile-history-v1",
        "authenticated megafile history",
    ),
    (
        "state-migration-manifests-v1",
        "authenticated state migration manifests",
    ),
    (
        GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME,
        "authenticated generated follow-up queues",
    ),
];

#[cfg(test)]
pub(crate) fn authentication_key_file_name() -> &'static str {
    AUTH_KEY_FILE
}

#[cfg(test)]
pub(crate) fn authentication_key_lock_name() -> &'static str {
    AUTH_KEY_LOCK
}

#[cfg(test)]
pub(crate) fn authentication_key_length() -> usize {
    AUTH_KEY_BYTES
}

pub(crate) fn random_identifier() -> Result<String> {
    let mut bytes = SecretKey([0_u8; AUTH_KEY_BYTES]);
    fill_os_random(&mut bytes.0)?;
    Ok(hex_encode(&bytes.0))
}

/// Resolves and revalidates the owner-private repository state root that must
/// be hidden from every untrusted child process. The returned path is only a
/// mount/confinement target; consumers receive no key material.
pub(crate) fn sensitive_state_root(common_dir: &Path) -> Result<std::path::PathBuf> {
    let common_root = SafeRoot::open_existing(common_dir)
        .context("Git common directory is not safely reachable for state masking")?;
    let state_path = common_root.path().join("maco").join("state");
    let state_root = SafeRoot::open_existing(&state_path).with_context(|| {
        format!(
            "repository sensitive state root is missing or unsafe: {}",
            state_path.display()
        )
    })?;
    common_root.verify()?;
    state_root.verify()?;
    Ok(state_root.path().to_path_buf())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryAuthBinding {
    pub version: u32,
    pub repository_id: String,
    pub common_dir_path_sha256: String,
    pub common_dir_identity: FileIdentity,
    pub key_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct AuthenticationTag(String);

impl AuthenticationTag {
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !is_canonical_lower_hex_64(&value) {
            bail!("authentication tag is not canonical lowercase SHA-256 hex");
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !is_canonical_lower_hex_64(&self.0) {
            bail!("authentication tag is not canonical lowercase SHA-256 hex");
        }
        Ok(())
    }

    pub(crate) fn zero() -> Self {
        Self("0".repeat(64))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticationDomain(&'static [u8]);

impl AuthenticationDomain {
    pub(crate) const fn new(bytes: &'static [u8]) -> Self {
        Self(bytes)
    }
}

/// A loaded repository key. Deliberately has no `Debug`, `Clone`, or raw-byte
/// accessor so consumers cannot accidentally expose or persist the secret.
pub(crate) struct RepositoryAuthenticator {
    common_root: SafeRoot,
    state_root: SafeRoot,
    key: SecretKey,
    binding: RepositoryAuthBinding,
}

struct SecretKey([u8; AUTH_KEY_BYTES]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

pub(crate) struct RepositoryAuthWriter {
    authenticator: RepositoryAuthenticator,
    lock: BoundStateLock,
}

/// A kernel lock whose pathname and containing SafeRoot remain identity-bound
/// for the full protected operation.
#[derive(Debug)]
pub(crate) struct BoundStateLock {
    lock: KernelStateLock,
    root_identity: FileIdentity,
    lock_identity: FileIdentity,
}

impl BoundStateLock {
    pub(crate) fn acquire(root: &SafeRoot, name: &str) -> Result<Self> {
        let lock = KernelStateLock::acquire_direct(root, name)?;
        Self::from_lock(root, lock)
    }

    pub(crate) fn try_acquire_exclusive(root: &SafeRoot, name: &str) -> Result<Self> {
        let lock = KernelStateLock::try_acquire_exclusive_direct(root, name)?;
        Self::from_lock(root, lock)
    }

    pub(crate) fn try_acquire_existing_exclusive(root: &SafeRoot, name: &str) -> Result<Self> {
        match KernelStateLock::try_acquire_existing_exclusive_direct(root, name)? {
            ExistingExclusiveLock::Acquired(lock) => Self::from_lock(root, lock),
            ExistingExclusiveLock::Busy => bail!("state lock is active elsewhere"),
            ExistingExclusiveLock::Missing => bail!("required existing state lock is missing"),
        }
    }

    pub(crate) fn try_acquire_optional_existing_exclusive(
        root: &SafeRoot,
        name: &str,
    ) -> Result<Option<Self>> {
        match KernelStateLock::try_acquire_existing_exclusive_direct(root, name)? {
            ExistingExclusiveLock::Acquired(lock) => Self::from_lock(root, lock).map(Some),
            ExistingExclusiveLock::Busy => bail!("state lock is active elsewhere"),
            ExistingExclusiveLock::Missing => Ok(None),
        }
    }

    fn from_lock(root: &SafeRoot, lock: KernelStateLock) -> Result<Self> {
        let bound = Self {
            root_identity: root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        bound.verify(root)?;
        Ok(bound)
    }

    pub(crate) fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        if self.root_identity != *root.identity() {
            bail!("state lock was presented with a different root inode");
        }
        self.lock.verify_direct_binding(root)?;
        if self.lock.identity() != &self.lock_identity {
            bail!("state lock identity changed unexpectedly");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        self.lock.path()
    }
}

impl RepositoryAuthenticator {
    pub(crate) fn open_existing(common_dir: &Path) -> Result<Self> {
        let common_root = SafeRoot::open_existing(common_dir)
            .context("Git common directory is not safely reachable for authentication")?;
        let state_path = common_root.path().join("maco").join("state");
        let state_root = SafeRoot::open_existing(&state_path).with_context(|| {
            format!(
                "repository authentication state is missing or unsafe: {}",
                state_path.display()
            )
        })?;
        Self::load(common_root, state_root)
    }

    fn load(common_root: SafeRoot, state_root: SafeRoot) -> Result<Self> {
        common_root.verify()?;
        state_root.verify()?;
        if !state_root.direct_child_exists(AUTH_KEY_FILE)? {
            bail!("repository authentication MAC key is missing");
        }
        let key_path = state_root.direct_child(AUTH_KEY_FILE)?;
        let key_identity = ensure_private_auth_file(&key_path)?;
        let mut contents =
            BoundedRegularReader::read_direct(&state_root, AUTH_KEY_FILE, AUTH_KEY_BYTES as u64)?;
        if contents.len() != AUTH_KEY_BYTES {
            let observed = contents.len();
            zeroize(&mut contents);
            bail!(
                "repository authentication key has invalid length {} (expected {})",
                observed,
                AUTH_KEY_BYTES
            );
        }
        let mut key_bytes = [0_u8; AUTH_KEY_BYTES];
        key_bytes.copy_from_slice(&contents);
        zeroize(&mut contents);
        let key = SecretKey(key_bytes);
        let binding = RepositoryAuthBinding {
            version: AUTH_BINDING_VERSION,
            repository_id: sha256_hex(&key.0),
            common_dir_path_sha256: sha256_hex(&filesystem_path_bytes(common_root.path())),
            common_dir_identity: common_root.identity().clone(),
            key_identity,
        };
        let authenticator = Self {
            common_root,
            state_root,
            key,
            binding,
        };
        authenticator.verify()?;
        Ok(authenticator)
    }

    pub(crate) fn binding(&self) -> &RepositoryAuthBinding {
        &self.binding
    }

    pub(crate) fn state_root(&self) -> &SafeRoot {
        &self.state_root
    }

    pub(crate) fn verify_repository_binding(&self, expected: &RepositoryAuthBinding) -> Result<()> {
        validate_repository_binding(expected)?;
        self.verify()?;
        if expected != &self.binding {
            bail!("authenticated state belongs to a different repository or key epoch");
        }
        Ok(())
    }

    pub(crate) fn sign(
        &self,
        domain: AuthenticationDomain,
        payload: &[u8],
    ) -> Result<AuthenticationTag> {
        self.verify()?;
        let message = framed_auth_message(domain, payload)?;
        let tag = AuthenticationTag(hex_encode(&hmac_sha256(&self.key.0, &message)));
        self.verify()?;
        Ok(tag)
    }

    /// Compatibility-only signing for the already published artifact v2
    /// marker format. New state formats must use the length-framed `sign` API.
    pub(crate) fn sign_legacy_artifact_finalization_v2(
        &self,
        payload: &[u8],
    ) -> Result<AuthenticationTag> {
        if payload.len() > MAX_AUTH_PAYLOAD_BYTES {
            bail!("legacy artifact authentication payload exceeds its bound");
        }
        self.verify()?;
        let mut message =
            Vec::with_capacity(LEGACY_ARTIFACT_DOMAIN.len().saturating_add(payload.len()));
        message.extend_from_slice(LEGACY_ARTIFACT_DOMAIN);
        message.extend_from_slice(payload);
        let tag = AuthenticationTag(hex_encode(&hmac_sha256(&self.key.0, &message)));
        self.verify()?;
        Ok(tag)
    }

    pub(crate) fn verify_legacy_artifact_finalization_v2(
        &self,
        payload: &[u8],
        tag: &AuthenticationTag,
    ) -> Result<()> {
        let expected = self.sign_legacy_artifact_finalization_v2(payload)?;
        if !constant_time_eq(expected.as_str().as_bytes(), tag.as_str().as_bytes()) {
            bail!("artifact finalization HMAC verification failed");
        }
        Ok(())
    }

    pub(crate) fn verify_tag(
        &self,
        domain: AuthenticationDomain,
        payload: &[u8],
        tag: &AuthenticationTag,
    ) -> Result<()> {
        tag.validate().context("authentication tag is malformed")?;
        let expected = self.sign(domain, payload)?;
        if !constant_time_eq(expected.as_str().as_bytes(), tag.as_str().as_bytes()) {
            bail!("repository authentication tag verification failed");
        }
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.common_root.verify()?;
        self.state_root.verify()?;
        let observed = ensure_private_auth_file(&self.state_root.direct_child(AUTH_KEY_FILE)?)?;
        if observed != self.binding.key_identity {
            bail!("repository authentication key inode was replaced");
        }
        let mut contents = BoundedRegularReader::read_direct(
            &self.state_root,
            AUTH_KEY_FILE,
            AUTH_KEY_BYTES as u64,
        )?;
        let key_matches = constant_time_eq(&contents, &self.key.0);
        zeroize(&mut contents);
        if !key_matches {
            bail!("repository authentication key contents changed");
        }
        let observed_binding = RepositoryAuthBinding {
            version: AUTH_BINDING_VERSION,
            repository_id: sha256_hex(&self.key.0),
            common_dir_path_sha256: sha256_hex(&filesystem_path_bytes(self.common_root.path())),
            common_dir_identity: self.common_root.identity().clone(),
            key_identity: observed,
        };
        if observed_binding != self.binding {
            bail!("repository authentication binding changed");
        }
        Ok(())
    }

    /// Validates the durable epoch sentinel after caller-controlled state has
    /// been authenticated. Key-only open deliberately does not inspect this
    /// repository-global state so checkpoint locators can be MAC-checked first.
    pub(crate) fn verify_epoch(&self) -> Result<()> {
        self.verify()?;
        if !self.state_root.direct_child_exists(AUTH_EPOCH_FILE)? {
            bail!(
                "repository authentication epoch sentinel is missing; refusing ambiguous key state"
            );
        }
        let path = self.state_root.direct_child(AUTH_EPOCH_FILE)?;
        ensure_private_auth_file(&path)?;
        let mut epoch = BoundedRegularReader::read_direct(
            &self.state_root,
            AUTH_EPOCH_FILE,
            AUTH_EPOCH_BYTES as u64,
        )?;
        if epoch.len() != AUTH_EPOCH_BYTES {
            let observed = epoch.len();
            zeroize(&mut epoch);
            bail!(
                "repository authentication epoch sentinel has invalid length {} (expected {})",
                observed,
                AUTH_EPOCH_BYTES
            );
        }
        zeroize(&mut epoch);
        self.verify()
    }
}

impl RepositoryAuthWriter {
    pub(super) fn open_or_create<F>(common_dir: &Path, before_first_key: F) -> Result<Self>
    where
        F: FnOnce(&SafeRoot) -> Result<()>,
    {
        let common_root = SafeRoot::open_existing(common_dir)
            .context("Git common directory is not safely reachable for authentication")?;
        let state_path = common_root.path().join("maco").join("state");
        let existed = fs::symlink_metadata(&state_path).is_ok();
        let state_root = match SafeRoot::open_or_create(&state_path) {
            Ok(root) => root,
            Err(error) if existed => {
                bail!("existing repository authentication root is not owner-private: {error:#}")
            }
            Err(error) => {
                return Err(error).context("failed to create repository authentication root")
            }
        };
        let lock = BoundStateLock::acquire(&state_root, AUTH_KEY_LOCK)?;
        lock.verify(&state_root)?;
        let key_exists = state_root.direct_child_exists(AUTH_KEY_FILE)?;
        let epoch_exists = state_root.direct_child_exists(AUTH_EPOCH_FILE)?;
        if !key_exists {
            // Scan every registered legacy consumer before considering a new
            // key. This preserves precise diagnostics for existing markers or
            // journals while the epoch sentinel remains the final fail-closed
            // backstop for otherwise unregistered authenticated state.
            before_first_key(&state_root)?;
            validate_registered_consumers_before_first_key(&state_root)?;
            if epoch_exists {
                bail!(
                    "repository authentication key is missing for an existing authentication epoch; refusing to generate a replacement key"
                );
            }
            let mut key = SecretKey([0_u8; AUTH_KEY_BYTES]);
            fill_os_random(&mut key.0)?;
            AtomicStateWriter::scavenge_direct_temps(&state_root, AUTH_KEY_FILE)?;
            AtomicStateWriter::write_direct_fenced(&state_root, AUTH_KEY_FILE, &key.0, || {
                lock.verify(&state_root)
            })?;
            run_key_bootstrap_fault(KeyBootstrapFaultPoint::AfterKey)?;

            // The key is authoritative and must become durable before the
            // epoch sentinel. A crash between these writes is recoverable by
            // the key-existing/epoch-missing branch below; the reverse order
            // could strand an epoch with no recoverable authentication key.
            let mut epoch = SecretKey([0_u8; AUTH_EPOCH_BYTES]);
            fill_os_random(&mut epoch.0)?;
            AtomicStateWriter::scavenge_direct_temps(&state_root, AUTH_EPOCH_FILE)?;
            AtomicStateWriter::write_direct_fenced(&state_root, AUTH_EPOCH_FILE, &epoch.0, || {
                lock.verify(&state_root)
            })?;
            run_key_bootstrap_fault(KeyBootstrapFaultPoint::AfterEpoch)?;
        } else if !epoch_exists {
            // One-time migration for repositories whose key predates the
            // epoch sentinel. The existing key remains authoritative.
            let mut epoch = SecretKey([0_u8; AUTH_EPOCH_BYTES]);
            fill_os_random(&mut epoch.0)?;
            AtomicStateWriter::scavenge_direct_temps(&state_root, AUTH_EPOCH_FILE)?;
            AtomicStateWriter::write_direct_fenced(&state_root, AUTH_EPOCH_FILE, &epoch.0, || {
                lock.verify(&state_root)
            })?;
            run_key_bootstrap_fault(KeyBootstrapFaultPoint::AfterEpoch)?;
        }
        let authenticator = RepositoryAuthenticator::load(common_root, state_root)?;
        let writer = Self {
            authenticator,
            lock,
        };
        writer.verify()?;
        Ok(writer)
    }

    pub(crate) fn authenticator(&self) -> &RepositoryAuthenticator {
        &self.authenticator
    }

    #[cfg(test)]
    pub(crate) fn lock_path(&self) -> &Path {
        self.lock.path()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.lock.verify(&self.authenticator.state_root)?;
        self.authenticator.verify()?;
        self.authenticator.verify_epoch()?;
        self.lock.verify(&self.authenticator.state_root)
    }

    pub(crate) fn into_authenticator(self) -> Result<RepositoryAuthenticator> {
        self.verify()?;
        Ok(self.authenticator)
    }
}

fn validate_registered_consumers_before_first_key(state_root: &SafeRoot) -> Result<()> {
    state_root.verify()?;
    for (root_name, description) in AUTHENTICATED_STATE_CONSUMERS {
        if state_root.direct_child_exists(root_name)? {
            bail!(
                "repository authentication key is missing while {description} exist; refusing to establish a replacement key epoch"
            );
        }
    }
    state_root.verify()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyBootstrapFaultPoint {
    AfterKey,
    AfterEpoch,
}

#[cfg(test)]
thread_local! {
    static KEY_BOOTSTRAP_FAULT: std::cell::Cell<Option<KeyBootstrapFaultPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_key_bootstrap_fault(point: KeyBootstrapFaultPoint) {
    KEY_BOOTSTRAP_FAULT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn run_key_bootstrap_fault(point: KeyBootstrapFaultPoint) -> Result<()> {
    let should_fail = KEY_BOOTSTRAP_FAULT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        bail!("injected repository authentication bootstrap fault after {point:?}");
    }
    Ok(())
}

#[cfg(not(test))]
fn run_key_bootstrap_fault(_point: KeyBootstrapFaultPoint) -> Result<()> {
    Ok(())
}

fn validate_auth_input(domain: AuthenticationDomain, payload: &[u8]) -> Result<()> {
    if domain.0.is_empty()
        || domain.0.len() > MAX_AUTH_DOMAIN_BYTES
        || !domain.0.starts_with(b"MACO\0")
        || payload.len() > MAX_AUTH_PAYLOAD_BYTES
    {
        bail!("authentication domain or payload exceeds its bounded canonical format");
    }
    Ok(())
}

fn framed_auth_message(domain: AuthenticationDomain, payload: &[u8]) -> Result<Vec<u8>> {
    validate_auth_input(domain, payload)?;
    let domain_len = u64::try_from(domain.0.len()).context("auth domain length overflowed")?;
    let payload_len = u64::try_from(payload.len()).context("auth payload length overflowed")?;
    let mut message = Vec::with_capacity(
        AUTH_FRAME_MAGIC
            .len()
            .saturating_add(16)
            .saturating_add(domain.0.len())
            .saturating_add(payload.len()),
    );
    message.extend_from_slice(AUTH_FRAME_MAGIC);
    message.extend_from_slice(&domain_len.to_be_bytes());
    message.extend_from_slice(domain.0);
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

pub(crate) fn validate_repository_binding(binding: &RepositoryAuthBinding) -> Result<()> {
    if binding.version != AUTH_BINDING_VERSION
        || !is_canonical_lower_hex_64(&binding.repository_id)
        || !is_canonical_lower_hex_64(&binding.common_dir_path_sha256)
        || binding.common_dir_identity.file == 0
        || binding.key_identity.file == 0
    {
        bail!("repository authentication binding is malformed or unsupported");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_auth_file(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect authentication file {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!("repository authentication key is not a private single-link regular file");
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn ensure_private_auth_file(path: &Path) -> Result<FileIdentity> {
    bail!(
        "repository authentication key ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0_usize;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(
                bytes[filled..].as_mut_ptr().cast(),
                bytes.len().saturating_sub(filled),
                0,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("OS getrandom failed for repository authentication key");
        }
        let read = usize::try_from(result).context("OS random byte count overflow")?;
        if read == 0 {
            bail!("OS getrandom returned zero bytes for repository authentication key");
        }
        filled = filled
            .checked_add(read)
            .context("OS random fill count overflow")?;
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    use std::{
        io::Read,
        os::unix::{fs::FileTypeExt, fs::OpenOptionsExt},
    };
    let mut source = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .context("failed to open OS random source")?;
    if !source.metadata()?.file_type().is_char_device() {
        bail!("OS random source is not a character device");
    }
    source
        .read_exact(bytes)
        .context("failed to read repository authentication key from OS random source")
}

#[cfg(target_os = "windows")]
fn fill_os_random(bytes: &mut [u8]) -> Result<()> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut core::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = u32::try_from(bytes.len()).context("random request exceeds Windows API limit")?;
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        bail!("BCryptGenRandom failed with NTSTATUS {status:#x}");
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn fill_os_random(_bytes: &mut [u8]) -> Result<()> {
    bail!("repository authentication key generation is unsupported on this platform")
}

pub(crate) fn sha256_hex(input: &[u8]) -> String {
    hex_encode(&sha256_bytes(input))
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
        zeroize(&mut words);
    }
    let mut output = [0_u8; 32];
    for (index, word) in hash.iter().enumerate() {
        let offset = index.saturating_mul(4);
        output[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    zeroize(&mut message);
    zeroize(&mut hash);
    output
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded_key = [0_u8; 64];
    let mut hashed_key = [0_u8; 32];
    if key.len() > padded_key.len() {
        hashed_key = sha256_bytes(key);
        padded_key[..32].copy_from_slice(&hashed_key);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= padded_key[index];
        outer_pad[index] ^= padded_key[index];
    }
    let mut inner = Vec::with_capacity(inner_pad.len().saturating_add(message.len()));
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let mut inner_digest = sha256_bytes(&inner);
    let mut outer = Vec::with_capacity(outer_pad.len().saturating_add(inner_digest.len()));
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    let output = sha256_bytes(&outer);
    zeroize(&mut padded_key);
    zeroize(&mut hashed_key);
    zeroize(&mut inner_pad);
    zeroize(&mut outer_pad);
    zeroize(&mut inner);
    zeroize(&mut inner_digest);
    zeroize(&mut outer);
    output
}

fn zeroize<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // Volatile stores keep the wipe observable to the abstract machine so
        // it is not optimized away after the last secret use.
        unsafe { std::ptr::write_volatile(value, T::default()) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn is_canonical_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::err_expect)]
    use super::*;
    use git2::Repository;
    use tempfile::TempDir;

    fn repository() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        let repository = Repository::init(&path).expect("repository");
        (temp, repository.commondir().to_path_buf())
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hex_encode(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn framed_authentication_separates_domain_and_payload_boundaries() {
        let left =
            framed_auth_message(AuthenticationDomain::new(b"MACO\0a"), b"bc").expect("left frame");
        let right =
            framed_auth_message(AuthenticationDomain::new(b"MACO\0ab"), b"c").expect("right frame");
        assert_ne!(left, right);
    }

    #[test]
    fn secret_authenticator_api_remains_opaque() {
        let source = include_str!("state_auth.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production auth source");
        let declaration = production
            .find("pub(crate) struct RepositoryAuthenticator")
            .expect("authenticator declaration");
        let declaration_context = &production[declaration.saturating_sub(256)..declaration];
        assert!(!declaration_context.contains("derive(Debug"));
        assert!(!declaration_context.contains("derive(Clone"));
        for forbidden in [
            "impl Debug for RepositoryAuthenticator",
            "impl Clone for RepositoryAuthenticator",
            "fn raw_key(",
            "fn key_bytes(",
            "fn secret_key(",
        ] {
            assert!(
                !production.contains(forbidden),
                "secret API exposed forbidden surface: {forbidden}"
            );
        }
        assert!(production.contains("std::ptr::write_volatile"));
        assert!(!production.contains(".fill(0)"));
    }

    #[test]
    fn key_first_bootstrap_recovers_when_epoch_write_never_started() {
        let (_temp, common_dir) = repository();
        set_key_bootstrap_fault(KeyBootstrapFaultPoint::AfterKey);
        let error = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .err()
            .expect("injected fault");
        assert!(error.to_string().contains("AfterKey"));
        let state = common_dir.join("maco/state");
        let key = state.join(AUTH_KEY_FILE);
        let epoch = state.join(AUTH_EPOCH_FILE);
        let original_key = fs::read(&key).expect("durable key");
        assert!(!epoch.exists());

        let writer = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .expect("recover missing epoch");
        writer.verify().expect("recovered writer");
        assert_eq!(fs::read(key).expect("preserved key"), original_key);
        assert_eq!(fs::read(epoch).expect("epoch").len(), AUTH_EPOCH_BYTES);
    }

    #[test]
    fn completed_epoch_write_is_idempotently_reopened_after_fault() {
        let (_temp, common_dir) = repository();
        set_key_bootstrap_fault(KeyBootstrapFaultPoint::AfterEpoch);
        RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .err()
            .expect("injected fault");
        let state = common_dir.join("maco/state");
        let key = fs::read(state.join(AUTH_KEY_FILE)).expect("key");
        let epoch = fs::read(state.join(AUTH_EPOCH_FILE)).expect("epoch");

        let writer = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .expect("idempotent reopen");
        writer.verify().expect("writer");
        assert_eq!(fs::read(state.join(AUTH_KEY_FILE)).expect("key"), key);
        assert_eq!(fs::read(state.join(AUTH_EPOCH_FILE)).expect("epoch"), epoch);
    }

    #[test]
    fn registered_authenticated_consumer_refuses_first_key() {
        let (_temp, common_dir) = repository();
        let state = SafeRoot::open_or_create(common_dir.join("maco/state")).expect("state root");
        SafeRoot::open_or_create(state.path().join("authenticated-effect-wals-v1"))
            .expect("consumer root");

        let error = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .err()
            .expect("must refuse rekey");
        assert!(error.to_string().contains("authenticated effect WALs"));
        assert!(!state.path().join(AUTH_KEY_FILE).exists());
    }

    #[test]
    fn authenticated_field_guide_refuses_first_key() {
        let (_temp, common_dir) = repository();
        let state = SafeRoot::open_or_create(common_dir.join("maco/state")).expect("state root");
        SafeRoot::open_or_create(state.path().join(FIELD_GUIDE_STATE_NAMESPACE))
            .expect("field guide consumer root");

        let error = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .err()
            .expect("must refuse replacement epoch");

        assert!(error
            .to_string()
            .contains("authenticated field guide state"));
        assert!(!state.path().join(AUTH_KEY_FILE).exists());
    }

    #[test]
    fn orphaned_megafile_history_refuses_replacement_key_epoch() {
        let (_temp, common_dir) = repository();
        let state = SafeRoot::open_or_create(common_dir.join("maco/state")).expect("state root");
        SafeRoot::open_or_create(state.path().join("authenticated-megafile-history-v1"))
            .expect("megafile consumer root");

        let error = RepositoryAuthWriter::open_or_create(&common_dir, |_| Ok(()))
            .err()
            .expect("must refuse replacement epoch");

        assert!(error.to_string().contains("authenticated megafile history"));
        assert!(!state.path().join(AUTH_KEY_FILE).exists());
    }
}
