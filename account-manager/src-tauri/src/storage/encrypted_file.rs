//! Encrypted-file fallback store.
//!
//! Used only when no OS credential service is available — headless Linux, and
//! the Docker relay that `FR-10` requires. The file lives at a caller-supplied
//! path (tests inject a `tempfile`; production uses [`EncryptedFileStore::default_path`]),
//! is written through [`crate::fsx`] so a replace is atomic and owner-only, and
//! is encrypted with a key derived from a user passphrase.
//!
//! There is no plaintext mode, behind any flag (`docs/adr/0003`). If no
//! passphrase has been supplied the store is unavailable and says so; it never
//! degrades. A forgotten passphrase cannot be recovered — the accounts must be
//! re-added. That is stated here and in the error wording so it is not
//! discovered later.
//!
//! # File format
//!
//! A versioned JSON envelope. Binary fields are standard base64.
//!
//! | Field            | Why it is there                                                                                          |
//! | ---------------- | -------------------------------------------------------------------------------------------------------- |
//! | `schemaVersion`  | Lets an older build refuse a newer file instead of best-effort parsing it (`docs/ARCHITECTURE.md` §7).   |
//! | `kdf`            | Algorithm, version, memory, iterations, parallelism, output length — recorded so tomorrow's parameters   |
//! |                  | can be adopted on the next write without orphaning today's file.                                         |
//! | `salt`           | Per-installation random salt for Argon2id. Never a hard-coded value.                                     |
//! | `nonce`          | Fresh random 96-bit nonce for ChaCha20-Poly1305, unique per write.                                       |
//! | `keyCheck`       | Extra 16 bytes of KDF output, compared in constant time, so a wrong passphrase is reported distinctly    |
//! |                  | from a flipped ciphertext (which still matches `keyCheck` and then fails AEAD).                          |
//! | `ciphertext`     | ChaCha20-Poly1305 over the whole secret map. Tampering fails authentication; nothing is partially trusted.|
//!
//! A newer-than-known `schemaVersion` is a refusal to read **or** write. An
//! older build must never silently downgrade a newer file.
//!
//! # What the errors distinguish
//!
//! - **Missing file.** `get` / `delete` treat it as an empty map (`Ok(None)` /
//!   success). The store is created on the first `put`.
//! - **Wrong passphrase.** `keyCheck` does not match. The message says so and
//!   that there is no recovery.
//! - **Tampered or corrupt.** Envelope parse fails, or `keyCheck` matches and
//!   AEAD authentication does not. The file is left untouched.
//!
//! Nothing secret is placed in an error: not the passphrase, not a key, not a
//! [`SecretRef`]'s value, not a decrypted byte (`NFR-1`, threat T2). A path is
//! safe and is included.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CredentialStore, Secret, SecretRef};
use crate::error::{Error, Result};

/// Schema this build writes and is willing to read.
const SCHEMA_VERSION: u32 = 1;

/// File name under the platform application data directory.
const FILE_NAME: &str = "credentials.enc.json";

/// OWASP Password Storage Cheat Sheet (interactive Argon2id): 19 MiB, 2
/// iterations, 1 lane. Recorded in the file so they can be raised later.
/// Chosen over RFC 9106's 64 MiB option because this path also serves the
/// memory-constrained Docker relay (`FR-10`).
const KDF_ALGORITHM: &str = "argon2id";
const KDF_VERSION: u32 = 0x13;
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const CHECK_LEN: usize = 16;
const OUTPUT_LEN: usize = KEY_LEN + CHECK_LEN;

/// Caps applied when *reading* parameters from a file, so a tampered envelope
/// cannot ask this process to allocate gigabytes or spin for hours.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 16;
const MAX_PARALLELISM: u32 = 16;
const MAX_OUTPUT_LEN: usize = 64;

/// Fallback store for hosts with no OS credential service.
///
/// Construct with [`EncryptedFileStore::new`] (locked, unavailable) or
/// [`EncryptedFileStore::unlock`] (passphrase supplied). There is no recovery
/// from a forgotten passphrase; the accounts must be re-added.
///
/// Deliberately implements neither `Debug` nor `Default`: a debug print would
/// be a path to the passphrase, and a default constructor would hide the path
/// parameter that keeps tests off a real data directory.
pub struct EncryptedFileStore {
    path: PathBuf,
    /// Present only after [`EncryptedFileStore::unlock`]. Zeroed on drop.
    passphrase: Option<Secret>,
}

impl EncryptedFileStore {
    /// Locked store at `path`. [`CredentialStore::is_available`] is `false`
    /// until the same path is opened with [`EncryptedFileStore::unlock`].
    ///
    /// Does not resolve [`default_path`]; callers that want the platform
    /// location pass it in explicitly.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            passphrase: None,
        }
    }

    /// Unlocked store at `path`. Available for `put` / `get` / `delete`.
    ///
    /// There is no recovery from a forgotten passphrase (`docs/adr/0003`);
    /// the accounts must be re-added.
    pub fn unlock(path: PathBuf, passphrase: Secret) -> Self {
        Self {
            path,
            passphrase: Some(passphrase),
        }
    }

    /// Platform application-data path for a real installation.
    ///
    /// Never called from a constructor: a store always takes its path, so no
    /// test can reach a user's data directory by accident.
    pub fn default_path() -> Result<PathBuf> {
        crate::paths::project_dirs()
            .map(|dirs| dirs.data_dir().join(FILE_NAME))
            .ok_or_else(|| {
                Error::CredentialStoreUnavailable(
                    "could not resolve the application data directory for the encrypted-file store"
                        .to_owned(),
                )
            })
    }

    fn passphrase(&self) -> Result<&Secret> {
        self.passphrase.as_ref().ok_or_else(|| {
            Error::CredentialStoreUnavailable(
                "encrypted-file store is locked: no passphrase has been provided".to_owned(),
            )
        })
    }

    fn load_map(&self) -> Result<SecretMap> {
        let passphrase = self.passphrase()?;
        match fs::read(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SecretMap::default()),
            Err(error) => Err(crate::fsx::io_at(&self.path, error)),
            Ok(bytes) => decrypt_map(&self.path, &bytes, passphrase),
        }
    }

    fn save_map(&self, map: &SecretMap) -> Result<()> {
        let passphrase = self.passphrase()?;
        let encoded = encrypt_map(map, passphrase)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::fsx::create_dir_all_private(parent)?;
            }
        }
        crate::fsx::write_atomic(&self.path, &encoded)
    }
}

impl CredentialStore for EncryptedFileStore {
    fn id(&self) -> &'static str {
        "encrypted-file"
    }

    fn is_available(&self) -> bool {
        // Stay false until a passphrase has actually unlocked the file.
        // Returning true here would make `default_store` hand back a store
        // that fails on first use, which that function exists to prevent.
        self.passphrase.is_some()
    }

    fn put(&self, key: &SecretRef, secret: &Secret) -> Result<()> {
        let mut map = self.load_map()?;
        if let Some(mut previous) = map.0.insert(key.0.clone(), secret.expose().to_vec()) {
            previous.zeroize();
        }
        self.save_map(&map)
    }

    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        let mut map = self.load_map()?;
        Ok(map.0.remove(&key.0).map(Secret::new))
    }

    fn delete(&self, key: &SecretRef) -> Result<()> {
        // Passphrase first: a locked store must not report success just
        // because the file is missing. The file-existence check after that
        // avoids creating an empty store when there is nothing to delete.
        self.passphrase()?;
        if !self.path.is_file() {
            return Ok(());
        }
        let mut map = self.load_map()?;
        if let Some(mut previous) = map.0.remove(&key.0) {
            previous.zeroize();
        }
        self.save_map(&map)
    }
}

/// In-memory decrypted map. Values are zeroed on drop so plaintext does not
/// linger past the operation that needed it.
#[derive(Default)]
struct SecretMap(HashMap<String, Vec<u8>>);

impl Drop for SecretMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Derived {
    key: [u8; KEY_LEN],
    check: [u8; CHECK_LEN],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    schema_version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    key_check: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    version: u32,
    #[serde(rename = "memoryKiB")]
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    #[serde(rename = "outputLength")]
    output_length: usize,
}

impl KdfParams {
    fn current() -> Self {
        Self {
            algorithm: KDF_ALGORITHM.to_owned(),
            version: KDF_VERSION,
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            parallelism: PARALLELISM,
            output_length: OUTPUT_LEN,
        }
    }
}

/// The part of an envelope that must be readable at every schema version.
///
/// Parsed before the strict [`Envelope`] so a newer file with a renamed
/// field is refused as newer, not misreported as corrupt.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaProbe {
    schema_version: u32,
}

fn decrypt_map(path: &Path, bytes: &[u8], passphrase: &Secret) -> Result<SecretMap> {
    let probe: SchemaProbe = serde_json::from_slice(bytes).map_err(|_| corrupt(path))?;
    refuse_newer_schema(path, probe.schema_version)?;

    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| corrupt(path))?;
    if envelope.schema_version < 1 {
        return Err(corrupt(path));
    }

    let derived = derive(passphrase, &envelope)?;
    if !ct_eq(
        &derived.check,
        &decode_exact(path, &envelope.key_check, CHECK_LEN)?,
    ) {
        return Err(wrong_passphrase(path));
    }

    let nonce = decode_exact(path, &envelope.nonce, NONCE_LEN)?;
    let ciphertext = decode_b64(path, &envelope.ciphertext)?;
    let plaintext = Secret::new(
        aead_decrypt(&derived.key, &nonce, &ciphertext).map_err(|_| {
            // keyCheck matched, so the passphrase is right and the bytes are not.
            tampered(path)
        })?,
    );

    let parsed: HashMap<String, Vec<u8>> =
        serde_json::from_slice(plaintext.expose()).map_err(|_| corrupt(path))?;
    Ok(SecretMap(parsed))
}

fn encrypt_map(map: &SecretMap, passphrase: &Secret) -> Result<Vec<u8>> {
    let mut plaintext = Secret::new(serde_json::to_vec(&map.0).map_err(|_| {
        Error::CredentialStoreUnavailable("could not serialise the credential map".to_owned())
    })?);

    let salt = random_bytes::<SALT_LEN>();
    // A fresh random nonce on every write. ChaCha20-Poly1305 is a stream
    // cipher plus Poly1305: the keystream is a function of (key, nonce) only.
    // Reusing a nonce under the same key XORs the two plaintexts together
    // (anyone who sees both ciphertexts recovers `P1 XOR P2`) and, worse,
    // lets an attacker forge Poly1305 tags for other messages under that
    // key. A 96-bit random nonce per write keeps reuse negligible for the
    // number of writes this file will ever see.
    let nonce = random_bytes::<NONCE_LEN>();
    let kdf = KdfParams::current();
    let derived = derive_with(&kdf, passphrase, &salt)?;
    let ciphertext = aead_encrypt(&derived.key, &nonce, plaintext.expose())?;
    plaintext.zeroize();

    let envelope = Envelope {
        schema_version: SCHEMA_VERSION,
        kdf,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        key_check: STANDARD.encode(derived.check),
        ciphertext: STANDARD.encode(ciphertext),
    };
    serde_json::to_vec_pretty(&envelope).map_err(|_| {
        Error::CredentialStoreUnavailable("could not serialise the credential envelope".to_owned())
    })
}

fn refuse_newer_schema(path: &Path, schema_version: u32) -> Result<()> {
    if schema_version > SCHEMA_VERSION {
        return Err(Error::CredentialStoreUnavailable(format!(
            "encrypted credential file at {} has schema version {schema_version}, \
             which this build does not understand; refusing to read or write",
            path.display()
        )));
    }
    Ok(())
}

fn derive(passphrase: &Secret, envelope: &Envelope) -> Result<Derived> {
    let salt = decode_b64_pathless(&envelope.salt)?;
    derive_with(&envelope.kdf, passphrase, &salt)
}

fn derive_with(kdf: &KdfParams, passphrase: &Secret, salt: &[u8]) -> Result<Derived> {
    if kdf.algorithm != KDF_ALGORITHM {
        return Err(Error::CredentialStoreUnavailable(format!(
            "encrypted credential file uses unrecognised KDF `{}`",
            kdf.algorithm
        )));
    }
    if kdf.memory_kib > MAX_MEMORY_KIB
        || kdf.iterations > MAX_ITERATIONS
        || kdf.parallelism > MAX_PARALLELISM
        || kdf.output_length > MAX_OUTPUT_LEN
    {
        return Err(Error::CredentialStoreUnavailable(
            "encrypted credential file names Argon2 parameters this build will not honour"
                .to_owned(),
        ));
    }
    let version = Version::try_from(kdf.version).map_err(|_| {
        Error::CredentialStoreUnavailable(
            "encrypted credential file names an Argon2 version this build does not understand"
                .to_owned(),
        )
    })?;
    if kdf.output_length < OUTPUT_LEN {
        return Err(corrupt_kind("KDF output length"));
    }
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(kdf.output_length),
    )
    .map_err(|_| corrupt_kind("Argon2 parameters"))?;

    let mut output = vec![0u8; kdf.output_length];
    Argon2::new(Algorithm::Argon2id, version, params)
        .hash_password_into(passphrase.expose(), salt, &mut output)
        .map_err(|_| {
            Error::CredentialStoreUnavailable(
                "could not derive a key from the passphrase".to_owned(),
            )
        })?;

    let mut derived = Derived {
        key: [0u8; KEY_LEN],
        check: [0u8; CHECK_LEN],
    };
    derived.key.copy_from_slice(&output[..KEY_LEN]);
    derived
        .check
        .copy_from_slice(&output[KEY_LEN..KEY_LEN + CHECK_LEN]);
    output.zeroize();
    Ok(derived)
}

fn aead_encrypt(key: &[u8; KEY_LEN], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = nonce_from(nonce)?;
    cipher.encrypt(&nonce, plaintext).map_err(|_| {
        Error::CredentialStoreUnavailable("could not encrypt the credential file".to_owned())
    })
}

fn aead_decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = nonce_from(nonce)?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::CredentialStoreUnavailable("authentication failed".to_owned()))
}

fn nonce_from(bytes: &[u8]) -> Result<Nonce> {
    let array: [u8; NONCE_LEN] = bytes.try_into().map_err(|_| corrupt_kind("nonce length"))?;
    Ok(Nonce::from(array))
}

fn decode_exact(path: &Path, value: &str, expected: usize) -> Result<Vec<u8>> {
    let bytes = decode_b64(path, value)?;
    if bytes.len() != expected {
        return Err(corrupt(path));
    }
    Ok(bytes)
}

fn decode_b64(path: &Path, value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| corrupt(path))
}

fn decode_b64_pathless(value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| corrupt_kind("salt"))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Length is public (fixed). Compared in constant time so a wrong passphrase
/// does not leak the check via an early exit.
fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn wrong_passphrase(path: &Path) -> Error {
    Error::CredentialStoreUnavailable(format!(
        "wrong passphrase for the encrypted credential file at {}; \
         a forgotten passphrase cannot be recovered and the accounts must be re-added",
        path.display()
    ))
}

fn tampered(path: &Path) -> Error {
    Error::CredentialStoreUnavailable(format!(
        "encrypted credential file at {} failed authentication and is treated as \
         tampered or corrupt; it has not been rewritten",
        path.display()
    ))
}

fn corrupt(path: &Path) -> Error {
    Error::CredentialStoreUnavailable(format!(
        "encrypted credential file at {} is corrupt or unreadable; it has not been rewritten",
        path.display()
    ))
}

fn corrupt_kind(what: &str) -> Error {
    Error::CredentialStoreUnavailable(format!(
        "encrypted credential file is corrupt ({what}); it has not been rewritten"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"FAKE-passphrase-0001";
    const OTHER_PASSPHRASE: &[u8] = b"FAKE-passphrase-0002";
    const TOKEN: &[u8] = b"FAKE-access-token-0001";

    fn unlocked(dir: &tempfile::TempDir) -> EncryptedFileStore {
        EncryptedFileStore::unlock(dir.path().join(FILE_NAME), Secret::new(PASSPHRASE.to_vec()))
    }

    fn key() -> SecretRef {
        SecretRef::for_account("test-provider", "round-trip")
    }

    fn assert_no_leak(message: &str) {
        assert!(
            !message.contains("FAKE-"),
            "error leaked a FAKE- value: {message}"
        );
        assert!(
            !message.contains(std::str::from_utf8(PASSPHRASE).expect("utf8")),
            "error leaked the passphrase: {message}"
        );
        assert!(
            !message.contains(std::str::from_utf8(OTHER_PASSPHRASE).expect("utf8")),
            "error leaked the other passphrase: {message}"
        );
    }

    /// `Result::expect` needs `Debug` on the success type, and `Secret` must
    /// not implement it. Inspect through `Display` on the error instead.
    fn get_ok(store: &EncryptedFileStore, key: &SecretRef) -> Option<Secret> {
        match store.get(key) {
            Ok(value) => value,
            Err(error) => panic!("get failed: {error}"),
        }
    }

    fn get_err(store: &EncryptedFileStore, key: &SecretRef) -> Error {
        match store.get(key) {
            Ok(None) => panic!("get returned None"),
            Ok(Some(_)) => panic!("get returned a secret"),
            Err(error) => error,
        }
    }

    #[test]
    fn locked_store_is_not_available() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EncryptedFileStore::new(dir.path().join(FILE_NAME));
        assert!(!store.is_available());
        assert_eq!(store.id(), "encrypted-file");
    }

    #[test]
    fn locked_store_errors_on_get_and_delete_when_the_file_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let store = EncryptedFileStore::new(path.clone());
        assert!(!path.is_file(), "the locked-store file must not exist");

        let get_message = get_err(&store, &key()).to_string();
        assert!(get_message.contains("locked"), "{get_message}");
        assert_no_leak(&get_message);

        let delete_message = match store.delete(&key()) {
            Ok(()) => panic!("delete succeeded on a locked missing file"),
            Err(error) => error.to_string(),
        };
        assert!(delete_message.contains("locked"), "{delete_message}");
        assert_no_leak(&delete_message);
    }

    #[test]
    fn round_trip_put_get_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        assert!(store.is_available());

        let key = key();
        store.put(&key, &Secret::new(TOKEN.to_vec())).expect("put");

        let Some(found) = get_ok(&store, &key) else {
            panic!("stored entry missing");
        };
        assert_eq!(found.expose(), TOKEN);

        store.delete(&key).expect("delete");
        assert!(get_ok(&store, &key).is_none());
        store.delete(&key).expect("delete is idempotent");
    }

    #[test]
    fn get_of_a_missing_key_is_ok_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        assert!(get_ok(&store, &key()).is_none());
    }

    #[test]
    fn wrong_passphrase_fails_distinctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let writer = EncryptedFileStore::unlock(path.clone(), Secret::new(PASSPHRASE.to_vec()));
        writer
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect("put");

        let reader = EncryptedFileStore::unlock(path, Secret::new(OTHER_PASSPHRASE.to_vec()));
        let error = get_err(&reader, &key());
        let message = error.to_string();
        assert!(message.contains("wrong passphrase"), "{message}");
        assert!(message.contains("cannot be recovered"), "{message}");
        assert!(!message.contains("tamper"), "{message}");
        assert_no_leak(&message);
    }

    #[test]
    fn flipped_ciphertext_byte_fails_authentication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        store
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect("put");

        let path = dir.path().join(FILE_NAME);
        let raw = fs::read(&path).expect("read envelope");
        let mut envelope: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        let ciphertext = STANDARD
            .decode(envelope["ciphertext"].as_str().expect("ciphertext field"))
            .expect("ciphertext b64");
        let mut flipped = ciphertext;
        flipped[0] ^= 0x01;
        envelope["ciphertext"] = serde_json::Value::String(STANDARD.encode(flipped));
        fs::write(&path, serde_json::to_vec(&envelope).expect("rewrite")).expect("write");

        let error = get_err(&store, &key());
        let message = error.to_string();
        assert!(
            message.contains("authentication") || message.contains("tampered"),
            "{message}"
        );
        assert!(!message.contains("wrong passphrase"), "{message}");
        assert_no_leak(&message);
    }

    #[test]
    fn higher_schema_version_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        store
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect("put");

        let path = dir.path().join(FILE_NAME);
        let raw = fs::read(&path).expect("read envelope");
        let mut envelope: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        envelope["schemaVersion"] = serde_json::json!(SCHEMA_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&envelope).expect("rewrite")).expect("write");

        let read_error = get_err(&store, &key());
        let read_message = read_error.to_string();
        assert!(read_message.contains("schema version"), "{read_message}");
        assert!(read_message.contains("refusing"), "{read_message}");
        assert_no_leak(&read_message);

        let write_error = store
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect_err("newer schema must refuse write");
        let write_message = write_error.to_string();
        assert!(write_message.contains("schema version"), "{write_message}");
        assert!(write_message.contains("refusing"), "{write_message}");
        assert_no_leak(&write_message);
    }

    #[test]
    fn newer_schema_with_a_renamed_field_is_refused_not_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        store
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect("put");

        let path = dir.path().join(FILE_NAME);
        let raw = fs::read(&path).expect("read envelope");
        let mut envelope: serde_json::Value = serde_json::from_slice(&raw).expect("json");
        envelope["schemaVersion"] = serde_json::json!(SCHEMA_VERSION + 1);
        let ciphertext = envelope
            .as_object_mut()
            .expect("object")
            .remove("ciphertext")
            .expect("ciphertext");
        envelope["payload"] = ciphertext;
        fs::write(&path, serde_json::to_vec(&envelope).expect("rewrite")).expect("write");

        let error = get_err(&store, &key());
        let message = error.to_string();
        assert!(message.contains("schema version"), "{message}");
        assert!(message.contains("refusing"), "{message}");
        assert!(!message.contains("corrupt"), "{message}");
        assert_no_leak(&message);
    }

    #[cfg(unix)]
    #[test]
    fn written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = unlocked(&dir);
        store
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect("put");

        let mode = fs::metadata(dir.path().join(FILE_NAME))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn errors_never_contain_a_secret_or_the_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = EncryptedFileStore::new(dir.path().join(FILE_NAME));
        let locked_message = locked
            .put(&key(), &Secret::new(TOKEN.to_vec()))
            .expect_err("locked put")
            .to_string();
        assert_no_leak(&locked_message);

        // A missing file is not an error on get; pin that so it cannot later
        // collapse into "wrong passphrase" or "corrupt".
        let missing = unlocked(&dir);
        assert!(get_ok(&missing, &key()).is_none());
    }
}
