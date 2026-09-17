//! Credential and application-state storage.
//!
//! Two rules govern everything in this module:
//!
//! 1. A secret never leaves this module in plaintext except to the adapter that
//!    is about to write it into its tool's own config.
//! 2. A secret is never logged, never serialised into diagnostics, and never
//!    included in an error message.
//!
//! See `docs/SECURITY_MODEL.md`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub mod encrypted_file;
pub mod keychain;

/// What the user is told when nothing can hold a secret safely.
///
/// `docs/adr/0003` forbids a plaintext mode, so the only honest answer here is
/// a refusal plus the two things that would fix it. Kept as one constant so the
/// wording cannot drift between call sites.
const NO_STORE_AVAILABLE: &str = "no OS credential service is reachable and no encrypted-file \
     passphrase has been set. On Linux, install and start a Secret Service provider such as \
     gnome-keyring or KWallet; on macOS or Windows, unlock the system keychain. Secrets are \
     never stored in plaintext.";

/// Opaque handle to a stored secret.
///
/// The application passes handles around; only [`CredentialStore`] can turn one
/// back into secret material. The inner string is deliberately private: it is a
/// storage key, and backends read it through the module-private field rather
/// than through a public accessor that would invite building keys by hand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef(String);

impl SecretRef {
    /// Derive the storage key for one provider account.
    ///
    /// The result becomes the entry name in the user's OS keychain, so the
    /// format is effectively permanent: changing it orphans every secret
    /// already stored and leaves the user with two sets of entries they cannot
    /// tell apart. `secret_ref_format_is_pinned` guards it for that reason.
    pub fn for_account(provider_id: &str, account_id: &str) -> Self {
        Self(format!("{provider_id}/{account_id}"))
    }
}

/// Secret material, in memory, for as short a time as possible.
///
/// Deliberately implements neither `Debug`, `Display`, `Serialize`, nor `Clone`,
/// so it cannot be logged, serialised, or quietly duplicated into a buffer that
/// nothing zeroes. `zeroize` supplies the `Drop` implementation, which means the
/// guarantee is the derive's, not a hand-written loop a later edit could drop.
///
/// Printing one does not compile:
///
/// ```compile_fail
/// use coding_agent_manager_lib::storage::Secret;
/// let secret = Secret::new(b"FAKE-token".to_vec());
/// println!("{secret:?}");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The single, greppable way to reach the bytes.
    ///
    /// A review that wants to find every place a secret is read greps for
    /// `expose(`; keep it that way and do not add a second accessor.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Backend-agnostic secret storage.
pub trait CredentialStore: Send + Sync {
    /// Short identifier used in settings and diagnostics, e.g. `keychain`.
    fn id(&self) -> &'static str;

    /// Whether this backend can be used on this machine right now.
    ///
    /// Implementations must probe without mutating: a headless Linux host with
    /// no Secret Service is an ordinary, expected answer of `false`, not an
    /// error, and never a reason to write anything anywhere.
    fn is_available(&self) -> bool;

    fn put(&self, key: &SecretRef, secret: &Secret) -> Result<()>;
    fn get(&self, key: &SecretRef) -> Result<Option<Secret>>;
    fn delete(&self, key: &SecretRef) -> Result<()>;
}

/// Select the best available backend: OS keychain first, encrypted file second.
///
/// Returns an error rather than a store that will fail on first use. Per
/// `docs/adr/0003` and `docs/ARCHITECTURE.md` §8, when nothing can hold a secret
/// safely the application refuses and explains; it never degrades to plaintext.
pub fn default_store() -> Result<Box<dyn CredentialStore>> {
    // SEAM for the encrypted-file worker: this list is preference order, and
    // `first_available` picks the first entry whose `is_available()` is true.
    // `EncryptedFileStore::is_available()` must stay `false` until a passphrase
    // has actually unlocked the file; returning `true` before then would make
    // this function hand back a store that fails on first use, which is exactly
    // what it exists to prevent. The encrypted-file candidate is included only
    // when `default_path()` resolves; a resolution failure falls through to
    // the same refusal as "nothing available", rather than constructing a
    // store at the empty path.
    let mut candidates: Vec<Box<dyn CredentialStore>> = vec![Box::new(keychain::KeychainStore)];
    if let Ok(path) = encrypted_file::EncryptedFileStore::default_path() {
        candidates.push(Box::new(encrypted_file::EncryptedFileStore::new(path)));
    }
    first_available(candidates)
}

/// Pick the first usable store, or explain why there is none.
///
/// Split out from [`default_store`] so the selection rule can be tested against
/// stub stores, without depending on whatever credential services happen to be
/// running on the machine running the tests.
fn first_available(candidates: Vec<Box<dyn CredentialStore>>) -> Result<Box<dyn CredentialStore>> {
    candidates
        .into_iter()
        .find(|store| store.is_available())
        .ok_or_else(|| Error::CredentialStoreUnavailable(NO_STORE_AVAILABLE.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;

    /// A store whose availability the test decides, so selection can be tested
    /// without a live keychain.
    struct StubStore {
        id: &'static str,
        available: bool,
    }

    impl CredentialStore for StubStore {
        fn id(&self) -> &'static str {
            self.id
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn put(&self, _key: &SecretRef, _secret: &Secret) -> Result<()> {
            Ok(())
        }

        fn get(&self, _key: &SecretRef) -> Result<Option<Secret>> {
            Ok(None)
        }

        fn delete(&self, _key: &SecretRef) -> Result<()> {
            Ok(())
        }
    }

    fn stub(id: &'static str, available: bool) -> Box<dyn CredentialStore> {
        Box::new(StubStore { id, available })
    }

    #[test]
    fn secret_bytes_are_zeroed_rather_than_merely_dropped() {
        let mut secret = Secret::new(b"FAKE-access-token-0001".to_vec());
        let length = secret.expose().len();

        secret.zeroize();

        // `Vec::zeroize` overwrites the initialised bytes *and* the spare
        // capacity before truncating, so the original bytes are still inside an
        // allocation this test owns. Reading them back is sound — the buffer is
        // alive and every byte in it was just written — and it is the only way
        // to observe that the material is gone rather than simply unreachable.
        let spare = secret.0.spare_capacity_mut();
        assert!(spare.len() >= length, "capacity shrank; nothing to inspect");
        let bytes = unsafe { &*(spare as *const [MaybeUninit<u8>] as *const [u8]) };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "secret material survived zeroize"
        );
    }

    #[test]
    fn secret_is_zeroed_on_drop() {
        // Type-level half of the guarantee: the marker trait only exists if the
        // `ZeroizeOnDrop` derive is still on `Secret`, so deleting the derive
        // breaks this test rather than silently removing the wipe.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Secret>();
    }

    #[test]
    fn secret_ref_format_is_pinned() {
        // This string ends up in users' keychains. Changing it is a migration,
        // not a refactor.
        assert_eq!(
            SecretRef::for_account("claude-code", "work"),
            SecretRef("claude-code/work".to_owned())
        );
    }

    #[test]
    fn selection_prefers_the_first_available_store() {
        let chosen = first_available(vec![
            stub("unavailable", false),
            stub("keychain", true),
            stub("encrypted-file", true),
        ])
        .expect("a store was available");
        assert_eq!(chosen.id(), "keychain");
    }

    #[test]
    fn selection_refuses_when_nothing_is_available() {
        let error = first_available(vec![stub("keychain", false), stub("encrypted-file", false)])
            .err()
            .expect("selection must refuse rather than return a doomed store");
        assert!(matches!(error, Error::CredentialStoreUnavailable(_)));

        // The refusal has to tell the user what to do about it (ADR 0003).
        let message = error.to_string();
        assert!(message.contains("gnome-keyring"), "{message}");
        assert!(message.contains("passphrase"), "{message}");
    }
}
