//! OS-native credential storage.
//!
//! Target backends: macOS Keychain, Windows Credential Manager, and the
//! Freedesktop Secret Service (gnome-keyring / KWallet) on Linux. This is the
//! preferred store; the encrypted-file store exists only for hosts where no
//! Secret Service is running — headless Linux, for example.
//!
//! The `keyring` crate supplies the three platform integrations. Its errors are
//! never forwarded verbatim: `keyring::Error::BadEncoding` carries the stored
//! bytes and `Ambiguous` carries whole credential records, so forwarding
//! `Display` output would put secret material into a message the user sees
//! (`NFR-1`, threat T2). [`store_error`] maps each variant to wording of our
//! own and drops every payload.

use keyring::Entry;

use super::{CredentialStore, Secret, SecretRef};
use crate::error::{Error, Result};

/// The service name every secret is filed under.
///
/// This string is shown verbatim to the user by Keychain Access, Credential
/// Manager, and Seahorse, and it is part of the lookup key. It is therefore
/// effectively permanent: changing it orphans every secret already stored and
/// leaves the user staring at two indistinguishable sets of entries.
const SERVICE: &str = "coding-agent-manager";

/// Entry name used only by [`KeychainStore::is_available`].
///
/// Nothing is ever written under it. It exists so the probe has a name that is
/// guaranteed absent, which turns "the backend is reachable" into an ordinary
/// `NoEntry` answer instead of requiring a write.
const AVAILABILITY_PROBE_ENTRY: &str = "availability-probe (never stored)";

#[derive(Debug, Default)]
pub struct KeychainStore;

impl KeychainStore {
    fn entry(&self, key: &SecretRef) -> Result<Entry> {
        Entry::new(SERVICE, &key.0).map_err(|error| store_error("open", error))
    }
}

impl CredentialStore for KeychainStore {
    fn id(&self) -> &'static str {
        "keychain"
    }

    fn is_available(&self) -> bool {
        let Ok(entry) = Entry::new(SERVICE, AVAILABILITY_PROBE_ENTRY) else {
            return false;
        };
        // A read of a name that was never stored. A backend that answers "no
        // such entry" is a working backend; a backend that cannot answer at all
        // — no session bus, no Secret Service, a locked or denied store — is
        // unavailable, which on headless Linux is the expected case and must
        // stay quiet and cheap rather than becoming an error path.
        matches!(entry.get_secret(), Ok(_) | Err(keyring::Error::NoEntry))
    }

    fn put(&self, key: &SecretRef, secret: &Secret) -> Result<()> {
        self.entry(key)?
            .set_secret(secret.expose())
            .map_err(|error| store_error("write", error))
    }

    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        // `Ok(None)` and `Err(..)` mean different things to a caller: the first
        // is "no such account", the second is "the store is broken". Collapsing
        // them would let a switch silently treat a dead Secret Service as an
        // account that was never imported.
        match self.entry(key)?.get_secret() {
            Ok(bytes) => Ok(Some(Secret::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(store_error("read", error)),
        }
    }

    fn delete(&self, key: &SecretRef) -> Result<()> {
        // Deleting what is not there is a success: removing an account must not
        // fail because a previous removal was interrupted part-way.
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(store_error("delete", error)),
        }
    }
}

/// Translate a `keyring` failure into an error that carries the *kind* of
/// failure and nothing else.
///
/// Every payload is discarded on purpose. This costs some diagnostic detail,
/// which is the intended trade: `BadEncoding` holds the stored bytes verbatim,
/// and `Ambiguous` holds credential records including their attributes.
fn store_error(operation: &str, error: keyring::Error) -> Error {
    let reason = match error {
        keyring::Error::NoEntry => "no entry is stored under that key",
        keyring::Error::NoStorageAccess(_) => {
            "the OS credential service refused access; it may be locked"
        }
        keyring::Error::PlatformFailure(_) => "the OS credential service reported a failure",
        keyring::Error::BadEncoding(_) => "the stored entry is not in the expected encoding",
        keyring::Error::TooLong(_, _) => "the key is longer than this platform allows",
        keyring::Error::Invalid(_, _) => "the key is not valid on this platform",
        keyring::Error::Ambiguous(_) => "more than one stored entry matches that key",
        // `keyring::Error` is `#[non_exhaustive]`; a variant added by a future
        // release must not compile into a leak.
        _ => "the OS credential service failed in an unrecognised way",
    };
    Error::CredentialStoreUnavailable(format!("could not {operation} a keychain entry: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_describe_the_kind_of_failure_and_the_operation() {
        let error = store_error("read", keyring::Error::NoEntry);
        let message = error.to_string();
        assert!(message.contains("read"), "{message}");
        assert!(message.contains("no entry is stored"), "{message}");
    }

    #[test]
    fn error_mapping_never_forwards_stored_bytes() {
        // `BadEncoding` is the variant that carries the secret itself, so it is
        // the one worth pinning: `keyring`'s own `Display` would print the byte
        // vector, and this test fails the moment anyone forwards it.
        let stored = b"FAKE-access-token-0001".to_vec();
        let message = store_error("read", keyring::Error::BadEncoding(stored)).to_string();
        assert!(!message.contains("FAKE"), "{message}");
        assert!(message.contains("encoding"), "{message}");
    }

    #[test]
    fn error_mapping_never_forwards_attribute_payloads() {
        let message = store_error(
            "open",
            keyring::Error::Invalid("username".to_owned(), "FAKE-account-0001".to_owned()),
        )
        .to_string();
        assert!(!message.contains("FAKE"), "{message}");
    }

    /// Round-trips a secret through the real platform credential service.
    ///
    /// Ignored because it writes to the developer's own keychain, which
    /// `docs/TESTING.md` §4 forbids by default. Run it deliberately, on a
    /// machine with a working credential service, with:
    ///
    /// ```text
    /// nix develop --command cargo test --manifest-path src-tauri/Cargo.toml \
    ///   -- --ignored keychain_round_trip
    /// ```
    #[test]
    #[ignore = "writes to the developer's real keychain; see the doc comment"]
    fn keychain_round_trip() {
        let store = KeychainStore;
        assert!(store.is_available(), "no credential service on this host");

        let key = SecretRef::for_account("test-provider", "round-trip");
        store
            .put(&key, &Secret::new(b"FAKE-access-token-0001".to_vec()))
            .expect("put");

        let found = store.get(&key).expect("get").expect("stored entry");
        assert_eq!(found.expose(), b"FAKE-access-token-0001");

        store.delete(&key).expect("delete");
        assert!(store.get(&key).expect("get after delete").is_none());
        store.delete(&key).expect("delete is idempotent");
    }
}
