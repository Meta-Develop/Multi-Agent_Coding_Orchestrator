use serde::Serialize;

/// Every error that can cross the Tauri IPC boundary.
///
/// Error values are shown to the user, so a variant must never carry a secret.
/// When wrapping an underlying failure, include the *kind* of thing that failed
/// and a path when it is safe to show, never a credential value.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no adapter is registered for provider `{0}`")]
    UnknownProvider(String),

    #[error("no account is registered with id `{0}`")]
    UnknownAccount(String),

    #[error("`{provider}` is not installed on this machine")]
    ProviderNotInstalled { provider: String },

    #[error("credential store is unavailable: {0}")]
    CredentialStoreUnavailable(String),

    #[error("configuration for `{provider}` could not be read: {reason}")]
    ConfigRead { provider: String, reason: String },

    #[error("configuration for `{provider}` could not be written: {reason}")]
    ConfigWrite { provider: String, reason: String },

    #[error("this adapter does not implement `{0}` yet")]
    NotImplemented(&'static str),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
