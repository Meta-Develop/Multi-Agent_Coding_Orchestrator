//! Account incarnation identifiers.

use getrandom::getrandom;

use crate::error::{Error, Result};

pub(crate) const INCARNATION_HEX_LEN: usize = 32;

/// Create a new opaque account incarnation persisted at account creation.
pub fn new_account_incarnation() -> String {
    let mut bytes = [0u8; INCARNATION_HEX_LEN / 2];
    getrandom(&mut bytes).expect("OS random source for account incarnation");
    hex_encode(&bytes)
}

/// Reject untrusted incarnation values before path construction or persistence.
pub(crate) fn validate_account_incarnation(value: &str) -> Result<()> {
    if value.len() != INCARNATION_HEX_LEN {
        return Err(incarnation_error("account incarnation has invalid length"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(incarnation_error(
            "account incarnation must be lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn incarnation_error(reason: impl Into<String>) -> Error {
    Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: reason.into(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}
