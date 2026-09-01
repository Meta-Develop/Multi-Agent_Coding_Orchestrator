/// In-memory secret material. Never serializes, never displays the bytes.
#[derive(Clone)]
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn from_str(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    pub(crate) fn as_str(&self) -> Result<&str, super::types::SecretLifecycleError> {
        std::str::from_utf8(&self.0).map_err(|_| {
            super::types::SecretLifecycleError::InvalidMaterial {
                reason: "not_utf8".to_string(),
            }
        })
    }

    pub(crate) fn eq_str(&self, candidate: &str) -> bool {
        constant_time_eq(&self.0, candidate.as_bytes())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for SecretBytes {}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("bytes", &format!("<redacted:{} bytes>", self.0.len()))
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

pub(crate) fn zeroize_bytes(bytes: &mut Vec<u8>) {
    bytes.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    bytes.clear();
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
