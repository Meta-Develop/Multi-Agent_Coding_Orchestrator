use super::{
    material::SecretBytes,
    types::{SecretLifecycleError, SecretRef},
};
use serde::{ser::SerializeMap, Serialize};
use std::collections::BTreeMap;

/// Bounded execution-boundary lease. Debug/serde cannot carry material.
pub struct SecretLease {
    reference: SecretRef,
    env_key: String,
    material: SecretBytes,
}

impl SecretLease {
    pub(crate) fn new(reference: SecretRef, env_key: String, material: SecretBytes) -> Self {
        Self {
            reference,
            env_key,
            material,
        }
    }

    pub fn reference(&self) -> &SecretRef {
        &self.reference
    }

    pub fn env_key(&self) -> &str {
        &self.env_key
    }

    /// Copy material into an in-memory environment map for process spawn only.
    ///
    /// The destination map is the execution-boundary payload. Do not log,
    /// journal, or serialize it; hold [`SecretEnvironment`] or this lease
    /// instead until spawn.
    pub fn apply_to(&self, env: &mut BTreeMap<String, String>) -> Result<(), SecretLifecycleError> {
        env.insert(self.env_key.clone(), self.material.as_str()?.to_string());
        Ok(())
    }

    pub fn material_eq(&self, candidate: &str) -> bool {
        self.material.eq_str(candidate)
    }
}

impl std::fmt::Debug for SecretLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretLease")
            .field("reference", &self.reference)
            .field("env_key", &self.env_key)
            .field("material", &"<redacted:secret-lease>")
            .finish()
    }
}

impl Serialize for SecretLease {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecretLease", 3)?;
        state.serialize_field("reference", &self.reference)?;
        state.serialize_field("env_key", &self.env_key)?;
        state.serialize_field("material", "<redacted:secret-lease>")?;
        state.end()
    }
}

/// Scoped injection map. Debug and serde emit keys only; values stay in memory
/// until [`SecretEnvironment::into_process_env`] at the spawn boundary.
#[derive(Default)]
pub struct SecretEnvironment {
    values: BTreeMap<String, SecretBytes>,
}

impl SecretEnvironment {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub fn material_eq(&self, key: &str, candidate: &str) -> bool {
        self.values
            .get(key)
            .is_some_and(|material| material.eq_str(candidate))
    }

    /// Copy values into a process-spawn environment map. Do not log the result.
    pub fn apply_to(&self, env: &mut BTreeMap<String, String>) -> Result<(), SecretLifecycleError> {
        for (key, material) in &self.values {
            env.insert(key.clone(), material.as_str()?.to_string());
        }
        Ok(())
    }

    /// Consume into a process-spawn environment map. Do not log the result.
    pub fn into_process_env(self) -> Result<BTreeMap<String, String>, SecretLifecycleError> {
        let mut env = BTreeMap::new();
        self.apply_to(&mut env)?;
        Ok(env)
    }

    pub(crate) fn insert_lease(&mut self, lease: SecretLease) {
        self.values.insert(lease.env_key, lease.material);
    }
}

impl std::fmt::Debug for SecretEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretEnvironment")
            .field(
                "entries",
                &self
                    .values
                    .keys()
                    .map(|key| (key.as_str(), "<redacted:secret-env>"))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Serialize for SecretEnvironment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for key in self.values.keys() {
            map.serialize_entry(key, "<redacted:secret-env>")?;
        }
        map.end()
    }
}
