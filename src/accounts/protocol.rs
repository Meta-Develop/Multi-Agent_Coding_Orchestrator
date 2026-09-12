//! Independently defined, closed account metadata protocol.

use super::AccountError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Capability service v1 framing limit, including the terminating newline.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Capability service v1 maximum complete-request deadline.
pub const MAX_REQUEST_SECONDS: u64 = 60;

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

vocabulary!(Provider { Openai });
vocabulary!(Runtime { Codex });
vocabulary!(AuthState {
    Unknown,
    Unauthenticated,
    LocalLogin,
    RemoteValidated,
    ReauthRequired
});
vocabulary!(AuthProvenance {
    None,
    CodexAccountRead,
    CodexRateLimits
});
vocabulary!(ObservationState { Unknown, Observed });
vocabulary!(ModelProvenance {
    None,
    CodexModelList
});
vocabulary!(QuotaProvenance {
    None,
    CodexRateLimits
});
vocabulary!(Entitlement { Unknown });
vocabulary!(Availability {
    Unknown,
    Unavailable
});
vocabulary!(DiscoveryFailure {
    ProviderUnavailable,
    Protocol,
    Timeout,
    ReauthRequired,
    UnsafeConfiguration,
    Busy
});
vocabulary!(ModelEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    Ultra
});
vocabulary!(QuotaWindowKind { Primary, Secondary });
vocabulary!(ServiceErrorCode {
    InvalidRequest,
    AccessDenied,
    UnknownCapability,
    CapabilityDisabled,
    InvalidArguments,
    ProviderUnavailable,
    UpstreamFailure,
    Timeout,
    Internal
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDescriptor {
    pub alias: String,
    pub provider: Provider,
    pub runtime: Runtime,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountList {
    pub schema_version: u32,
    pub accounts: Vec<AccountDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthObservation {
    pub state: AuthState,
    pub provenance: AuthProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDescriptor {
    pub id: String,
    pub supported_reasoning_efforts: Vec<ModelEffort>,
    #[serde(deserialize_with = "required_option")]
    pub default_reasoning_effort: Option<ModelEffort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelObservation {
    pub state: ObservationState,
    pub provenance: ModelProvenance,
    pub entitlement: Entitlement,
    pub items: Vec<ModelDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaWindow {
    #[serde(deserialize_with = "required_option")]
    pub limit_id: Option<String>,
    pub window: QuotaWindowKind,
    pub used_percent: f64,
    #[serde(deserialize_with = "required_option")]
    pub window_duration_mins: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub resets_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaObservation {
    pub state: ObservationState,
    pub provenance: QuotaProvenance,
    pub windows: Vec<QuotaWindow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDiscovery {
    pub schema_version: u32,
    pub observation_id: String,
    pub account: AccountDescriptor,
    pub observed_at: u64,
    #[serde(deserialize_with = "required_option")]
    pub expires_at: Option<u64>,
    pub auth: AuthObservation,
    pub models: ModelObservation,
    pub quota: QuotaObservation,
    pub availability: Availability,
    #[serde(deserialize_with = "required_option")]
    pub failure: Option<DiscoveryFailure>,
}

pub(super) fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

pub fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

pub fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:/-".contains(&c))
}

pub(super) fn valid_observation_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[14] == b'4'
        && b"89ab".contains(&bytes[19])
        && bytes.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
}

impl AccountList {
    pub fn validate(&self) -> Result<(), AccountError> {
        let mut seen = BTreeSet::new();
        if self.schema_version != 1
            || self
                .accounts
                .iter()
                .any(|a| !valid_alias(&a.alias) || !seen.insert(&a.alias))
        {
            return Err(AccountError::Protocol);
        }
        Ok(())
    }
}

impl AccountDiscovery {
    pub fn validate(&self) -> Result<(), AccountError> {
        let invalid = self.schema_version != 1
            || !valid_alias(&self.account.alias)
            || !self.account.enabled
            || !valid_observation_id(&self.observation_id)
            || self.expires_at.is_some()
            || match self.auth.state {
                AuthState::Unknown => self.auth.provenance == AuthProvenance::CodexRateLimits,
                AuthState::LocalLogin | AuthState::Unauthenticated => {
                    self.auth.provenance != AuthProvenance::CodexAccountRead
                }
                AuthState::RemoteValidated => {
                    self.auth.provenance != AuthProvenance::CodexRateLimits
                }
                AuthState::ReauthRequired => false,
            }
            || match self.models.state {
                ObservationState::Unknown => {
                    self.models.provenance != ModelProvenance::None || !self.models.items.is_empty()
                }
                ObservationState::Observed => {
                    self.models.provenance != ModelProvenance::CodexModelList
                }
            }
            || match self.quota.state {
                ObservationState::Unknown => {
                    self.quota.provenance != QuotaProvenance::None || !self.quota.windows.is_empty()
                }
                ObservationState::Observed => {
                    self.quota.provenance != QuotaProvenance::CodexRateLimits
                }
            };
        if invalid {
            return Err(AccountError::Protocol);
        }
        let mut models = BTreeSet::new();
        for model in &self.models.items {
            let efforts: BTreeSet<_> = model.supported_reasoning_efforts.iter().collect();
            if !valid_identifier(&model.id)
                || !models.insert(&model.id)
                || efforts.len() != model.supported_reasoning_efforts.len()
                || model
                    .default_reasoning_effort
                    .as_ref()
                    .is_some_and(|e| !efforts.contains(e))
            {
                return Err(AccountError::Protocol);
            }
        }
        let mut windows = BTreeSet::new();
        for window in &self.quota.windows {
            if window
                .limit_id
                .as_ref()
                .is_some_and(|id| !valid_identifier(id))
                || !windows.insert((&window.limit_id, window.window))
                || !window.used_percent.is_finite()
                || !(0.0..=100.0).contains(&window.used_percent)
                || window.window_duration_mins == Some(0)
            {
                return Err(AccountError::Protocol);
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct Request<A> {
    pub id: u64,
    pub capability: &'static str,
    pub arguments: A,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Success<T> {
    id: u64,
    ok: bool,
    result: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    id: u64,
    ok: bool,
    error: ServiceError,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceError {
    code: ServiceErrorCode,
    message: String,
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    id: u64,
) -> Result<T, AccountError> {
    // Deserialize directly into closed structures, preserving duplicate-field rejection.
    if let Ok(reply) = serde_json::from_slice::<Success<T>>(bytes) {
        return if reply.id == id && reply.ok {
            Ok(reply.result)
        } else {
            Err(AccountError::Protocol)
        };
    }
    let reply: Failure = serde_json::from_slice(bytes).map_err(|_| AccountError::Protocol)?;
    if reply.id != id || reply.ok {
        return Err(AccountError::Protocol);
    }
    // The message is deliberately neither exposed nor logged.
    let _ = reply.error.message;
    Err(match reply.error.code {
        ServiceErrorCode::Timeout => AccountError::Timeout,
        ServiceErrorCode::ProviderUnavailable
        | ServiceErrorCode::UpstreamFailure
        | ServiceErrorCode::Internal => AccountError::Unavailable,
        _ => AccountError::Refused,
    })
}
