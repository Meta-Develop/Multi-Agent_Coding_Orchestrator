//! Closed device-login projections. A ready login grants no execution authority.

use super::{
    protocol::{required_option, valid_alias, valid_observation_id, Provider, Runtime},
    AccountClient, AccountError,
};
use serde::{Deserialize, Serialize};

pub const DEVICE_VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginStatus {
    Starting,
    Pending,
    Confirming,
    Ready,
    Cancelled,
    Expired,
    Failed,
    Superseded,
}

impl LoginStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Pending | Self::Confirming)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFailure {
    ProviderUnavailable,
    Protocol,
    Timeout,
    UnsafeConfiguration,
    LoginFailed,
}

// Intentionally no Debug implementation: pending device codes must not enter logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginObservation {
    pub schema_version: u32,
    pub handle: String,
    pub alias: String,
    pub provider: Provider,
    pub runtime: Runtime,
    pub status: LoginStatus,
    #[serde(deserialize_with = "required_option")]
    pub verification_url: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub user_code: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub expires_at: Option<u64>,
    pub broker_deadline: u64,
    #[serde(deserialize_with = "required_option")]
    pub failure: Option<LoginFailure>,
}

impl LoginObservation {
    pub fn validate(&self) -> Result<(), AccountError> {
        let pending_fields_valid = if self.status == LoginStatus::Pending {
            self.verification_url.as_deref() == Some(DEVICE_VERIFICATION_URL)
                && self
                    .user_code
                    .as_ref()
                    .is_some_and(|code| !code.is_empty() && !code.chars().any(char::is_control))
        } else {
            self.verification_url.is_none() && self.user_code.is_none()
        };
        let failure_valid = match self.status {
            LoginStatus::Starting
            | LoginStatus::Pending
            | LoginStatus::Confirming
            | LoginStatus::Ready
            | LoginStatus::Cancelled => self.failure.is_none(),
            LoginStatus::Expired => self.failure == Some(LoginFailure::Timeout),
            LoginStatus::Failed => matches!(
                self.failure,
                Some(
                    LoginFailure::ProviderUnavailable
                        | LoginFailure::Protocol
                        | LoginFailure::UnsafeConfiguration
                        | LoginFailure::LoginFailed
                )
            ),
            LoginStatus::Superseded => true,
        };
        if self.schema_version != 1
            || !valid_alias(&self.alias)
            || !valid_observation_id(&self.handle)
            || self.expires_at.is_some()
            || !pending_fields_valid
            || !failure_valid
        {
            return Err(AccountError::Protocol);
        }
        Ok(())
    }
}

impl AccountClient {
    pub fn login_start(
        &self,
        alias: &str,
        request_nonce: &str,
        replace_handle: Option<&str>,
    ) -> Result<LoginObservation, AccountError> {
        validate_arguments(alias, replace_handle)?;
        if !valid_observation_id(request_nonce) {
            return Err(AccountError::InvalidInput);
        }
        #[derive(Serialize)]
        struct Arguments<'a> {
            alias: &'a str,
            request_nonce: &'a str,
            replace_handle: Option<&'a str>,
        }
        let result = self.request(
            "accounts.login.start",
            Arguments {
                alias,
                request_nonce,
                replace_handle,
            },
        )?;
        checked_result(result, alias, None)
    }

    pub fn login_status(
        &self,
        alias: &str,
        handle: Option<&str>,
    ) -> Result<LoginObservation, AccountError> {
        validate_arguments(alias, handle)?;
        #[derive(Serialize)]
        struct Arguments<'a> {
            alias: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            handle: Option<&'a str>,
        }
        let result = self.request("accounts.login.status", Arguments { alias, handle })?;
        checked_result(result, alias, handle)
    }

    pub fn login_cancel(
        &self,
        alias: &str,
        handle: &str,
    ) -> Result<LoginObservation, AccountError> {
        validate_arguments(alias, Some(handle))?;
        #[derive(Serialize)]
        struct Arguments<'a> {
            alias: &'a str,
            handle: &'a str,
        }
        let result = self.request("accounts.login.cancel", Arguments { alias, handle })?;
        checked_result(result, alias, Some(handle))
    }
}

fn validate_arguments(alias: &str, handle: Option<&str>) -> Result<(), AccountError> {
    if !valid_alias(alias) || handle.is_some_and(|value| !valid_observation_id(value)) {
        Err(AccountError::InvalidInput)
    } else {
        Ok(())
    }
}

fn checked_result(
    result: LoginObservation,
    alias: &str,
    handle: Option<&str>,
) -> Result<LoginObservation, AccountError> {
    result.validate()?;
    if result.alias != alias || handle.is_some_and(|value| result.handle != value) {
        return Err(AccountError::Protocol);
    }
    Ok(result)
}
