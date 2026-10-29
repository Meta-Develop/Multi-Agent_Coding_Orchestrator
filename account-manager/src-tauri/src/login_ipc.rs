//! Login response shared by the desktop transport and IPC.

use crate::login::{LoginAuthorization, LoginStatus};
use serde::{Deserialize, Serialize};

/// Private GUI response; the core status and public owner action stay bound together.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginIpcStatus {
    #[serde(flatten)]
    pub status: LoginStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<LoginAuthorization>,
}

impl std::ops::Deref for LoginIpcStatus {
    type Target = LoginStatus;
    fn deref(&self) -> &Self::Target {
        &self.status
    }
}

impl std::fmt::Debug for LoginIpcStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginIpcStatus")
            .field("status", &self.status)
            .field("authorization_available", &self.authorization.is_some())
            .finish()
    }
}
