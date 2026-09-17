//! Provider-agnostic domain types.
//!
//! These are mirrored in TypeScript at `src/types/index.ts`. Change both sides
//! together; `docs/ARCHITECTURE.md` describes the contract.

use serde::{Deserialize, Serialize};

/// Stable identifier for a managed agent tool, e.g. `claude-code`.
pub type ProviderId = &'static str;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// serde kebab-case would emit `"o-auth"`; the webview type is `"oauth"`.
    #[serde(rename = "oauth")]
    OAuth,
    ApiKey,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallState {
    Installed,
    NotInstalled,
    Unknown,
}

/// How complete an adapter is. Surfaced in the UI so users are never misled
/// about what the application can actually do for a given tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Maturity {
    Planned,
    Experimental,
    Supported,
}

/// An account/tool operation an adapter actually implements.
///
/// `maturity` is too coarse for the Accounts page: an experimental adapter
/// may still add, switch, or delete. The UI offers a button only when this
/// list contains the corresponding capability (NFR-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderCapability {
    AddAccount,
    SwitchAccount,
    DeleteAccount,
    /// Start the provider tool through an app-owned launch path.
    LaunchTool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDescriptor {
    pub id: String,
    pub display_name: String,
    pub vendor: String,
    pub auth_kinds: Vec<AuthKind>,
    pub maturity: Maturity,
    pub install_state: InstallState,
    /// Account/tool operations this adapter will honour (NFR-8).
    pub capabilities: Vec<ProviderCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Assigned by this application, never by the vendor.
    pub id: String,
    pub provider_id: String,
    /// User-chosen label. Must never contain a secret.
    pub label: String,
    /// Vendor identity, already masked for display (e.g. `a***@example.com`).
    pub masked_identity: Option<String>,
    pub auth_kind: AuthKind,
    pub is_active: bool,
    /// Selected for the next app-owned environment-driven launch. This is not
    /// a claim about the account used by tools started elsewhere.
    #[serde(default)]
    pub is_selected_for_launch: bool,
    /// Whether this application owns durable account metadata or material that
    /// its core/adapter lifecycle can select or forget.
    ///
    /// This is not a validity, currency, or vendor-acceptance signal.
    /// Stored material may be expired, unused, or rejected by the vendor. An
    /// incomplete row is still stored and may be forgotten, but cannot be
    /// selected for use.
    pub is_stored: bool,
    /// True when provisioning left a structurally incomplete stored account.
    ///
    /// It is listed so the user can recover or forget it. It is never active or
    /// selected for launch. Completeness is structural: this is not a claim
    /// that complete material is current or accepted by the vendor.
    #[serde(default)]
    pub is_incomplete: bool,
    /// RFC 3339 timestamp, when the adapter can determine one.
    pub expires_at: Option<String>,
}

/// Durable lifecycle of application-owned account metadata.
///
/// `Pending` and `Deleting` are recovery records, not usable accounts. Only a
/// `Complete` account may be selected for an environment-driven launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoredAccountState {
    Pending,
    Complete,
    Deleting,
}

/// External material associated with durable account metadata.
///
/// Paths and credential references are derived inside the Rust core; only this
/// non-secret classification is persisted or exposed over IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoredAccountMaterial {
    CredentialStore,
    VendorHome,
}

/// Non-secret metadata for an account managed by this application.
///
/// The credential reference is derived from `(provider_id, id)` inside the
/// Rust core when needed. Neither the reference nor secret material is stored
/// in this document or exposed over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccountMetadata {
    /// Assigned by this application, never by the vendor.
    pub id: String,
    pub provider_id: String,
    /// User-chosen label. Must never contain a secret.
    pub label: String,
    pub auth_kind: AuthKind,
    pub state: StoredAccountState,
    pub material: StoredAccountMaterial,
    /// At most one complete account per provider is selected.
    pub is_selected: bool,
}

/// Non-secret result returned after the core starts a provider child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchedProcess {
    pub provider_id: String,
    pub account_id: String,
    pub process_id: u32,
}

/// One user-authored routing rule, evaluated in list order (FR-7).
///
/// A rule identifies a provider, not a credential. The native router resolves
/// that provider to exactly one configured account before a request can be
/// served, and secret material never crosses IPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteRule {
    /// Exact inbound model name or one case-sensitive trailing-`*` prefix.
    pub match_model: String,
    /// Provider whose configured account may serve the request.
    pub provider_id: String,
    /// Upstream model substituted by the relay.
    pub target_model: String,
    /// Optional maximum consumed fraction, inclusive, in `0.0..=1.0`.
    pub max_utilization: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaSource {
    LocalFile,
    Api,
    Header,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaSnapshot {
    pub account_id: String,
    pub model: Option<String>,
    /// Fraction of the window consumed, 0.0..=1.0.
    ///
    /// Absence is represented by an empty provider collection, never by a
    /// snapshot without a number.
    pub utilization: f32,
    /// Provider-published rate-limit window, when available.
    pub window_label: Option<String>,
    pub resets_at: Option<String>,
    pub captured_at: String,
    pub source: QuotaSource,
}

/// Per-provider result of quota collection.
///
/// Every registry adapter gets one row. This keeps "no signal" distinct from
/// a failed collection and prevents one adapter error from blanking the rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderQuotaList {
    pub provider_id: String,
    pub plan_label: Option<String>,
    pub snapshots: Vec<QuotaSnapshot>,
    pub outcome: QuotaListOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum QuotaListOutcome {
    /// At least one validated, sourced numeric snapshot is present.
    Available,
    /// The provider publishes no usable quota signal.
    NoSignal,
    /// Collection failed or an adapter returned an invalid snapshot.
    Failed { error: QuotaListError },
}

/// Secret-free quota collection error surfaced to the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaListError {
    pub kind: QuotaListErrorKind,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaListErrorKind {
    ConfigRead,
    InvalidSnapshot,
    Other,
}

/// Secret-free relay state exposed to the webview.
///
/// Listener configuration that can contain credentials stays in the Rust core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatus {
    pub running: bool,
    pub bind_address: String,
    pub port: u16,
    pub prefixes: Vec<String>,
}

/// Per-provider result of `list_accounts`.
///
/// A flat `Vec<Account>` cannot tell "listed zero", "cannot list yet", and
/// "the look failed" apart. One struct per adapter keeps a single failure
/// from blanking the other providers, and gives the webview a status it can
/// render without guessing from `maturity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountList {
    pub provider_id: String,
    pub accounts: Vec<Account>,
    pub outcome: AccountListOutcome,
}

/// How `list_accounts` finished for one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AccountListOutcome {
    /// The adapter enumerated; `accounts` may be empty.
    Listed,
    /// The adapter enumerated the API-key path only and does not inspect
    /// OAuth credentials. `accounts` may still be empty.
    ListedApiKeyOnly,
    /// The adapter enumerated; `accounts` may be empty. Something is
    /// wrong that the user needs to see — typically a damaged live
    /// document — and is described by `error`. This is not a failure
    /// of the look: stored copies are still listed. The error never
    /// contains a credential value (NFR-1).
    ListedWithError { error: AccountListError },
    /// The adapter returned `Error::NotImplemented`.
    NotImplemented,
    /// The adapter is implemented and the look failed.
    Failed { error: AccountListError },
}

/// Kind and, where safe, path of a failed look. Never a credential value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountListError {
    pub kind: AccountListErrorKind,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountListErrorKind {
    ConfigRead,
    CredentialStoreUnavailable,
    Other,
}

// Wire values are shared with `src/types/index.ts`. Change both sides together.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_kind_wire_values() {
        assert_eq!(
            serde_json::to_string(&AuthKind::OAuth).unwrap(),
            r#""oauth""#
        );
        assert_eq!(
            serde_json::to_string(&AuthKind::ApiKey).unwrap(),
            r#""api-key""#
        );
        assert_eq!(
            serde_json::to_string(&AuthKind::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn install_state_wire_values() {
        assert_eq!(
            serde_json::to_string(&InstallState::Installed).unwrap(),
            r#""installed""#
        );
        assert_eq!(
            serde_json::to_string(&InstallState::NotInstalled).unwrap(),
            r#""not-installed""#
        );
        assert_eq!(
            serde_json::to_string(&InstallState::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn maturity_wire_values() {
        assert_eq!(
            serde_json::to_string(&Maturity::Planned).unwrap(),
            r#""planned""#
        );
        assert_eq!(
            serde_json::to_string(&Maturity::Experimental).unwrap(),
            r#""experimental""#
        );
        assert_eq!(
            serde_json::to_string(&Maturity::Supported).unwrap(),
            r#""supported""#
        );
    }

    #[test]
    fn provider_capability_wire_values() {
        assert_eq!(
            serde_json::to_string(&ProviderCapability::AddAccount).unwrap(),
            r#""add-account""#
        );
        assert_eq!(
            serde_json::to_string(&ProviderCapability::SwitchAccount).unwrap(),
            r#""switch-account""#
        );
        assert_eq!(
            serde_json::to_string(&ProviderCapability::DeleteAccount).unwrap(),
            r#""delete-account""#
        );
        assert_eq!(
            serde_json::to_string(&ProviderCapability::LaunchTool).unwrap(),
            r#""launch-tool""#
        );
    }

    #[test]
    fn provider_descriptor_wire_shape_includes_capabilities() {
        let descriptor = ProviderDescriptor {
            id: "codex-cli".to_string(),
            display_name: "Codex CLI".to_string(),
            vendor: "OpenAI".to_string(),
            auth_kinds: vec![AuthKind::OAuth],
            maturity: Maturity::Experimental,
            install_state: InstallState::Installed,
            capabilities: vec![
                ProviderCapability::AddAccount,
                ProviderCapability::SwitchAccount,
                ProviderCapability::DeleteAccount,
            ],
        };
        assert_eq!(
            serde_json::to_value(&descriptor).unwrap(),
            serde_json::json!({
                "id": "codex-cli",
                "displayName": "Codex CLI",
                "vendor": "OpenAI",
                "authKinds": ["oauth"],
                "maturity": "experimental",
                "installState": "installed",
                "capabilities": ["add-account", "switch-account", "delete-account"]
            })
        );
    }

    #[test]
    fn account_wire_shape_includes_is_stored() {
        let stored = Account {
            id: "acct-work".to_string(),
            provider_id: "codex-cli".to_string(),
            label: "work".to_string(),
            masked_identity: Some("****0001".to_string()),
            auth_kind: AuthKind::OAuth,
            is_active: true,
            is_selected_for_launch: false,
            is_stored: true,
            is_incomplete: false,
            expires_at: None,
        };
        assert_eq!(
            serde_json::to_value(&stored).unwrap(),
            serde_json::json!({
                "id": "acct-work",
                "providerId": "codex-cli",
                "label": "work",
                "maskedIdentity": "****0001",
                "authKind": "oauth",
                "isActive": true,
                "isSelectedForLaunch": false,
                "isStored": true,
                "isIncomplete": false,
                "expiresAt": null
            })
        );

        let live = Account {
            id: "codex-cli-on-disk".to_string(),
            provider_id: "codex-cli".to_string(),
            label: "Codex CLI".to_string(),
            masked_identity: Some("****0001".to_string()),
            auth_kind: AuthKind::OAuth,
            is_active: true,
            is_selected_for_launch: false,
            is_stored: false,
            is_incomplete: false,
            expires_at: None,
        };
        assert_eq!(
            serde_json::to_value(&live).unwrap(),
            serde_json::json!({
                "id": "codex-cli-on-disk",
                "providerId": "codex-cli",
                "label": "Codex CLI",
                "maskedIdentity": "****0001",
                "authKind": "oauth",
                "isActive": true,
                "isSelectedForLaunch": false,
                "isStored": false,
                "isIncomplete": false,
                "expiresAt": null
            })
        );

        let incomplete = Account {
            id: "acct-abandoned".to_string(),
            provider_id: "codex-cli".to_string(),
            label: "acct-abandoned".to_string(),
            masked_identity: None,
            auth_kind: AuthKind::Unknown,
            is_active: false,
            is_selected_for_launch: false,
            is_stored: true,
            is_incomplete: true,
            expires_at: None,
        };
        assert_eq!(
            serde_json::to_value(&incomplete).unwrap(),
            serde_json::json!({
                "id": "acct-abandoned",
                "providerId": "codex-cli",
                "label": "acct-abandoned",
                "maskedIdentity": null,
                "authKind": "unknown",
                "isActive": false,
                "isSelectedForLaunch": false,
                "isStored": true,
                "isIncomplete": true,
                "expiresAt": null
            })
        );
    }

    #[test]
    fn quota_source_wire_values() {
        assert_eq!(
            serde_json::to_string(&QuotaSource::LocalFile).unwrap(),
            r#""local-file""#
        );
        assert_eq!(
            serde_json::to_string(&QuotaSource::Api).unwrap(),
            r#""api""#
        );
        assert_eq!(
            serde_json::to_string(&QuotaSource::Header).unwrap(),
            r#""header""#
        );
    }

    #[test]
    fn provider_quota_wire_shape_keeps_no_signal_explicit() {
        let quota = ProviderQuotaList {
            provider_id: "codex-cli".to_string(),
            plan_label: None,
            snapshots: Vec::new(),
            outcome: QuotaListOutcome::NoSignal,
        };
        assert_eq!(
            serde_json::to_value(&quota).unwrap(),
            serde_json::json!({
                "providerId": "codex-cli",
                "planLabel": null,
                "snapshots": [],
                "outcome": { "kind": "no-signal" }
            })
        );
    }

    #[test]
    fn quota_snapshot_wire_shape_requires_a_number_and_window() {
        let quota = ProviderQuotaList {
            provider_id: "example".to_string(),
            plan_label: Some("Example plan".to_string()),
            snapshots: vec![QuotaSnapshot {
                account_id: "work".to_string(),
                model: Some("example-model".to_string()),
                utilization: 0.25,
                window_label: Some("5 hours".to_string()),
                resets_at: Some("2030-01-01T00:00:00Z".to_string()),
                captured_at: "2029-12-31T23:00:00Z".to_string(),
                source: QuotaSource::LocalFile,
            }],
            outcome: QuotaListOutcome::Available,
        };
        assert_eq!(
            serde_json::to_value(&quota).unwrap(),
            serde_json::json!({
                "providerId": "example",
                "planLabel": "Example plan",
                "snapshots": [{
                    "accountId": "work",
                    "model": "example-model",
                    "utilization": 0.25,
                    "windowLabel": "5 hours",
                    "resetsAt": "2030-01-01T00:00:00Z",
                    "capturedAt": "2029-12-31T23:00:00Z",
                    "source": "local-file"
                }],
                "outcome": { "kind": "available" }
            })
        );
    }

    #[test]
    fn stored_account_metadata_wire_shape_is_non_secret() {
        let account = StoredAccountMetadata {
            id: "work".to_string(),
            provider_id: "gemini-cli".to_string(),
            label: "Work".to_string(),
            auth_kind: AuthKind::ApiKey,
            state: StoredAccountState::Complete,
            material: StoredAccountMaterial::CredentialStore,
            is_selected: true,
        };
        assert_eq!(
            serde_json::to_value(&account).unwrap(),
            serde_json::json!({
                "id": "work",
                "providerId": "gemini-cli",
                "label": "Work",
                "authKind": "api-key",
                "state": "complete",
                "material": "credential-store",
                "isSelected": true
            })
        );
    }

    #[test]
    fn launched_process_wire_shape_is_non_secret() {
        let process = LaunchedProcess {
            provider_id: "gemini-cli".to_string(),
            account_id: "work".to_string(),
            process_id: 42,
        };
        assert_eq!(
            serde_json::to_value(&process).unwrap(),
            serde_json::json!({
                "providerId": "gemini-cli",
                "accountId": "work",
                "processId": 42
            })
        );
    }

    #[test]
    fn relay_status_wire_shape_contains_only_public_listener_state() {
        let status = RelayStatus {
            running: true,
            bind_address: "127.0.0.1".to_string(),
            port: 8787,
            prefixes: vec![
                "/v1/chat/completions".to_string(),
                "/v1/messages".to_string(),
                "/v1beta/models/*:generateContent".to_string(),
            ],
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "running": true,
                "bindAddress": "127.0.0.1",
                "port": 8787,
                "prefixes": [
                    "/v1/chat/completions",
                    "/v1/messages",
                    "/v1beta/models/*:generateContent"
                ]
            })
        );
    }

    #[test]
    fn account_list_outcome_wire_values() {
        assert_eq!(
            serde_json::to_string(&AccountListOutcome::Listed).unwrap(),
            r#"{"kind":"listed"}"#
        );
        assert_eq!(
            serde_json::to_string(&AccountListOutcome::ListedApiKeyOnly).unwrap(),
            r#"{"kind":"listed-api-key-only"}"#
        );
        let listed_with_error = AccountListOutcome::ListedWithError {
            error: AccountListError {
                kind: AccountListErrorKind::ConfigRead,
                path: Some("/tmp/auth.json".to_string()),
                message: "configuration for `codex-cli` could not be read: /tmp/auth.json is not valid JSON".to_string(),
            },
        };
        assert_eq!(
            serde_json::to_value(&listed_with_error).unwrap(),
            serde_json::json!({
                "kind": "listed-with-error",
                "error": {
                    "kind": "config-read",
                    "path": "/tmp/auth.json",
                    "message": "configuration for `codex-cli` could not be read: /tmp/auth.json is not valid JSON"
                }
            })
        );
        assert_eq!(
            serde_json::to_string(&AccountListOutcome::NotImplemented).unwrap(),
            r#"{"kind":"not-implemented"}"#
        );
        let failed = AccountListOutcome::Failed {
            error: AccountListError {
                kind: AccountListErrorKind::ConfigRead,
                path: Some("/tmp/auth.json".to_string()),
                message: "configuration for `codex-cli` could not be read: /tmp/auth.json is not valid JSON".to_string(),
            },
        };
        assert_eq!(
            serde_json::to_value(&failed).unwrap(),
            serde_json::json!({
                "kind": "failed",
                "error": {
                    "kind": "config-read",
                    "path": "/tmp/auth.json",
                    "message": "configuration for `codex-cli` could not be read: /tmp/auth.json is not valid JSON"
                }
            })
        );
    }

    #[test]
    fn account_list_error_kind_wire_values() {
        assert_eq!(
            serde_json::to_string(&AccountListErrorKind::ConfigRead).unwrap(),
            r#""config-read""#
        );
        assert_eq!(
            serde_json::to_string(&AccountListErrorKind::CredentialStoreUnavailable).unwrap(),
            r#""credential-store-unavailable""#
        );
        assert_eq!(
            serde_json::to_string(&AccountListErrorKind::Other).unwrap(),
            r#""other""#
        );
    }

    #[test]
    fn provider_account_list_wire_shape() {
        let listing = ProviderAccountList {
            provider_id: "codex-cli".to_string(),
            accounts: Vec::new(),
            outcome: AccountListOutcome::Listed,
        };
        assert_eq!(
            serde_json::to_value(&listing).unwrap(),
            serde_json::json!({
                "providerId": "codex-cli",
                "accounts": [],
                "outcome": { "kind": "listed" }
            })
        );
    }
}
