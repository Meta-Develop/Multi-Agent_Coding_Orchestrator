//! Immutable selection binding returned from a complete, explicit selection.

use serde::{Deserialize, Serialize};

/// Exact frozen selection identity for one provider.
///
/// Consumers must treat `selection_revision` and `account_incarnation` as opaque
/// equality tokens; they are not ordering hints beyond monotonic revision checks
/// performed by the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedAccountBinding {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
}
