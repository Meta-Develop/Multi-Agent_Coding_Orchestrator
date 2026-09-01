//! Per-runtime capability descriptors and the generated conformance matrix.
//!
//! Gates must consult these declarations instead of vendor names. Admission is
//! split: isolated managed-child worktree writes are allowed when
//! `writable_workspace` is Partial or Supported and
//! `side_effect_confinement == Verified`. Primary-writable release uses the
//! separate `blocking_pre_action_callback == All` gate and is not granted by
//! the descriptors in this module. The matrix reports callback coverage honestly.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

use super::RuntimeId;

/// Stable adapter identity. Every registered adapter is selectable via [`RuntimeId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterId {
    Codex,
    Fake,
    Grok,
    Cursor,
    #[serde(rename = "claude-code")]
    ClaudeCode,
    #[serde(rename = "gemini-cli")]
    GeminiCli,
}

impl AdapterId {
    pub const ALL: [Self; 6] = [
        Self::Codex,
        Self::Fake,
        Self::Grok,
        Self::Cursor,
        Self::ClaudeCode,
        Self::GeminiCli,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Fake => "fake",
            Self::Grok => "grok",
            Self::Cursor => "cursor",
            Self::ClaudeCode => "claude-code",
            Self::GeminiCli => "gemini-cli",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "codex" => Some(Self::Codex),
            "fake" => Some(Self::Fake),
            "grok" => Some(Self::Grok),
            "cursor" => Some(Self::Cursor),
            "claude-code" | "claude" => Some(Self::ClaudeCode),
            "gemini-cli" | "gemini" => Some(Self::GeminiCli),
            _ => None,
        }
    }

    pub const fn default_binary(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Fake => "fake",
            Self::Grok => "grok",
            Self::Cursor => "cursor-agent",
            Self::ClaudeCode => "claude",
            Self::GeminiCli => "gemini",
        }
    }

    pub const fn env_prefix(self) -> Option<&'static str> {
        match self {
            Self::Grok => Some("MACO_GROK"),
            Self::Cursor => Some("MACO_CURSOR"),
            Self::ClaudeCode => Some("MACO_CLAUDE"),
            Self::GeminiCli => Some("MACO_GEMINI"),
            Self::Codex | Self::Fake => None,
        }
    }

    pub const fn is_subprocess(self) -> bool {
        !matches!(self, Self::Fake)
    }

    pub const fn from_runtime(runtime: RuntimeId) -> Self {
        match runtime {
            RuntimeId::Codex => Self::Codex,
            RuntimeId::Fake => Self::Fake,
            RuntimeId::Grok => Self::Grok,
            RuntimeId::Cursor => Self::Cursor,
            RuntimeId::ClaudeCode => Self::ClaudeCode,
            RuntimeId::GeminiCli => Self::GeminiCli,
        }
    }

    pub const fn to_runtime_id(self) -> Option<RuntimeId> {
        match self {
            Self::Codex => Some(RuntimeId::Codex),
            Self::Fake => Some(RuntimeId::Fake),
            Self::Grok => Some(RuntimeId::Grok),
            Self::Cursor => Some(RuntimeId::Cursor),
            Self::ClaudeCode => Some(RuntimeId::ClaudeCode),
            Self::GeminiCli => Some(RuntimeId::GeminiCli),
        }
    }

    /// ReadWrite launch gate for an isolated managed child worktree.
    ///
    /// This is the ordinary orchestrator posture: the child uses its native
    /// permission/sandbox mode inside a disposable worktree. Primary-writable
    /// / All-callback release stays on [`RuntimeCapabilities::writable_refusal`].
    pub const fn writable_leaf_launch_refusal(self) -> Option<&'static str> {
        self.writable_launch_refusal(WritableLaunchTarget::ManagedChildWorktree)
    }

    /// Launch-time writable admission for a concrete workspace target.
    pub const fn writable_launch_refusal(
        self,
        target: WritableLaunchTarget,
    ) -> Option<&'static str> {
        self.capabilities().writable_launch_refusal(target)
    }

    pub const fn capabilities(self) -> RuntimeCapabilities {
        match self {
            Self::Codex => RuntimeCapabilities::CODEX,
            Self::Fake => RuntimeCapabilities::FAKE,
            Self::Grok => RuntimeCapabilities::GROK,
            Self::Cursor => RuntimeCapabilities::CURSOR,
            Self::ClaudeCode => RuntimeCapabilities::CLAUDE_CODE,
            Self::GeminiCli => RuntimeCapabilities::GEMINI_CLI,
        }
    }

    /// Current MACO trust posture. Only Codex is a trusted-system executable today.
    pub const fn trust_class(self) -> AdapterTrustClass {
        match self {
            Self::Codex => AdapterTrustClass::TrustedSystem,
            Self::Fake => AdapterTrustClass::LocalDeterministic,
            Self::Grok | Self::Cursor | Self::ClaudeCode | Self::GeminiCli => {
                AdapterTrustClass::ExplicitCustom
            }
        }
    }

    /// Observed private state home. `None` means this adapter has no staged runtime home.
    pub const fn private_state_home(self) -> Option<PrivateRuntimeStateHome> {
        match self {
            Self::Codex => Some(PrivateRuntimeStateHome {
                env_var: "CODEX_HOME",
                relative_path: ".codex",
            }),
            Self::Grok => Some(PrivateRuntimeStateHome {
                env_var: "GROK_HOME",
                relative_path: ".grok",
            }),
            Self::Cursor => Some(PrivateRuntimeStateHome {
                env_var: "CURSOR_CONFIG_DIR",
                relative_path: ".cursor",
            }),
            Self::ClaudeCode => Some(PrivateRuntimeStateHome {
                env_var: "CLAUDE_CONFIG_DIR",
                relative_path: ".claude",
            }),
            Self::GeminiCli => Some(PrivateRuntimeStateHome {
                env_var: "GEMINI_CLI_HOME",
                relative_path: ".gemini",
            }),
            Self::Fake => None,
        }
    }
}

/// How MACO currently classifies the adapter executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTrustClass {
    TrustedSystem,
    ExplicitCustom,
    LocalDeterministic,
}

/// Generalized `private_runtime_codex_home`: where this runtime keeps its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivateRuntimeStateHome {
    pub env_var: &'static str,
    pub relative_path: &'static str,
}

impl From<RuntimeId> for AdapterId {
    fn from(runtime: RuntimeId) -> Self {
        Self::from_runtime(runtime)
    }
}

impl Display for AdapterId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether MACO can host a blocking pre-tool callback for this runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingPreActionCallback {
    All,
    CommandsOnly,
    None,
}

impl BlockingPreActionCallback {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::All => MatrixStatus::Supported,
            Self::CommandsOnly => MatrixStatus::Partial,
            Self::None => MatrixStatus::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceWritability {
    Supported,
    Partial,
    Unsupported,
}

impl WorkspaceWritability {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::Supported => MatrixStatus::Supported,
            Self::Partial => MatrixStatus::Partial,
            Self::Unsupported => MatrixStatus::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectConfinement {
    Verified,
    Unverified,
}

impl SideEffectConfinement {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::Verified => MatrixStatus::Supported,
            Self::Unverified => MatrixStatus::Partial,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCatalogSource {
    RuntimeAdvertised,
    OperatorDeclared,
    None,
}

impl ModelCatalogSource {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::RuntimeAdvertised => MatrixStatus::Supported,
            Self::OperatorDeclared => MatrixStatus::Partial,
            Self::None => MatrixStatus::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReporting {
    PerTurn,
    Aggregate,
    None,
}

impl UsageReporting {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::PerTurn => MatrixStatus::Supported,
            Self::Aggregate => MatrixStatus::Partial,
            Self::None => MatrixStatus::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionResume {
    Supported,
    Unsupported,
}

impl SessionResume {
    pub const fn matrix_status(self) -> MatrixStatus {
        match self {
            Self::Supported => MatrixStatus::Supported,
            Self::Unsupported => MatrixStatus::Unsupported,
        }
    }
}

/// Where a writable child would run. Parent merge/apply to the primary stays
/// a separate fail-closed gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WritableLaunchTarget {
    ManagedChildWorktree,
    PrimaryWorktree,
}

/// Shared matrix cell used by the generated adapter × capability table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixStatus {
    Supported,
    Partial,
    Unsupported,
}

impl MatrixStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

impl Display for MatrixStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Static, test-asserted capability set for one adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct RuntimeCapabilities {
    pub blocking_pre_action_callback: BlockingPreActionCallback,
    pub writable_workspace: WorkspaceWritability,
    pub side_effect_confinement: SideEffectConfinement,
    pub model_catalog: ModelCatalogSource,
    pub usage_reporting: UsageReporting,
    pub session_resume: SessionResume,
}

impl RuntimeCapabilities {
    pub const CODEX: Self = Self {
        // App-server approval covers commands; it is not a blocking callback for every tool.
        blocking_pre_action_callback: BlockingPreActionCallback::CommandsOnly,
        writable_workspace: WorkspaceWritability::Partial,
        side_effect_confinement: SideEffectConfinement::Verified,
        model_catalog: ModelCatalogSource::RuntimeAdvertised,
        usage_reporting: UsageReporting::PerTurn,
        session_resume: SessionResume::Supported,
    };

    pub const FAKE: Self = Self {
        blocking_pre_action_callback: BlockingPreActionCallback::None,
        writable_workspace: WorkspaceWritability::Unsupported,
        side_effect_confinement: SideEffectConfinement::Verified,
        model_catalog: ModelCatalogSource::None,
        usage_reporting: UsageReporting::None,
        session_resume: SessionResume::Unsupported,
    };

    pub const GROK: Self = Self {
        // `--permission-mode` is CLI-side, not a MACO-hosted callback.
        blocking_pre_action_callback: BlockingPreActionCallback::None,
        writable_workspace: WorkspaceWritability::Partial,
        side_effect_confinement: SideEffectConfinement::Unverified,
        model_catalog: ModelCatalogSource::RuntimeAdvertised,
        usage_reporting: UsageReporting::None,
        session_resume: SessionResume::Supported,
    };

    /// Capabilities of a launch that has proved the immutable Grok 4.6/xhigh
    /// adapter contract. This is deliberately separate from [`Self::GROK`]: a
    /// vendor id or model name alone is not evidence that cwd, output, and
    /// delegation are bounded.
    pub(super) const GROK_4_6_XHIGH: Self = Self {
        side_effect_confinement: SideEffectConfinement::Verified,
        ..Self::GROK
    };

    pub const CURSOR: Self = Self {
        blocking_pre_action_callback: BlockingPreActionCallback::None,
        writable_workspace: WorkspaceWritability::Partial,
        side_effect_confinement: SideEffectConfinement::Unverified,
        model_catalog: ModelCatalogSource::RuntimeAdvertised,
        usage_reporting: UsageReporting::None,
        session_resume: SessionResume::Supported,
    };

    pub const CLAUDE_CODE: Self = Self {
        // `--permission-mode` and PreToolUse hooks exist on the CLI. The static
        // descriptor stays `None` until a MACO-owned host in `hosted_callback`
        // is attached. Hosted All-callback is optional defense-in-depth, not a
        // worktree-launch requirement.
        blocking_pre_action_callback: BlockingPreActionCallback::None,
        writable_workspace: WorkspaceWritability::Partial,
        side_effect_confinement: SideEffectConfinement::Unverified,
        model_catalog: ModelCatalogSource::OperatorDeclared,
        usage_reporting: UsageReporting::None,
        session_resume: SessionResume::Supported,
    };

    pub const GEMINI_CLI: Self = Self {
        // `--approval-mode` is CLI-side, not a MACO-hosted callback.
        blocking_pre_action_callback: BlockingPreActionCallback::None,
        writable_workspace: WorkspaceWritability::Partial,
        side_effect_confinement: SideEffectConfinement::Unverified,
        model_catalog: ModelCatalogSource::OperatorDeclared,
        usage_reporting: UsageReporting::None,
        session_resume: SessionResume::Supported,
    };

    pub const fn matrix_cells(self) -> [(&'static str, MatrixStatus); 6] {
        [
            (
                "blocking_pre_action_callback",
                self.blocking_pre_action_callback.matrix_status(),
            ),
            (
                "writable_workspace",
                self.writable_workspace.matrix_status(),
            ),
            (
                "side_effect_confinement",
                self.side_effect_confinement.matrix_status(),
            ),
            ("model_catalog", self.model_catalog.matrix_status()),
            ("usage_reporting", self.usage_reporting.matrix_status()),
            ("session_resume", self.session_resume.matrix_status()),
        ]
    }

    /// Read-only consultant admission requires verified side-effect confinement.
    pub const fn read_only_inner_contract_refusal(self) -> Option<&'static str> {
        if !matches!(
            self.side_effect_confinement,
            SideEffectConfinement::Verified
        ) {
            return Some("side_effect_confinement != verified");
        }
        None
    }

    /// Isolated managed-child worktree writes. Does not require a hosted All-callback, but the
    /// selected runtime must declare verified side-effect confinement rather than relying on the
    /// outer launcher to turn an unverified native contract into a static capability claim.
    pub const fn worktree_writable_refusal(self) -> Option<&'static str> {
        if matches!(self.writable_workspace, WorkspaceWritability::Unsupported) {
            return Some("writable_workspace == unsupported");
        }
        if !matches!(
            self.side_effect_confinement,
            SideEffectConfinement::Verified
        ) {
            return Some("side_effect_confinement != verified");
        }
        None
    }

    pub const fn admits_worktree_writable(self) -> bool {
        self.worktree_writable_refusal().is_none()
    }

    /// Primary-writable / publication release. Still requires a hosted All-callback.
    pub const fn writable_refusal(self) -> Option<&'static str> {
        if !matches!(
            self.blocking_pre_action_callback,
            BlockingPreActionCallback::All
        ) {
            return Some("blocking_pre_action_callback != All");
        }
        if !matches!(self.writable_workspace, WorkspaceWritability::Supported) {
            return Some("writable_workspace != supported");
        }
        None
    }

    pub const fn admits_writable_release(self) -> bool {
        self.writable_refusal().is_none()
    }

    /// Writable-release pair used only after a host covers every action.
    ///
    /// Do not map this from [`AdapterId::capabilities`]. The static Claude
    /// descriptor stays fail-closed for primary-writable until a hosted
    /// PreToolUse attachment is real. Isolated worktree launch does not use this.
    pub const fn with_hosted_blocking_callback(self) -> Self {
        Self {
            blocking_pre_action_callback: BlockingPreActionCallback::All,
            writable_workspace: WorkspaceWritability::Supported,
            side_effect_confinement: self.side_effect_confinement,
            model_catalog: self.model_catalog,
            usage_reporting: self.usage_reporting,
            session_resume: self.session_resume,
        }
    }

    pub const fn writable_launch_refusal(
        self,
        target: WritableLaunchTarget,
    ) -> Option<&'static str> {
        match target {
            WritableLaunchTarget::ManagedChildWorktree => self.worktree_writable_refusal(),
            WritableLaunchTarget::PrimaryWorktree => self.writable_refusal(),
        }
    }
}

/// Generated adapter × capability table. This is the authoritative answer to
/// "can runtime X do writable work?" and must not drift from the descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapabilityMatrix {
    pub version: u32,
    pub adapters: Vec<CapabilityMatrixRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapabilityMatrixRow {
    pub adapter: AdapterId,
    pub capabilities: RuntimeCapabilities,
    pub cells: Vec<CapabilityMatrixCell>,
    pub admits_writable_release: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable_refusal: Option<String>,
    pub admits_worktree_writable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree_writable_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapabilityMatrixCell {
    pub capability: String,
    pub status: MatrixStatus,
}

impl CapabilityMatrix {
    pub const VERSION: u32 = 1;

    pub fn from_adapters(ids: impl IntoIterator<Item = AdapterId>) -> Self {
        let mut adapters: Vec<CapabilityMatrixRow> = ids
            .into_iter()
            .map(|adapter| {
                let capabilities = adapter.capabilities();
                CapabilityMatrixRow {
                    adapter,
                    cells: capabilities
                        .matrix_cells()
                        .into_iter()
                        .map(|(capability, status)| CapabilityMatrixCell {
                            capability: capability.to_string(),
                            status,
                        })
                        .collect(),
                    admits_writable_release: capabilities.admits_writable_release(),
                    writable_refusal: capabilities.writable_refusal().map(str::to_string),
                    admits_worktree_writable: capabilities.admits_worktree_writable(),
                    worktree_writable_refusal: capabilities
                        .worktree_writable_refusal()
                        .map(str::to_string),
                    capabilities,
                }
            })
            .collect();
        adapters.sort_by_key(|row| row.adapter);
        Self {
            version: Self::VERSION,
            adapters,
        }
    }

    pub fn all_known() -> Self {
        Self::from_adapters(AdapterId::ALL)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("capability matrix is always JSON-serializable")
    }

    pub fn to_markdown(&self) -> String {
        let mut table = String::from(
            "| adapter | blocking_pre_action_callback | writable_workspace | side_effect_confinement | model_catalog | usage_reporting | session_resume | writable_release | worktree_writable |\n",
        );
        table.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for row in &self.adapters {
            let mut cells = row
                .cells
                .iter()
                .map(|cell| cell.status.as_str())
                .collect::<Vec<_>>();
            let release = if row.admits_writable_release {
                "admitted"
            } else {
                "refused"
            };
            let worktree = if row.admits_worktree_writable {
                "admitted"
            } else {
                "refused"
            };
            cells.push(release);
            cells.push(worktree);
            table.push_str(&format!(
                "| {} | {} |\n",
                row.adapter.as_str(),
                cells.join(" | ")
            ));
        }
        table
    }
}

/// Operator allow-list. Unset means every known adapter is registered; unknown
/// names are ignored so an untrusted CLI is absent rather than a startup failure.
pub fn parse_adapter_allowlist(raw: Option<&str>) -> Vec<AdapterId> {
    let Some(raw) = raw else {
        return AdapterId::ALL.to_vec();
    };
    let mut ids: Vec<AdapterId> = raw.split(',').filter_map(AdapterId::parse).collect();
    ids.sort();
    ids.dedup();
    ids
}

pub fn registered_adapter_ids() -> Vec<AdapterId> {
    parse_adapter_allowlist(std::env::var("MACO_RUNTIME_ADAPTERS").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_adapter_declares_a_complete_capability_set() {
        for adapter in AdapterId::ALL {
            let capabilities = adapter.capabilities();
            assert_eq!(
                capabilities.matrix_cells().len(),
                6,
                "{adapter} capability row is incomplete"
            );
            assert!(
                !capabilities.admits_writable_release()
                    || matches!(
                        capabilities.blocking_pre_action_callback,
                        BlockingPreActionCallback::All
                    ),
                "{adapter} cannot admit primary-writable release without a hosted All-callback"
            );
            assert!(
                !capabilities.admits_worktree_writable()
                    || (matches!(
                        capabilities.writable_workspace,
                        WorkspaceWritability::Partial | WorkspaceWritability::Supported
                    ) && matches!(
                        capabilities.side_effect_confinement,
                        SideEffectConfinement::Verified
                    )),
                "{adapter} worktree-writable admission must require writability and verified confinement"
            );
        }
    }

    #[test]
    fn worktree_writable_requires_verified_selected_runtime_confinement() {
        let codex = RuntimeCapabilities::CODEX;
        assert_ne!(
            codex.blocking_pre_action_callback,
            BlockingPreActionCallback::All
        );
        assert!(codex.admits_worktree_writable());
        assert_eq!(
            codex.writable_launch_refusal(WritableLaunchTarget::ManagedChildWorktree),
            None
        );
        assert!(!codex.admits_writable_release());
        assert_eq!(
            codex.writable_launch_refusal(WritableLaunchTarget::PrimaryWorktree),
            Some("blocking_pre_action_callback != All")
        );

        for capabilities in [
            RuntimeCapabilities::CURSOR,
            RuntimeCapabilities::CLAUDE_CODE,
            RuntimeCapabilities::GROK,
            RuntimeCapabilities::GEMINI_CLI,
        ] {
            assert_ne!(
                capabilities.blocking_pre_action_callback,
                BlockingPreActionCallback::All
            );
            assert!(!capabilities.admits_worktree_writable());
            assert_eq!(
                capabilities.writable_launch_refusal(WritableLaunchTarget::ManagedChildWorktree),
                Some("side_effect_confinement != verified")
            );
            assert!(!capabilities.admits_writable_release());
            assert_eq!(
                capabilities.writable_launch_refusal(WritableLaunchTarget::PrimaryWorktree),
                Some("blocking_pre_action_callback != All")
            );
        }
        assert!(!RuntimeCapabilities::FAKE.admits_worktree_writable());
        assert_eq!(
            RuntimeCapabilities::FAKE.worktree_writable_refusal(),
            Some("writable_workspace == unsupported")
        );
        assert!(!RuntimeCapabilities::FAKE.admits_writable_release());
    }

    #[test]
    fn writable_release_fails_closed_unless_callback_covers_all_actions() {
        assert!(!RuntimeCapabilities::CODEX.admits_writable_release());
        assert!(!RuntimeCapabilities::GROK.admits_writable_release());
        assert!(!RuntimeCapabilities::CURSOR.admits_writable_release());
        assert!(!RuntimeCapabilities::GEMINI_CLI.admits_writable_release());
        assert!(!RuntimeCapabilities::CLAUDE_CODE.admits_writable_release());
        assert!(!RuntimeCapabilities::FAKE.admits_writable_release());
        assert_eq!(
            RuntimeCapabilities::GEMINI_CLI.writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        assert_eq!(
            RuntimeCapabilities::CODEX.blocking_pre_action_callback,
            BlockingPreActionCallback::CommandsOnly
        );
        assert_eq!(
            RuntimeCapabilities::CURSOR.blocking_pre_action_callback,
            BlockingPreActionCallback::None
        );
        assert_eq!(
            RuntimeCapabilities::CLAUDE_CODE.blocking_pre_action_callback,
            BlockingPreActionCallback::None
        );
    }

    #[test]
    fn matrix_is_deterministic_and_covers_every_known_adapter() {
        let matrix = CapabilityMatrix::all_known();
        assert_eq!(matrix.version, 1);
        let ids: Vec<_> = matrix.adapters.iter().map(|row| row.adapter).collect();
        assert_eq!(ids, AdapterId::ALL);
        let again = CapabilityMatrix::all_known();
        assert_eq!(matrix, again);
        assert_eq!(matrix.to_json(), again.to_json());
    }

    #[test]
    fn markdown_matrix_names_every_adapter_and_writable_refusal() {
        let markdown = CapabilityMatrix::all_known().to_markdown();
        for adapter in AdapterId::ALL {
            assert!(
                markdown.contains(adapter.as_str()),
                "matrix missing {adapter}"
            );
        }
        assert!(markdown.contains("refused"));
        assert!(markdown.contains("worktree_writable"));
        assert!(markdown.contains("| admitted |"));
        let callback_status = |adapter: AdapterId| -> &str {
            markdown
                .lines()
                .find(|line| line.starts_with(&format!("| {} |", adapter.as_str())))
                .and_then(|line| line.split('|').nth(2))
                .map(str::trim)
                .unwrap_or_else(|| panic!("matrix missing callback cell for {adapter}"))
        };
        assert_eq!(callback_status(AdapterId::Codex), "partial");
        assert_eq!(callback_status(AdapterId::Cursor), "unsupported");
        assert_eq!(callback_status(AdapterId::ClaudeCode), "unsupported");
        assert_eq!(callback_status(AdapterId::Grok), "unsupported");
        assert_eq!(callback_status(AdapterId::GeminiCli), "unsupported");
        assert_eq!(callback_status(AdapterId::Fake), "unsupported");
        let fake = markdown
            .lines()
            .find(|line| line.starts_with("| fake |"))
            .expect("matrix missing fake");
        assert!(fake.contains("refused"));
        assert!(!fake.contains("admitted"));
    }

    #[test]
    fn gemini_cli_identity_round_trips_through_serde_and_parse() {
        assert_eq!(AdapterId::parse("gemini-cli"), Some(AdapterId::GeminiCli));
        assert_eq!(AdapterId::parse("gemini"), Some(AdapterId::GeminiCli));
        let json = serde_json::to_string(&AdapterId::GeminiCli).unwrap();
        assert_eq!(json, "\"gemini-cli\"");
        assert_eq!(
            serde_json::from_str::<AdapterId>(&json).unwrap(),
            AdapterId::GeminiCli
        );
    }

    #[test]
    fn claude_and_gemini_are_first_class_runtime_ids() {
        assert_eq!(
            AdapterId::ClaudeCode.to_runtime_id(),
            Some(RuntimeId::ClaudeCode)
        );
        assert_eq!(
            AdapterId::GeminiCli.to_runtime_id(),
            Some(RuntimeId::GeminiCli)
        );
        assert_eq!(
            serde_json::to_string(&RuntimeId::ClaudeCode).unwrap(),
            "\"claude-code\""
        );
        assert_eq!(
            serde_json::from_str::<RuntimeId>("\"claude-code\"").unwrap(),
            RuntimeId::ClaudeCode
        );
        assert_eq!(
            serde_json::from_str::<RuntimeId>("\"gemini-cli\"").unwrap(),
            RuntimeId::GeminiCli
        );
        assert!(RuntimeId::ClaudeCode.is_adapter_subprocess());
        assert!(RuntimeId::GeminiCli.is_adapter_subprocess());
        assert_eq!(
            RuntimeCapabilities::CLAUDE_CODE.read_only_inner_contract_refusal(),
            Some("side_effect_confinement != verified")
        );
        assert_eq!(
            RuntimeCapabilities::CLAUDE_CODE.writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        assert!(!RuntimeCapabilities::CLAUDE_CODE.admits_writable_release());
        assert!(!RuntimeCapabilities::CLAUDE_CODE.admits_worktree_writable());
        for adapter in [
            AdapterId::ClaudeCode,
            AdapterId::GeminiCli,
            AdapterId::Grok,
            AdapterId::Cursor,
        ] {
            assert_eq!(
                adapter.writable_leaf_launch_refusal(),
                Some("side_effect_confinement != verified")
            );
        }
        assert_eq!(AdapterId::Codex.writable_leaf_launch_refusal(), None);
        assert_eq!(
            AdapterId::Fake.writable_leaf_launch_refusal(),
            Some("writable_workspace == unsupported")
        );
        assert_eq!(
            AdapterId::ClaudeCode.writable_launch_refusal(WritableLaunchTarget::PrimaryWorktree),
            Some("blocking_pre_action_callback != All")
        );
    }

    #[test]
    fn hosted_blocking_callback_is_the_only_primary_writable_release_admission() {
        let admitted = RuntimeCapabilities {
            blocking_pre_action_callback: BlockingPreActionCallback::All,
            writable_workspace: WorkspaceWritability::Supported,
            side_effect_confinement: SideEffectConfinement::Verified,
            model_catalog: ModelCatalogSource::OperatorDeclared,
            usage_reporting: UsageReporting::None,
            session_resume: SessionResume::Supported,
        };
        assert_eq!(admitted.writable_refusal(), None);
        assert!(admitted.admits_writable_release());
        assert!(!RuntimeCapabilities::CLAUDE_CODE.admits_writable_release());
        assert!(!RuntimeCapabilities::GEMINI_CLI.admits_writable_release());
        assert_eq!(
            RuntimeCapabilities::CLAUDE_CODE.writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        assert_eq!(
            RuntimeCapabilities::GEMINI_CLI.writable_refusal(),
            Some("blocking_pre_action_callback != All")
        );
        let hosted = RuntimeCapabilities::CLAUDE_CODE.with_hosted_blocking_callback();
        assert_eq!(
            hosted.blocking_pre_action_callback,
            BlockingPreActionCallback::All
        );
        assert_eq!(hosted.writable_workspace, WorkspaceWritability::Supported);
        assert!(hosted.admits_writable_release());
        assert_eq!(
            AdapterId::ClaudeCode.capabilities(),
            RuntimeCapabilities::CLAUDE_CODE
        );
        assert_eq!(
            RuntimeCapabilities::CODEX.blocking_pre_action_callback,
            BlockingPreActionCallback::CommandsOnly
        );
        assert!(!RuntimeCapabilities::FAKE.admits_writable_release());
    }

    #[test]
    fn claude_code_identity_round_trips_through_serde_and_parse() {
        assert_eq!(AdapterId::parse("claude-code"), Some(AdapterId::ClaudeCode));
        assert_eq!(AdapterId::parse("claude"), Some(AdapterId::ClaudeCode));
        let json = serde_json::to_string(&AdapterId::ClaudeCode).unwrap();
        assert_eq!(json, "\"claude-code\"");
        assert_eq!(
            serde_json::from_str::<AdapterId>(&json).unwrap(),
            AdapterId::ClaudeCode
        );
    }

    #[test]
    fn allowlist_ignores_unknown_names_and_does_not_fail_startup() {
        assert_eq!(parse_adapter_allowlist(None), AdapterId::ALL);
        assert_eq!(
            parse_adapter_allowlist(Some("grok, gemini-cli, unknown")),
            vec![AdapterId::Grok, AdapterId::GeminiCli]
        );
        assert_eq!(parse_adapter_allowlist(Some("not-a-runtime")), Vec::new());
    }

    #[test]
    fn observed_private_state_homes_are_declared_for_every_subprocess_runtime() {
        let homes = [
            (AdapterId::Codex, "CODEX_HOME", ".codex"),
            (AdapterId::Grok, "GROK_HOME", ".grok"),
            (AdapterId::Cursor, "CURSOR_CONFIG_DIR", ".cursor"),
            (AdapterId::ClaudeCode, "CLAUDE_CONFIG_DIR", ".claude"),
            (AdapterId::GeminiCli, "GEMINI_CLI_HOME", ".gemini"),
        ];
        for (adapter, env_var, relative_path) in homes {
            let home = adapter
                .private_state_home()
                .unwrap_or_else(|| panic!("{adapter} is missing a private state home"));
            assert_eq!(home.env_var, env_var);
            assert_eq!(home.relative_path, relative_path);
        }
        assert_eq!(AdapterId::Fake.private_state_home(), None);
        assert_eq!(
            AdapterId::Codex.trust_class(),
            AdapterTrustClass::TrustedSystem
        );
        assert_eq!(
            AdapterId::ClaudeCode.trust_class(),
            AdapterTrustClass::ExplicitCustom
        );
    }

    #[test]
    fn grok_and_cursor_catalogs_are_runtime_advertised_from_observed_clis() {
        assert_eq!(
            AdapterId::Grok.capabilities().model_catalog,
            ModelCatalogSource::RuntimeAdvertised
        );
        assert_eq!(
            AdapterId::Cursor.capabilities().model_catalog,
            ModelCatalogSource::RuntimeAdvertised
        );
        assert_eq!(
            AdapterId::GeminiCli.capabilities().model_catalog,
            ModelCatalogSource::OperatorDeclared
        );
        assert_eq!(
            AdapterId::ClaudeCode.capabilities().model_catalog,
            ModelCatalogSource::OperatorDeclared
        );
    }
}
