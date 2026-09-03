pub mod review_loop;
pub mod review_loop_entry;

use self::review_loop_entry::InboxIndependentAuditorSelectionEvidence;

use crate::{
    artifacts::{
        self, ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily,
    },
    autopilot::{
        self, AutopilotForgeMode, AutopilotPlan, AutopilotPublishMode, AutopilotRunOptions,
        AutopilotRunStatus, AutopilotTask, AutopilotValidationCommand,
    },
    external_agent::{load_codex_runtime_model_catalog, run_external_agent, ExternalAgentCommand},
    gate_denial::GateDenialReason,
    live_claim::{self, LiveClock},
    llm::{RedactionSummary, Redactor},
    machine_global::MachineGlobalRetentionBinding,
    orchestrator::RunId,
    planning,
    process_runner::{ProcessResourceLimits, StdinMode, TrustedFixedNetworkProfile},
    publication::{self, ExternalSourceGuard, ExternalSourceObjectKind},
    review::{ReviewerConfig, ReviewerMode},
    safe_state::{stable_checksum, BoundedRegularReader, SafeRoot},
    semantic_coord::SemanticIntentStore,
    sync::normalize_repo_relative_path,
    sync_store::SyncStore,
};
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use git2::{Delta, DiffFindOptions, DiffOptions, ObjectType, Oid, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::optimizer::merge_authority::{assess_independence, CompletionMode, ProducerFingerprint};
#[cfg(test)]
use crate::optimizer::merge_authority::{AgentIdentity, MergeActor, SessionId};
use crate::publication::forge_transport::{
    AuthenticatedPullRequestMergeEvidence, ForgeCheckConclusion, ForgeCheckStatus, ForgeItem,
    ForgeReviewState, PullRequestAuditorEvidence, PullRequestChangedPathsEvidence,
    PullRequestMergeReceipt, PullRequestMergeSimulationEvidence, PullRequestProducerEvidence,
    PullRequestReviewSnapshot,
};
#[cfg(test)]
use crate::publication::forge_transport::{
    FakeForgeTransport, ForgeActor, ForgeReview, ProviderObjectId, ProviderObjectKind,
    ReportedActorKind,
};
use crate::publication::AuthenticatedPullRequestMergeOutcome;

const INBOX_SCHEMA_VERSION: u32 = 1;
const CONFIG_FILE: &str = "maco-inbox.json";
const DEFAULT_MAX_ITEMS: usize = 4;
const DEFAULT_BODY_LIMIT: usize = 12 * 1024;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_CONFIG_SERIALIZED_BYTES: usize = 256 * 1024;
const MAX_WORKSPACE_REPOSITORIES: usize = 64;
const MAX_WORKSPACE_REPOSITORY_ID_BYTES: usize = 128;
const MAX_CONFIG_PATH_BYTES: usize = 4 * 1024;
const MAX_SELECTION_ITEMS: usize = 100;
const MAX_LABELS: usize = 32;
const MAX_LABEL_BYTES: usize = 100;
const MAX_REPAIR_ATTEMPTS: usize = 8;
const MAX_VALIDATION_COMMANDS: usize = 32;
const MAX_VALIDATION_NAME_BYTES: usize = 128;
const MAX_VALIDATION_COMMAND_BYTES: usize = 8 * 1024;
const MAX_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_ASSIGNED_PATHS: usize = 128;
const MAX_PRIVACY_TERMS: usize = 64;
const MAX_PRIVACY_TERM_BYTES: usize = 128;
const MAX_BODY_LIMIT: usize = 64 * 1024;
const MAX_CODEX_PATH_BYTES: usize = 4 * 1024;
const MAX_GITHUB_TITLE_BYTES: usize = 512;
const MAX_GITHUB_BODY_BYTES: usize = 128 * 1024;
const MAX_GITHUB_URL_BYTES: usize = 2 * 1024;
const MAX_GITHUB_LOGIN_BYTES: usize = 128;
const MAX_GITHUB_REF_BYTES: usize = 512;
const MAX_GITHUB_ITEMS: usize = MAX_SELECTION_ITEMS;
const GITHUB_WATCH_PR_DISCOVERY_SENTINEL: usize = MAX_GITHUB_ITEMS;
const MAX_GITHUB_WATCH_PR_PRODUCERS: usize = GITHUB_WATCH_PR_DISCOVERY_SENTINEL - 1;
const MAX_WATCH_RETAINED_ITERATIONS: usize = MAX_GITHUB_ITEMS;
const MAX_GITHUB_FILES: usize = MAX_ASSIGNED_PATHS;
const MAX_GITHUB_CHECKS: usize = 512;
const MAX_GITHUB_REVIEWS: usize = 512;
const MAX_GITHUB_REVIEW_BODY_BYTES: usize = 64 * 1024;
const MAX_GITHUB_STATUS_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SOURCE_SNAPSHOT_VERSION: u32 = 2;
const SOURCE_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"MACO\0inbox-source-snapshot\0v2\0";
#[cfg(test)]
const GH_OUTPUT_LIMIT: usize = 512 * 1024;
const GH_DIAGNOSTIC_LIMIT: usize = 4 * 1024;
const COMMENT_BODY_LIMIT: usize = 6 * 1024;
const ARTIFACT_FINAL_MARKER: &str = ".maco-artifact-final.json";
const PR_OBJECT_FETCH_CAPTURE_LIMIT: usize = 64 * 1024;
const PR_OBJECT_FETCH_MAX_OBJECTS: usize = 131_072;
const PR_OBJECT_FETCH_MAX_BYTES: u64 = 512 * 1024 * 1024;
const PR_OBJECT_FETCH_MAX_GRAPH_STEPS: usize = PR_OBJECT_FETCH_MAX_OBJECTS * 4;
const PR_OBJECT_FETCH_TIMEOUT: Duration = Duration::from_secs(300);
const APPROVED_GITHUB_LOGIN_CONFIG_KEY: &str = "agentFiles.approvedGitHubLogin";
const APPROVED_GITHUB_ACTOR_CAPTURE_LIMIT: usize = 4 * 1024;
const APPROVED_GITHUB_ACTOR_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GITHUB_TOKEN_BYTES: usize = 16 * 1024;
const MAX_PR_OBSERVATION_DETAIL_CHARS: usize = 256;
const MAX_REPOSITORY_CONFIG_BYTES: usize = 128 * 1024;

pub const DEFAULT_ROLLING_WINDOW_SECONDS: u64 =
    crate::budget_ledger::DEFAULT_ROLLING_WINDOW_SECONDS;

#[derive(Debug, Clone)]
pub struct InboxScanOptions {
    pub repo: PathBuf,
    pub github: bool,
    pub permission_mode: Option<InboxPermissionMode>,
    pub max_items: Option<usize>,
    pub action_policy_override: Option<InboxActionPolicy>,
}

/// Operator-reviewed machine-global cleanup authority forwarded to each
/// per-item autopilot dispatch. Effectful item work is refused without it.
#[derive(Debug, Clone)]
pub struct InboxMachineGlobalInput {
    pub config: PathBuf,
    pub runtime_root_id: String,
}

impl InboxMachineGlobalInput {
    fn retention_binding_for_run(&self, autopilot_run_id: &RunId) -> MachineGlobalRetentionBinding {
        MachineGlobalRetentionBinding {
            config: self.config.clone(),
            root_id: self.runtime_root_id.clone(),
            owner: "maco-inbox".to_string(),
            correction_correlation_id: autopilot_run_id.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InboxRunOptions {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub github: bool,
    pub permission_mode: Option<InboxPermissionMode>,
    pub dry_run: bool,
    pub max_items: Option<usize>,
    pub codex_bin: Option<PathBuf>,
    pub machine_global: Option<InboxMachineGlobalInput>,
}

/// Operator-configured aggregate quota shared by sequential inbox autopilot runs.
///
/// This inbox-owned value keeps the crate-private durable-ledger type out of the
/// public API. Each effectful item converts and binds it to the nested autopilot
/// run id so the supervisor run-budget ledger owns admission and reconciliation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InboxRollingBudgetQuota {
    pub max_tokens: Option<usize>,
    pub max_cost_usd: Option<f64>,
    pub window_seconds: u64,
}

impl InboxRollingBudgetQuota {
    fn into_rolling_budget_quota(self) -> Result<crate::budget_ledger::RollingBudgetQuota> {
        crate::budget_ledger::RollingBudgetQuota {
            max_tokens: self.max_tokens,
            max_cost_usd: self.max_cost_usd,
            window_seconds: self.window_seconds,
        }
        .validate()
    }
}

#[derive(Debug, Clone)]
pub struct InboxWatchOptions {
    pub repo: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub github: bool,
    pub permission_mode: Option<InboxPermissionMode>,
    pub dry_run: bool,
    pub max_items: Option<usize>,
    pub codex_bin: Option<PathBuf>,
    pub machine_global: Option<InboxMachineGlobalInput>,
}

#[derive(Debug, Clone)]
pub struct InboxWorkspaceScanOptions {
    pub config: PathBuf,
}

#[derive(Debug, Clone)]
pub struct InboxWorkspaceRunOptions {
    pub config: PathBuf,
    pub run_id: RunId,
    pub dry_run: bool,
    pub codex_bin: Option<PathBuf>,
    pub machine_global: Option<InboxMachineGlobalInput>,
}

#[derive(Debug, Clone)]
pub struct InboxWorkspaceWatchOptions {
    pub config: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub dry_run: bool,
    pub codex_bin: Option<PathBuf>,
    pub machine_global: Option<InboxMachineGlobalInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub repository: InboxRepositoryConfig,
    #[serde(default)]
    pub selection: InboxSelectionConfig,
    #[serde(default)]
    pub action_policy: InboxActionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<InboxPermissionMode>,
    #[serde(default = "default_max_repair_attempts")]
    pub max_repair_attempts: usize,
    #[serde(default)]
    pub default_validation_commands: Vec<InboxValidationCommandConfig>,
    #[serde(default = "default_assigned_paths")]
    pub default_assigned_paths: Vec<PathBuf>,
    #[serde(default)]
    pub privacy: InboxPrivacyPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_bin: Option<PathBuf>,
}

impl Default for InboxConfig {
    fn default() -> Self {
        Self {
            version: INBOX_SCHEMA_VERSION,
            repository: InboxRepositoryConfig::default(),
            selection: InboxSelectionConfig::default(),
            action_policy: InboxActionPolicy::default(),
            permission_mode: None,
            max_repair_attempts: default_max_repair_attempts(),
            default_validation_commands: Vec::new(),
            default_assigned_paths: default_assigned_paths(),
            privacy: InboxPrivacyPolicy::default(),
            timeout_seconds: None,
            codex_bin: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxWorkspaceConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default = "default_workspace_permission_mode")]
    pub default_permission_mode: InboxPermissionMode,
    #[serde(default = "default_max_items")]
    pub default_max_items_per_repo: usize,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub repositories: Vec<InboxWorkspaceRepositoryConfig>,
    #[serde(default)]
    pub safety: InboxWorkspaceSafetyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxWorkspaceRepositoryConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    pub id: String,
    pub path: PathBuf,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub permission_mode: Option<InboxPermissionMode>,
    #[serde(default)]
    pub max_items: Option<usize>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default = "default_true")]
    pub include_pull_requests: bool,
    #[serde(default = "default_true")]
    pub include_issues: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxWorkspaceSafetyConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub allow_auto_approval: bool,
    #[serde(default)]
    pub allow_auto_merge: bool,
    #[serde(default = "default_true")]
    pub require_clean_primary: bool,
    #[serde(default = "default_true")]
    pub require_validation_for_publication: bool,
}

impl Default for InboxWorkspaceSafetyConfig {
    fn default() -> Self {
        Self {
            version: INBOX_SCHEMA_VERSION,
            dry_run: false,
            allow_auto_approval: false,
            allow_auto_merge: false,
            require_clean_primary: true,
            require_validation_for_publication: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxRepositoryConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

impl Default for InboxRepositoryConfig {
    fn default() -> Self {
        Self {
            version: INBOX_SCHEMA_VERSION,
            owner: None,
            name: None,
            default_branch: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxSelectionConfig {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default = "default_true")]
    pub issues: bool,
    #[serde(default = "default_true", alias = "prs")]
    pub pull_requests: bool,
    #[serde(default = "default_max_items")]
    pub max_items: usize,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub include_draft_prs: bool,
}

impl Default for InboxSelectionConfig {
    fn default() -> Self {
        Self {
            version: INBOX_SCHEMA_VERSION,
            issues: true,
            pull_requests: true,
            max_items: DEFAULT_MAX_ITEMS,
            labels: Vec::new(),
            include_draft_prs: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxActionPolicy {
    DryRun,
    #[default]
    Fake,
    Github,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxPermissionMode {
    #[default]
    Fake,
    #[serde(alias = "github-read")]
    GithubRead,
    #[serde(alias = "github-local")]
    GithubLocal,
    #[serde(alias = "github-git")]
    GithubGit,
    #[serde(alias = "github-pr")]
    GithubPr,
    #[serde(alias = "github-full", alias = "github")]
    GithubFull,
}

impl InboxPermissionMode {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.replace('-', "_").as_str() {
            "fake" => Ok(Self::Fake),
            "github_read" => Ok(Self::GithubRead),
            "github_local" => Ok(Self::GithubLocal),
            "github_git" => Ok(Self::GithubGit),
            "github_pr" => Ok(Self::GithubPr),
            "github_full" | "github" => Ok(Self::GithubFull),
            _ => Err(
                "expected one of: fake, github_read, github_local, github_git, github_pr, github_full"
                    .to_string(),
            ),
        }
    }

    fn uses_github_intake(self) -> bool {
        matches!(
            self,
            Self::GithubRead
                | Self::GithubLocal
                | Self::GithubGit
                | Self::GithubPr
                | Self::GithubFull
        )
    }

    fn launches_autopilot(self) -> bool {
        !matches!(self, Self::GithubRead)
    }

    fn publishes_github_pr(self) -> bool {
        matches!(self, Self::GithubPr | Self::GithubFull)
    }

    fn publishes_git_branch(self) -> bool {
        matches!(self, Self::GithubGit)
    }

    fn publishes_real_branch_or_pr(self) -> bool {
        self.publishes_git_branch() || self.publishes_github_pr()
    }

    fn comments_on_source(self) -> bool {
        matches!(self, Self::GithubFull)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxPrivacyPolicy {
    #[serde(default = "default_inbox_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub allow_private_bodies: bool,
    #[serde(default = "default_blocked_terms")]
    pub blocked_terms: Vec<String>,
    #[serde(default = "default_body_limit")]
    pub max_body_chars: usize,
}

impl Default for InboxPrivacyPolicy {
    fn default() -> Self {
        Self {
            version: INBOX_SCHEMA_VERSION,
            allow_private_bodies: false,
            blocked_terms: default_blocked_terms(),
            max_body_chars: DEFAULT_BODY_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxValidationCommandConfig {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InboxValidationCommandInput {
    Legacy(String),
    Object(InboxValidationCommandObject),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxValidationCommandObject {
    #[serde(default = "default_inbox_schema_version")]
    version: u32,
    #[serde(default)]
    name: Option<String>,
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

impl<'de> Deserialize<'de> for InboxValidationCommandConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = InboxValidationCommandInput::deserialize(deserializer)?;
        Ok(match input {
            InboxValidationCommandInput::Legacy(command) => Self {
                version: INBOX_SCHEMA_VERSION,
                name: None,
                command,
                timeout_seconds: None,
            },
            InboxValidationCommandInput::Object(object) => Self {
                version: object.version,
                name: object.name,
                command: object.command,
                timeout_seconds: object.timeout_seconds,
            },
        })
    }
}

impl From<&InboxValidationCommandConfig> for AutopilotValidationCommand {
    fn from(command: &InboxValidationCommandConfig) -> Self {
        Self {
            name: command.name.clone(),
            command: command.command.clone(),
            timeout_seconds: command.timeout_seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxScanReport {
    pub version: u32,
    pub repo: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    pub action_policy: InboxActionPolicy,
    pub permission_mode: InboxPermissionMode,
    pub github_enabled: bool,
    pub success: bool,
    pub refused: bool,
    pub refusals: Vec<InboxRefusal>,
    pub candidate_count: usize,
    pub selected_count: usize,
    pub items: Vec<InboxItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pr_intake_reports: Vec<InboxPrIntakeReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_loops: Vec<review_loop_entry::InboxReviewLoopReport>,
    pub next_action: String,
}

/// A non-repair PR intake decision. Clean PRs enter an independent audit lane;
/// they are never silently treated as having no work to do.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxPrIntakeReport {
    pub version: u32,
    pub item_id: String,
    pub source_key: String,
    pub number: u64,
    pub task_kind: InboxPrIntakeTaskKind,
    pub status: InboxPrIntakeStatus,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<InboxIndependentAuditMergeLaneTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_block: Option<InboxPrLaunchBlockReport>,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxPrIntakeTaskKind {
    IndependentAuditMergeLane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxPrIntakeStatus {
    Ready,
    LaunchBlocked,
}

/// Source-bound work request for an auditor that is independent of the PR
/// producer. This is evidence for a later merge-authority adapter, not merge
/// permission and not an instruction to perform a merge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxIndependentAuditMergeLaneTask {
    pub version: u32,
    pub task_kind: InboxPrIntakeTaskKind,
    pub source_snapshot_digest: String,
    pub source_updated_at: String,
    pub head_oid: String,
    pub base_oid: String,
    pub producer_login: String,
    #[serde(default)]
    pub is_draft: bool,
    #[serde(default)]
    pub source_trust: GithubPrSourceTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_repository: Option<String>,
    pub changed_files: Vec<PathBuf>,
    pub checks: Vec<GithubCheckSummary>,
    pub requires_trusted_actor_binding: bool,
    pub requires_fresh_source_revalidation: bool,
    pub requires_passing_ci: bool,
    pub requires_independent_auditor: bool,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
    pub next_action: String,
}

/// Typed fail-closed evidence explaining why the independent audit lane was
/// not launched.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxPrLaunchBlockReport {
    pub version: u32,
    pub status: InboxPrIntakeStatus,
    pub success: bool,
    pub reason: String,
    pub missing_evidence: Vec<String>,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRefusal {
    pub kind: String,
    pub message: String,
    pub paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_details: Vec<InboxLockRefusalDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxLockRefusalDetail {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InboxItem {
    pub item_id: String,
    pub source_key: String,
    pub source_snapshot: InboxSourceSnapshotBinding,
    pub kind: InboxItemKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue: Option<GithubIssueCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<GithubPrCandidate>,
    pub privacy: PrivacyScanResult,
    pub duplicate: DuplicateDetectionResult,
    pub selected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxItemKind {
    Issue,
    PullRequest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPrSourceTrust {
    TrustedTargetRepository,
    Fork,
    #[default]
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxSourceProvider {
    Github,
    Fake,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxSourceSnapshotBinding {
    version: u32,
    provider: InboxSourceProvider,
    repository_host: String,
    repository_selector: String,
    repository_identity: String,
    kind: InboxItemKind,
    number: u64,
    source_key: String,
    updated_at: String,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    head_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_oid: Option<String>,
    content_digest: String,
    action_revision_digest: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxSourceSnapshotBindingWire {
    version: u32,
    provider: InboxSourceProvider,
    repository_host: String,
    repository_selector: String,
    repository_identity: String,
    kind: InboxItemKind,
    number: u64,
    source_key: String,
    updated_at: String,
    state: String,
    #[serde(default)]
    head_oid: Option<String>,
    #[serde(default)]
    base_oid: Option<String>,
    content_digest: String,
    action_revision_digest: String,
    digest: String,
}

#[derive(Serialize)]
struct InboxSourceSnapshotDigestPayload<'a> {
    version: u32,
    provider: InboxSourceProvider,
    repository_host: &'a str,
    repository_selector: &'a str,
    repository_identity: &'a str,
    kind: InboxItemKind,
    number: u64,
    source_key: &'a str,
    updated_at: &'a str,
    state: &'a str,
    head_oid: Option<&'a str>,
    base_oid: Option<&'a str>,
    content_digest: &'a str,
    action_revision_digest: &'a str,
}

struct InboxSourceSnapshotObservation {
    provider: InboxSourceProvider,
    repository_host: String,
    repository_selector: String,
    repository_identity: String,
    kind: InboxItemKind,
    number: u64,
    updated_at: String,
    state: String,
    head_oid: Option<String>,
    base_oid: Option<String>,
    content_digest: String,
    action_revision_digest: String,
}

impl InboxSourceSnapshotBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn for_issue(
        provider: InboxSourceProvider,
        repository_host: impl Into<String>,
        repository_selector: impl Into<String>,
        repository_identity: impl Into<String>,
        number: u64,
        updated_at: impl Into<String>,
        state: impl Into<String>,
        content_digest: impl Into<String>,
        action_revision_digest: impl Into<String>,
    ) -> Result<Self> {
        Self::from_observation(InboxSourceSnapshotObservation {
            provider,
            repository_host: repository_host.into(),
            repository_selector: repository_selector.into(),
            repository_identity: repository_identity.into(),
            kind: InboxItemKind::Issue,
            number,
            updated_at: updated_at.into(),
            state: state.into(),
            head_oid: None,
            base_oid: None,
            content_digest: content_digest.into(),
            action_revision_digest: action_revision_digest.into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_pull_request(
        provider: InboxSourceProvider,
        repository_host: impl Into<String>,
        repository_selector: impl Into<String>,
        repository_identity: impl Into<String>,
        number: u64,
        updated_at: impl Into<String>,
        state: impl Into<String>,
        head_oid: String,
        base_oid: String,
        content_digest: impl Into<String>,
        action_revision_digest: impl Into<String>,
    ) -> Result<Self> {
        Self::from_observation(InboxSourceSnapshotObservation {
            provider,
            repository_host: repository_host.into(),
            repository_selector: repository_selector.into(),
            repository_identity: repository_identity.into(),
            kind: InboxItemKind::PullRequest,
            number,
            updated_at: updated_at.into(),
            state: state.into(),
            head_oid: Some(head_oid),
            base_oid: Some(base_oid),
            content_digest: content_digest.into(),
            action_revision_digest: action_revision_digest.into(),
        })
    }

    fn from_observation(observation: InboxSourceSnapshotObservation) -> Result<Self> {
        let mut binding = Self {
            version: SOURCE_SNAPSHOT_VERSION,
            provider: observation.provider,
            repository_host: observation.repository_host,
            repository_selector: observation.repository_selector,
            repository_identity: observation.repository_identity,
            kind: observation.kind,
            number: observation.number,
            source_key: source_key(observation.kind, observation.number),
            updated_at: observation.updated_at,
            state: observation.state,
            head_oid: observation.head_oid,
            base_oid: observation.base_oid,
            content_digest: observation.content_digest,
            action_revision_digest: observation.action_revision_digest,
            digest: String::new(),
        };
        binding.digest = binding.deterministic_digest()?;
        binding.validate()?;
        Ok(binding)
    }

    pub fn deterministic_digest(&self) -> Result<String> {
        let payload = InboxSourceSnapshotDigestPayload {
            version: self.version,
            provider: self.provider,
            repository_host: &self.repository_host,
            repository_selector: &self.repository_selector,
            repository_identity: &self.repository_identity,
            kind: self.kind,
            number: self.number,
            source_key: &self.source_key,
            updated_at: &self.updated_at,
            state: &self.state,
            head_oid: self.head_oid.as_deref(),
            base_oid: self.base_oid.as_deref(),
            content_digest: &self.content_digest,
            action_revision_digest: &self.action_revision_digest,
        };
        let mut bytes = SOURCE_SNAPSHOT_DIGEST_DOMAIN.to_vec();
        bytes.extend(
            serde_json::to_vec(&payload)
                .context("failed to serialize inbox source snapshot digest payload")?,
        );
        Ok(stable_checksum(&bytes))
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SOURCE_SNAPSHOT_VERSION {
            bail!(
                "inbox source snapshot version must be {}; got {}",
                SOURCE_SNAPSHOT_VERSION,
                self.version
            );
        }
        match self.provider {
            InboxSourceProvider::Github => {
                publication::validate_github_source_repository_binding(
                    &self.repository_host,
                    &self.repository_selector,
                )?;
            }
            InboxSourceProvider::Fake => {
                if self.repository_host == "fake" {
                    validate_repository_selector(&self.repository_selector)?;
                } else {
                    publication::validate_github_source_repository_binding(
                        &self.repository_host,
                        &self.repository_selector,
                    )?;
                }
            }
        }
        validate_bounded_text(
            &self.repository_identity,
            "inbox source snapshot repository_identity",
            128,
            false,
        )?;
        validate_git_oid(
            &self.repository_identity,
            "inbox source snapshot repository_identity",
        )?;
        if self.repository_identity.len() != 64 {
            bail!("inbox source snapshot repository_identity is not SHA-256");
        }
        if self.number == 0 {
            bail!("inbox source snapshot number must be positive");
        }
        let expected_key = source_key(self.kind, self.number);
        if self.source_key != expected_key {
            bail!("inbox source snapshot source_key does not match kind and number");
        }
        validate_timestamp(&self.updated_at)?;
        validate_bounded_text(&self.state, "inbox source snapshot state", 64, false)?;
        validate_git_oid(&self.content_digest, "content_digest")?;
        validate_git_oid(&self.action_revision_digest, "action_revision_digest")?;
        match self.kind {
            InboxItemKind::Issue => {
                if self.head_oid.is_some() || self.base_oid.is_some() {
                    bail!("inbox issue source snapshot must not contain PR OIDs");
                }
            }
            InboxItemKind::PullRequest => {
                validate_git_oid(
                    self.head_oid
                        .as_deref()
                        .context("inbox PR source snapshot requires head_oid")?,
                    "head_oid",
                )?;
                validate_git_oid(
                    self.base_oid
                        .as_deref()
                        .context("inbox PR source snapshot requires base_oid")?,
                    "base_oid",
                )?;
            }
        }
        if self.digest != self.deterministic_digest()? {
            bail!("inbox source snapshot digest does not match its canonical fields");
        }
        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn provider(&self) -> InboxSourceProvider {
        self.provider
    }

    pub fn repository_selector(&self) -> &str {
        &self.repository_selector
    }

    pub fn repository_host(&self) -> &str {
        &self.repository_host
    }

    pub fn repository_identity(&self) -> &str {
        &self.repository_identity
    }

    pub fn kind(&self) -> InboxItemKind {
        self.kind
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn source_key(&self) -> &str {
        &self.source_key
    }

    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn head_oid(&self) -> Option<&str> {
        self.head_oid.as_deref()
    }

    pub fn base_oid(&self) -> Option<&str> {
        self.base_oid.as_deref()
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn action_revision_digest(&self) -> &str {
        &self.action_revision_digest
    }

    fn external_source_guard(&self) -> Result<Option<ExternalSourceGuard>> {
        if self.provider != InboxSourceProvider::Github {
            return Ok(None);
        }
        Ok(Some(ExternalSourceGuard::new(
            "github",
            self.repository_host.clone(),
            self.repository_selector.clone(),
            self.repository_identity.clone(),
            match self.kind {
                InboxItemKind::Issue => ExternalSourceObjectKind::Issue,
                InboxItemKind::PullRequest => ExternalSourceObjectKind::PullRequest,
            },
            self.number,
            self.updated_at.clone(),
            self.state.clone(),
            self.head_oid.clone(),
            self.base_oid.clone(),
            self.content_digest.clone(),
            self.action_revision_digest.clone(),
        )?))
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl<'de> Deserialize<'de> for InboxSourceSnapshotBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = InboxSourceSnapshotBindingWire::deserialize(deserializer)?;
        let binding = Self {
            version: wire.version,
            provider: wire.provider,
            repository_host: wire.repository_host,
            repository_selector: wire.repository_selector,
            repository_identity: wire.repository_identity,
            kind: wire.kind,
            number: wire.number,
            source_key: wire.source_key,
            updated_at: wire.updated_at,
            state: wire.state,
            head_oid: wire.head_oid,
            base_oid: wire.base_oid,
            content_digest: wire.content_digest,
            action_revision_digest: wire.action_revision_digest,
            digest: wire.digest,
        };
        binding
            .validate()
            .map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubIssueCandidate {
    pub number: u64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub body_summary: String,
    pub body_truncated: bool,
    pub assigned_paths: Vec<PathBuf>,
    #[serde(
        default,
        skip_serializing_if = "crate::planning::TaskPathProposalDiagnostics::is_empty"
    )]
    pub path_proposal: planning::TaskPathProposalDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubPrCandidate {
    pub number: u64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    #[serde(default)]
    pub is_draft: bool,
    #[serde(default)]
    pub source_trust: GithubPrSourceTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_repository: Option<String>,
    pub changed_files: Vec<PathBuf>,
    pub checks: Vec<GithubCheckSummary>,
    pub review_feedback: GithubReviewFeedbackSummary,
    pub body_summary: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubCheckSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct GithubReviewFeedbackSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_decision: Option<String>,
    pub requested_changes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_thread_count: Option<usize>,
    pub reviewer_logins: Vec<String>,
    pub summaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivacyScanResult {
    pub safe: bool,
    pub reasons: Vec<String>,
    pub redactions: RedactionSummary,
    pub body_summary: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DuplicateDetectionResult {
    pub duplicate: bool,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRunReport {
    pub version: u32,
    pub run_id: RunId,
    pub repo: PathBuf,
    pub action_policy: InboxActionPolicy,
    pub permission_mode: InboxPermissionMode,
    pub github_enabled: bool,
    pub success: bool,
    pub status: InboxRunStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<InboxRefusal>,
    pub artifacts: InboxRunArtifacts,
    pub selected_item_count: usize,
    pub item_reports: Vec<InboxItemRunReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_intake_producer: Option<InboxPrIntakeProducerBatchReport>,
    pub auto_merge_performed: bool,
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxRunStatus {
    Succeeded,
    Failed,
    Refused,
    DryRun,
    Planned,
    NoItems,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxRunArtifacts {
    pub run_dir: PathBuf,
    pub scan_report: PathBuf,
    pub selected_items: PathBuf,
    pub final_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxItemRunReport {
    pub item_index: usize,
    pub item_id: String,
    pub kind: InboxItemKind,
    pub title: String,
    pub success: bool,
    pub status: String,
    pub plan_path: PathBuf,
    pub autopilot_run_id: String,
    pub autopilot_report_path: PathBuf,
    pub github_report_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autopilot_success: Option<bool>,
    pub github_success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_loop: Option<review_loop_entry::InboxReviewLoopReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr_intake: Option<InboxPrIntakeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independent_audit_lane: Option<review_loop_entry::InboxIndependentAuditLaneResult>,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxGithubActionReport {
    pub mode: InboxActionPolicy,
    pub permission_mode: InboxPermissionMode,
    pub status: String,
    pub success: bool,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxStatusReport {
    pub run_id: RunId,
    pub run_dir: PathBuf,
    pub artifacts: InboxArtifactStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxArtifactStatus {
    pub scan_report: bool,
    pub selected_items: bool,
    pub final_report: bool,
    pub item_plan_count: usize,
    pub item_autopilot_report_count: usize,
    pub item_github_report_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWatchReport {
    pub repo: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub iteration_count: usize,
    pub retained_iteration_count: usize,
    pub dropped_iteration_count: usize,
    pub runs: Vec<InboxRunReport>,
}

/// Typed result of the watch-only, repository-bound open-PR discovery pass.
/// The list payload contributes only positive, unique PR numbers; every other
/// provider field is deliberately ignored and re-observed by the producer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum InboxPrDiscoveryRefusalCause {
    ProviderUnavailable {
        detail: String,
    },
    MalformedProviderResponse {
        detail: String,
    },
    BoundExceeded {
        returned_count: usize,
        maximum_processable: usize,
    },
    DuplicateNumber {
        number: u64,
    },
    ZeroNumber {
        entry_index: usize,
    },
}

/// Additive watch report containing the complete bounded producer batch for
/// one ordinary Inbox iteration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboxPrIntakeProducerBatchReport {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub discovery_sentinel: usize,
    pub maximum_processable: usize,
    pub discovered_count: usize,
    pub producer_report_count: usize,
    pub producer_refusal_count: usize,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_refusal: Option<InboxPrDiscoveryRefusalCause>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub producer_reports: Vec<crate::pr_intake::PrIntakeProducerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceScanReport {
    pub version: u32,
    pub config_path: PathBuf,
    pub strict: bool,
    pub success: bool,
    pub repo_count: usize,
    pub enabled_repo_count: usize,
    pub disabled_repo_count: usize,
    pub successful_repo_count: usize,
    pub failed_repo_count: usize,
    pub refused_repo_count: usize,
    pub repo_counts: InboxWorkspaceRepoCounts,
    pub repositories: Vec<InboxWorkspaceRepoReport>,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceRunReport {
    pub version: u32,
    pub run_id: RunId,
    pub config_path: PathBuf,
    pub run_dir: PathBuf,
    pub strict: bool,
    pub success: bool,
    pub repo_count: usize,
    pub enabled_repo_count: usize,
    pub disabled_repo_count: usize,
    pub successful_repo_count: usize,
    pub failed_repo_count: usize,
    pub refused_repo_count: usize,
    pub repo_counts: InboxWorkspaceRepoCounts,
    pub artifacts: InboxWorkspaceRunArtifacts,
    pub auto_merge_performed: bool,
    pub auto_approval_performed: bool,
    pub repositories: Vec<InboxWorkspaceRepoReport>,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceRunArtifacts {
    pub run_dir: PathBuf,
    pub scan_report: PathBuf,
    pub final_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceWatchReport {
    pub version: u32,
    pub config_path: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub success: bool,
    pub iteration_count: usize,
    pub auto_merge_performed: bool,
    pub auto_approval_performed: bool,
    pub runs: Vec<InboxWorkspaceRunReport>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceRepoCounts {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub refused: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxWorkspaceRepoReport {
    pub id: String,
    pub enabled: bool,
    pub permission_mode: InboxPermissionMode,
    pub status: String,
    pub success: bool,
    pub refused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_report: Option<InboxScanReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_report: Option<InboxRunReport>,
}

#[derive(Debug, Clone)]
struct LoadedConfig {
    config: InboxConfig,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct LoadedWorkspaceConfig {
    config: InboxWorkspaceConfig,
    config_dir: PathBuf,
    public_config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceRepository {
    pub id: String,
    pub path: PathBuf,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
struct WorkspaceRepoSpec {
    id: String,
    artifact_id: String,
    repo_path: PathBuf,
    enabled: bool,
    permission_mode: InboxPermissionMode,
    max_items: usize,
    labels: Vec<String>,
    include_issues: bool,
    include_pull_requests: bool,
}

#[derive(Debug, Clone, Default)]
struct InboxConfigOverrides {
    max_items: Option<usize>,
    action_policy: Option<InboxActionPolicy>,
    labels: Option<Vec<String>>,
    issues: Option<bool>,
    pull_requests: Option<bool>,
    pr_event_target: Option<InboxPrEventTarget>,
    pr_event_task: Option<InboxIndependentAuditMergeLaneTask>,
    authenticated_pr_event: bool,
    pr_dispatch_mode: InboxPrDispatchMode,
    pr_intake_producer: Option<InboxPrIntakeProducerBatchReport>,
    #[cfg(test)]
    fixed_scan_items: Option<Vec<InboxItem>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum InboxPrDispatchMode {
    #[default]
    All,
    RepairOnly,
}

#[derive(Debug, Clone)]
struct InboxPrEventTarget {
    number: u64,
    head_oid: String,
}

#[derive(Debug, Clone)]
struct RawIssueCandidate {
    provider: InboxSourceProvider,
    number: u64,
    title: String,
    body: String,
    url: Option<String>,
    author: Option<String>,
    labels: Vec<String>,
    updated_at: String,
    state: String,
    content_digest: String,
    action_revision_digest: String,
    assigned_paths: Vec<PathBuf>,
    path_proposal: planning::TaskPathProposalDiagnostics,
}

#[derive(Debug, Clone)]
struct RawPrCandidate {
    provider: InboxSourceProvider,
    number: u64,
    title: String,
    body: String,
    url: Option<String>,
    author: Option<String>,
    labels: Vec<String>,
    updated_at: String,
    state: String,
    content_digest: String,
    action_revision_digest: String,
    head_ref: Option<String>,
    base_ref: Option<String>,
    head_oid: String,
    base_oid: String,
    is_draft: bool,
    source_trust: GithubPrSourceTrust,
    head_repository: Option<String>,
    changed_files: Vec<PathBuf>,
    checks: Vec<GithubCheckSummary>,
    review_feedback: GithubReviewFeedbackSummary,
}

#[derive(Debug, Clone)]
struct SourceRepositoryBindingContext {
    host: String,
    selector: String,
    identity: String,
}

pub fn scan_inbox(options: InboxScanOptions) -> Result<InboxScanReport> {
    scan_inbox_with_overrides(options, InboxConfigOverrides::default())
}

fn scan_inbox_with_overrides(
    options: InboxScanOptions,
    mut overrides: InboxConfigOverrides,
) -> Result<InboxScanReport> {
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        None,
    )?;
    let repo = discover_repo_root(&options.repo)?;
    if options.max_items.is_some() {
        overrides.max_items = options.max_items;
    }
    if options.action_policy_override.is_some() {
        overrides.action_policy = options.action_policy_override;
    }
    let loaded = load_config_with_config_overrides(&repo, overrides.clone())?;
    let permission_mode =
        effective_permission_mode(&loaded.config, options.github, options.permission_mode);
    let action_policy = effective_action_policy(loaded.config.action_policy, permission_mode);
    let github_enabled = permission_mode.uses_github_intake();
    let duplicate_keys = load_duplicate_keys(&repo)?;
    let duplicate_pr_snapshots = load_duplicate_pr_snapshots(&repo)?;
    let source_repository =
        source_repository_binding_context(&repo, &loaded.config, github_enabled)?;
    let mut items = Vec::new();
    #[cfg(test)]
    let uses_fixed_scan_items = overrides.fixed_scan_items.is_some();
    #[cfg(not(test))]
    let uses_fixed_scan_items = false;
    #[cfg(test)]
    if let Some(fixed_scan_items) = overrides.fixed_scan_items.clone() {
        for item in fixed_scan_items {
            if pr_dispatch_mode_allows_item(overrides.pr_dispatch_mode, &item) {
                items.push(item);
            }
        }
    }
    if !uses_fixed_scan_items {
        if loaded.config.selection.issues {
            let issues = if github_enabled {
                github_issue_candidates(&repo, &loaded.config, &source_repository)?
            } else {
                fake_issue_candidates(&loaded.config)
            };
            for issue in issues {
                items.push(issue_item(
                    issue,
                    &loaded.config,
                    &source_repository,
                    &duplicate_keys,
                )?);
            }
        }
        if loaded.config.selection.pull_requests {
            let pull_requests = if github_enabled {
                match &overrides.pr_event_target {
                    Some(target) => vec![github_pr_candidate(
                        &repo,
                        &loaded.config,
                        &source_repository,
                        target.number,
                    )?],
                    None => github_pr_candidates(&repo, &loaded.config, &source_repository)?,
                }
            } else {
                fake_pr_candidates(&loaded.config)
            };
            for pull_request in pull_requests {
                if !should_include_pr_candidate(&loaded.config, &pull_request) {
                    continue;
                }
                let mut item = pr_item(
                    pull_request,
                    &loaded.config,
                    &source_repository,
                    &duplicate_keys,
                )?;
                if !pr_dispatch_mode_allows_item(overrides.pr_dispatch_mode, &item) {
                    continue;
                }
                apply_pr_snapshot_duplicate(&mut item, &duplicate_pr_snapshots);
                items.push(item);
            }
        }
    }
    validate_count(items.len(), "inbox candidate items", MAX_GITHUB_ITEMS)?;
    if let Some(target) = &overrides.pr_event_target {
        let number_seen = items.iter().any(|item| {
            item.kind == InboxItemKind::PullRequest
                && item
                    .pull_request
                    .as_ref()
                    .is_some_and(|pull_request| pull_request.number == target.number)
        });
        items.retain(|item| {
            item.kind == InboxItemKind::PullRequest
                && item
                    .pull_request
                    .as_ref()
                    .is_some_and(|pull_request| pull_request.number == target.number)
                && item.source_snapshot.head_oid() == Some(target.head_oid.as_str())
        });
        if !number_seen {
            bail!("authenticated PR intake target was not present in the fresh provider scan");
        }
        if items.is_empty() {
            bail!("authenticated PR intake target head changed before dispatch");
        }
    }
    if let Some(expected_task) = &overrides.pr_event_task {
        verify_pr_event_task(&items, expected_task)?;
    }
    items.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.item_id.cmp(&right.item_id))
    });
    apply_scan_decisions(&mut items, loaded.config.selection.max_items);
    let pr_intake_reports = items
        .iter()
        .filter(|item| item.selected)
        .filter_map(pr_intake_report_for_item)
        .collect::<Vec<_>>();
    let review_loops = review_loop_entry::evaluate_inbox_scan_review_loops(&items);

    let selected_count = items.iter().filter(|item| item.selected).count();
    let candidate_count = items.len();
    let target_paths = selected_target_paths(&items, &loaded.config)?;
    let refusals = preflight_refusals(&repo, &target_paths)?;
    if !refusals.is_empty() {
        return Ok(InboxScanReport {
            version: INBOX_SCHEMA_VERSION,
            repo: public_repo_path(),
            config_path: loaded.path,
            action_policy,
            permission_mode,
            github_enabled,
            success: false,
            refused: true,
            refusals,
            candidate_count,
            selected_count,
            items,
            pr_intake_reports,
            review_loops,
            next_action: "resolve inbox safety refusals, then scan again".to_string(),
        });
    }
    Ok(InboxScanReport {
        version: INBOX_SCHEMA_VERSION,
        repo: public_repo_path(),
        config_path: loaded.path,
        action_policy,
        permission_mode,
        github_enabled,
        success: true,
        refused: false,
        refusals: Vec::new(),
        candidate_count,
        selected_count,
        items,
        pr_intake_reports,
        review_loops,
        next_action: if selected_count == 0 {
            "no safe non-duplicate inbox items selected".to_string()
        } else {
            "run maco inbox run with a stable run id".to_string()
        },
    })
}

pub fn run_inbox(options: InboxRunOptions) -> Result<InboxRunReport> {
    run_inbox_with_rolling_budget(options, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxPrObservationFailureClass {
    ProviderUnavailable,
    MalformedProviderResponse,
    InvalidProviderGroundTruth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPrObservationError {
    pub classification: InboxPrObservationFailureClass,
    pub detail: String,
}

impl InboxPrObservationError {
    fn new(classification: InboxPrObservationFailureClass, detail: impl AsRef<str>) -> Self {
        Self {
            classification,
            detail: bounded_pr_observation_detail(detail.as_ref()),
        }
    }
}

impl std::fmt::Display for InboxPrObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for InboxPrObservationError {}

fn bounded_pr_observation_detail(detail: &str) -> String {
    let mut bounded = detail
        .chars()
        .take(MAX_PR_OBSERVATION_DETAIL_CHARS)
        .collect::<String>();
    if detail.chars().count() > MAX_PR_OBSERVATION_DETAIL_CHARS {
        bounded.push_str("...");
    }
    bounded
}

pub(crate) fn sanitize_pr_intake_provider_detail(repo: &Path, detail: &str) -> String {
    sanitize_public_text(repo, detail, MAX_PR_OBSERVATION_DETAIL_CHARS).text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxApprovedGithubActorFailure {
    MissingOrAmbiguousPin,
    MalformedPin,
    ActorUnavailable,
    MalformedActorResponse,
    PinMismatch,
    BindingChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxApprovedGithubActorError {
    pub failure: InboxApprovedGithubActorFailure,
    pub detail: String,
}

impl InboxApprovedGithubActorError {
    fn new(failure: InboxApprovedGithubActorFailure, detail: impl AsRef<str>) -> Self {
        Self {
            failure,
            detail: bounded_pr_observation_detail(detail.as_ref()),
        }
    }
}

impl std::fmt::Display for InboxApprovedGithubActorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for InboxApprovedGithubActorError {}

pub(crate) struct InboxApprovedGithubActorBinding {
    config_path: PathBuf,
    approved_login: String,
    config_bytes: Vec<u8>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl InboxApprovedGithubActorBinding {
    pub(crate) fn verify_fresh(&self) -> Result<(), InboxApprovedGithubActorError> {
        let current = capture_repository_config(&self.config_path).map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::BindingChanged,
                "repository-local approved GitHub login binding became unavailable",
            )
        })?;
        #[cfg(unix)]
        let same_identity = self.device == current.device && self.inode == current.inode;
        #[cfg(not(unix))]
        let same_identity = false;
        if !same_identity || self.config_bytes != current.bytes {
            return Err(InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::BindingChanged,
                "repository-local approved GitHub login binding changed before launch",
            ));
        }
        Ok(())
    }
}

impl Drop for InboxApprovedGithubActorBinding {
    fn drop(&mut self) {
        self.config_bytes.fill(0);
        self.approved_login.clear();
    }
}

struct RepositoryConfigCapture {
    bytes: Vec<u8>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

pub(crate) fn bind_approved_github_actor(
    repo: &Path,
) -> Result<InboxApprovedGithubActorBinding, InboxApprovedGithubActorError> {
    bind_approved_github_actor_with(repo, || authenticated_github_actor(repo))
}

pub(crate) fn bind_approved_github_actor_with<F>(
    repo: &Path,
    actor_lookup: F,
) -> Result<InboxApprovedGithubActorBinding, InboxApprovedGithubActorError>
where
    F: FnOnce() -> Result<String, InboxApprovedGithubActorError>,
{
    let repository = crate::git_repository::discover(repo).map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
            "repository-local approved GitHub login configuration was unavailable",
        )
    })?;
    let config_path = repository.commondir().join("config");
    let capture = capture_repository_config(&config_path).map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
            "repository-local approved GitHub login configuration was unavailable",
        )
    })?;
    let config = git2::Config::open(&config_path).map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
            "repository-local approved GitHub login configuration was unreadable",
        )
    })?;
    let mut values = Vec::new();
    match config.multivar(APPROVED_GITHUB_LOGIN_CONFIG_KEY, None) {
        Ok(mut entries) => {
            while let Some(entry) = entries.next() {
                let entry = entry.map_err(|_| {
                    InboxApprovedGithubActorError::new(
                        InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
                        "repository-local approved GitHub login pins could not be enumerated",
                    )
                })?;
                if entry.include_depth() == 0 {
                    let value = std::str::from_utf8(entry.value_bytes()).map_err(|_| {
                        InboxApprovedGithubActorError::new(
                            InboxApprovedGithubActorFailure::MalformedPin,
                            "repository-local approved GitHub login was not UTF-8",
                        )
                    })?;
                    values.push(value.to_string());
                }
            }
        }
        Err(error) if error.code() == git2::ErrorCode::NotFound => {}
        Err(_) => {
            return Err(InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
                "repository-local approved GitHub login pins could not be enumerated",
            ));
        }
    }
    if values.len() != 1 || values[0].is_empty() {
        return Err(InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
            "repository-local approved GitHub login must contain exactly one non-empty value",
        ));
    }
    validate_github_actor_login(&values[0]).map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MalformedPin,
            "repository-local approved GitHub login was malformed",
        )
    })?;
    let binding = InboxApprovedGithubActorBinding {
        config_path,
        approved_login: values.remove(0),
        config_bytes: capture.bytes,
        #[cfg(unix)]
        device: capture.device,
        #[cfg(unix)]
        inode: capture.inode,
    };
    binding.verify_fresh()?;
    let actual = actor_lookup()?;
    validate_github_actor_login(&actual).map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::MalformedActorResponse,
            "authenticated GitHub actor response was malformed",
        )
    })?;
    if actual != binding.approved_login {
        return Err(InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::PinMismatch,
            "authenticated GitHub actor did not exactly match the approved repository login",
        ));
    }
    binding.verify_fresh()?;
    Ok(binding)
}

fn capture_repository_config(
    path: &Path,
) -> std::result::Result<RepositoryConfigCapture, anyhow::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let before = fs::symlink_metadata(path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(path)?;
        let opened = file.metadata()?;
        let after = fs::symlink_metadata(path)?;
        let safe = |metadata: &fs::Metadata| {
            !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && metadata.permissions().mode() & 0o022 == 0
                && (metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == 0)
                && metadata.nlink() == 1
        };
        let same = |left: &fs::Metadata, right: &fs::Metadata| {
            left.dev() == right.dev() && left.ino() == right.ino()
        };
        if !safe(&before)
            || !safe(&opened)
            || !safe(&after)
            || !same(&before, &opened)
            || !same(&opened, &after)
        {
            bail!("repository config was not a path-bound trusted regular file");
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_REPOSITORY_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REPOSITORY_CONFIG_BYTES {
            bytes.fill(0);
            bail!("repository config exceeded its safety bound");
        }
        Ok(RepositoryConfigCapture {
            bytes,
            device: opened.dev(),
            inode: opened.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("repository config identity verification is unsupported on this platform")
    }
}

fn validate_github_actor_login(login: &str) -> Result<()> {
    if login.is_empty()
        || login.len() > MAX_GITHUB_LOGIN_BYTES
        || matches!(login, "." | "..")
        || !login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("GitHub actor login was malformed");
    }
    Ok(())
}

fn authenticated_github_actor(repo: &Path) -> Result<String, InboxApprovedGithubActorError> {
    let mut token = approved_github_actor_token()?;
    let mut runtime = crate::merge::PrivateRuntimeDirectory::create(
        repo,
        crate::merge::PrivateRuntimeKind::GhConfig,
    )
    .map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::ActorUnavailable,
            "authenticated GitHub actor runtime was unavailable",
        )
    })?;
    let directory = runtime.path().to_path_buf();
    let result = (|| {
        let token_text = std::str::from_utf8(&token).map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::ActorUnavailable,
                "GitHub authentication token was malformed",
            )
        })?;
        let hosts_path = directory.join("hosts.yml");
        let hosts =
            format!("'github.com':\n    oauth_token: '{token_text}'\n    git_protocol: https\n");
        crate::merge::write_private_file(&hosts_path, hosts.as_bytes()).map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::ActorUnavailable,
                "authenticated GitHub actor configuration was unavailable",
            )
        })?;
        let mut environment = crate::merge::minimal_network_environment().map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::ActorUnavailable,
                "authenticated GitHub actor environment was unavailable",
            )
        })?;
        for key in [
            "GIT_CONFIG_NOSYSTEM",
            "GIT_ATTR_NOSYSTEM",
            "GIT_OPTIONAL_LOCKS",
            "GIT_TERMINAL_PROMPT",
        ] {
            environment.remove(key);
        }
        environment.insert(
            "GH_CONFIG_DIR".to_string(),
            directory
                .to_str()
                .ok_or_else(|| {
                    InboxApprovedGithubActorError::new(
                        InboxApprovedGithubActorFailure::ActorUnavailable,
                        "authenticated GitHub actor runtime path was not UTF-8",
                    )
                })?
                .to_string(),
        );
        environment.insert("GH_PROMPT_DISABLED".to_string(), "1".to_string());
        let output = crate::merge::run_required_network_direct(
            "gh authenticated actor",
            crate::merge::resolve_trusted_executable("gh").map_err(|_| {
                InboxApprovedGithubActorError::new(
                    InboxApprovedGithubActorFailure::ActorUnavailable,
                    "trusted gh executable was unavailable",
                )
            })?,
            ["api", "user", "--jq", ".login"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            &directory,
            environment,
            StdinMode::Null,
            APPROVED_GITHUB_ACTOR_TIMEOUT,
            APPROVED_GITHUB_ACTOR_CAPTURE_LIMIT,
            0,
            TrustedFixedNetworkProfile::read_write(&directory)
                .with_resource_limits(ProcessResourceLimits::default())
                .with_visible_read_only_file(&hosts_path),
        )
        .map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::ActorUnavailable,
                "authenticated GitHub actor lookup was unavailable",
            )
        })?;
        if !output.success {
            return Err(InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::ActorUnavailable,
                "authenticated GitHub actor lookup failed",
            ));
        }
        let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
            InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::MalformedActorResponse,
                "authenticated GitHub actor response was not UTF-8",
            )
        })?;
        let login = stdout.strip_suffix('\n').unwrap_or(stdout);
        if login.contains(['\r', '\n']) {
            return Err(InboxApprovedGithubActorError::new(
                InboxApprovedGithubActorFailure::MalformedActorResponse,
                "authenticated GitHub actor response contained multiple lines",
            ));
        }
        Ok(login.to_string())
    })();
    token.fill(0);
    let cleanup = runtime.close().map_err(|_| {
        InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::ActorUnavailable,
            "authenticated GitHub actor runtime cleanup failed",
        )
    });
    match (result, cleanup) {
        (Ok(login), Ok(())) => Ok(login),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn approved_github_actor_token() -> Result<Vec<u8>, InboxApprovedGithubActorError> {
    let values = ["GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .filter_map(|key| env::var(key).ok())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let Some(first) = values.first() else {
        return Err(InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::ActorUnavailable,
            "authenticated GitHub actor lookup requires GH_TOKEN or GITHUB_TOKEN",
        ));
    };
    if values.iter().any(|value| value != first) {
        return Err(InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::ActorUnavailable,
            "GitHub authentication token variables were ambiguous",
        ));
    }
    if first.len() < 4
        || first.len() > MAX_GITHUB_TOKEN_BYTES
        || first
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(InboxApprovedGithubActorError::new(
            InboxApprovedGithubActorFailure::ActorUnavailable,
            "GitHub authentication token was malformed or oversized",
        ));
    }
    Ok(first.as_bytes().to_vec())
}

/// Read one exact GitHub pull request through the trusted Inbox source
/// boundary without accepting requester-supplied PR fields as ground truth.
pub(crate) fn observe_inbox_pr_event(
    options: &InboxRunOptions,
    number: u64,
) -> std::result::Result<InboxItem, InboxPrObservationError> {
    observe_inbox_pr_event_with(options, number, |repo, selector, number| {
        publication::view_github_source_item(
            repo,
            selector,
            number,
            ExternalSourceObjectKind::PullRequest,
        )
        .map_err(|error| {
            InboxPrObservationError::new(
                InboxPrObservationFailureClass::ProviderUnavailable,
                format!("GitHub PR provider transport was unavailable: {error:#}"),
            )
        })
    })
}

fn observe_inbox_pr_event_with<F>(
    options: &InboxRunOptions,
    number: u64,
    view: F,
) -> std::result::Result<InboxItem, InboxPrObservationError>
where
    F: FnOnce(&Path, &str, u64) -> std::result::Result<Value, InboxPrObservationError>,
{
    let unavailable = |error: anyhow::Error| {
        InboxPrObservationError::new(
            InboxPrObservationFailureClass::ProviderUnavailable,
            format!("GitHub PR observation preflight was unavailable: {error:#}"),
        )
    };
    if number == 0 {
        return Err(InboxPrObservationError::new(
            InboxPrObservationFailureClass::InvalidProviderGroundTruth,
            "GitHub PR observation requires a positive pull-request number",
        ));
    }
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        options.codex_bin.as_deref(),
    )
    .map_err(unavailable)?;
    let repo = discover_repo_root(&options.repo).map_err(unavailable)?;
    let loaded = load_config_with_config_overrides(
        &repo,
        InboxConfigOverrides {
            max_items: Some(1),
            issues: Some(false),
            pull_requests: Some(true),
            authenticated_pr_event: true,
            ..InboxConfigOverrides::default()
        },
    )
    .map_err(unavailable)?;
    let permission_mode =
        effective_permission_mode(&loaded.config, options.github, options.permission_mode);
    if !permission_mode.uses_github_intake() {
        return Err(InboxPrObservationError::new(
            InboxPrObservationFailureClass::ProviderUnavailable,
            "production PR observation requires an explicit GitHub Inbox permission mode",
        ));
    }
    let source_repository =
        source_repository_binding_context(&repo, &loaded.config, true).map_err(unavailable)?;
    let value = view(&repo, &source_repository.selector, number)?;
    let raw = raw_pr_from_value(&value, &loaded.config, &source_repository).map_err(|error| {
        InboxPrObservationError::new(
            InboxPrObservationFailureClass::MalformedProviderResponse,
            format!("GitHub PR provider response was malformed: {error:#}"),
        )
    })?;
    if raw.number != number {
        return Err(InboxPrObservationError::new(
            InboxPrObservationFailureClass::InvalidProviderGroundTruth,
            "exact GitHub PR observation returned a different pull-request number",
        ));
    }
    let item =
        pr_item(raw, &loaded.config, &source_repository, &BTreeMap::new()).map_err(|error| {
            InboxPrObservationError::new(
                InboxPrObservationFailureClass::InvalidProviderGroundTruth,
                format!("GitHub PR provider ground truth was invalid: {error:#}"),
            )
        })?;
    item.source_snapshot.validate().map_err(|error| {
        InboxPrObservationError::new(
            InboxPrObservationFailureClass::InvalidProviderGroundTruth,
            format!("GitHub PR provider snapshot was invalid: {error:#}"),
        )
    })?;
    Ok(item)
}

/// Resolve the exact provider-owned PR snapshot before any auditor or
/// publication effect is admitted for an authenticated intake event.
pub(crate) fn preflight_inbox_pr_event(
    options: &InboxRunOptions,
    number: u64,
    expected_head_oid: &str,
) -> Result<InboxIndependentAuditMergeLaneTask> {
    let scan = scan_inbox_with_overrides(
        InboxScanOptions {
            repo: options.repo.clone(),
            github: options.github,
            permission_mode: options.permission_mode,
            max_items: None,
            action_policy_override: None,
        },
        InboxConfigOverrides {
            max_items: Some(1),
            issues: Some(false),
            pull_requests: Some(true),
            pr_event_target: Some(InboxPrEventTarget {
                number,
                head_oid: expected_head_oid.to_string(),
            }),
            authenticated_pr_event: true,
            ..InboxConfigOverrides::default()
        },
    )?;
    let item = scan
        .items
        .into_iter()
        .find(|item| item.selected)
        .context("authenticated PR event target was not eligible for a new Inbox run")?;
    pr_intake_report_for_item(&item)
        .and_then(|report| report.task)
        .context("authenticated PR event target produced no source-bound audit task")
}

/// Run the ordinary Inbox pipeline for exactly one authenticated PR event.
/// The provider scan remains the source of truth; the event supplies only the
/// identity and expected freshness watermark used to filter that scan.
pub(crate) fn run_inbox_for_pr_event(
    mut options: InboxRunOptions,
    number: u64,
    expected_head_oid: &str,
    expected_task: &InboxIndependentAuditMergeLaneTask,
    before_auditor_launch: Option<
        &mut dyn FnMut(&str, &InboxIndependentAuditorSelectionEvidence) -> Result<()>,
    >,
) -> Result<InboxRunReport> {
    options.max_items = None;
    run_inbox_with_overrides(
        options,
        None,
        InboxConfigOverrides {
            max_items: Some(1),
            issues: Some(false),
            pull_requests: Some(true),
            pr_event_target: Some(InboxPrEventTarget {
                number,
                head_oid: expected_head_oid.to_string(),
            }),
            pr_event_task: Some(expected_task.clone()),
            authenticated_pr_event: true,
            ..InboxConfigOverrides::default()
        },
        before_auditor_launch,
    )
}

pub fn run_inbox_with_rolling_budget(
    options: InboxRunOptions,
    rolling_budget_quota: Option<InboxRollingBudgetQuota>,
) -> Result<InboxRunReport> {
    run_inbox_with_overrides(
        options,
        rolling_budget_quota,
        InboxConfigOverrides::default(),
        None,
    )
}

fn run_inbox_with_overrides(
    options: InboxRunOptions,
    rolling_budget_quota: Option<InboxRollingBudgetQuota>,
    mut overrides: InboxConfigOverrides,
    mut before_auditor_launch: Option<
        &mut dyn FnMut(&str, &InboxIndependentAuditorSelectionEvidence) -> Result<()>,
    >,
) -> Result<InboxRunReport> {
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        options.codex_bin.as_deref(),
    )?;
    let rolling_budget_quota = rolling_budget_quota
        .map(InboxRollingBudgetQuota::into_rolling_budget_quota)
        .transpose()?;
    let repo = discover_repo_root(&options.repo)?;
    if options.max_items.is_some() {
        overrides.max_items = options.max_items;
    }
    if options.dry_run {
        overrides.action_policy = Some(InboxActionPolicy::DryRun);
    }
    let loaded = load_config_with_config_overrides(&repo, overrides.clone())?;
    let preflight_permission_mode =
        effective_permission_mode(&loaded.config, options.github, options.permission_mode);
    let preflight_action_policy =
        effective_action_policy(loaded.config.action_policy, preflight_permission_mode);
    let event_reviewer_bound = overrides.authenticated_pr_event
        && (options.codex_bin.is_some() || loaded.config.codex_bin.is_some());
    if preflight_permission_mode.publishes_real_branch_or_pr()
        && preflight_action_policy != InboxActionPolicy::DryRun
        && !event_reviewer_bound
    {
        bail!(
            "real Inbox publication requires an explicitly bound external reviewer; the deterministic fake reviewer is not publication authority"
        );
    }
    let artifacts = run_artifacts(&options.run_id);
    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Inbox,
        options.run_id.clone(),
        "inbox",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let scan = match scan_inbox_with_overrides(
        InboxScanOptions {
            repo: repo.clone(),
            github: options.github,
            permission_mode: options.permission_mode,
            max_items: None,
            action_policy_override: None,
        },
        overrides.clone(),
    ) {
        Ok(scan) => scan,
        Err(error) => {
            let message =
                sanitize_public_text(&repo, &format!("{error:#}"), GH_DIAGNOSTIC_LIMIT).text;
            write_private_artifact_json(
                &mut artifact_writer,
                "scan-report.json",
                &json!({
                    "version": INBOX_SCHEMA_VERSION,
                    "status": "failed",
                    "success": false,
                    "message": message,
                }),
            )?;
            write_private_artifact_json(
                &mut artifact_writer,
                "selected-items.json",
                &Vec::<InboxItem>::new(),
            )?;
            let report = InboxRunReport {
                version: INBOX_SCHEMA_VERSION,
                run_id: options.run_id,
                repo: public_repo_path(),
                action_policy: preflight_action_policy,
                permission_mode: preflight_permission_mode,
                github_enabled: preflight_permission_mode.uses_github_intake(),
                success: false,
                status: InboxRunStatus::Failed,
                refusals: Vec::new(),
                artifacts,
                selected_item_count: 0,
                item_reports: Vec::new(),
                pr_intake_producer: overrides.pr_intake_producer.clone(),
                auto_merge_performed: false,
                next_action: "repair inbox intake, then rerun with the same bounded configuration"
                    .to_string(),
            };
            write_private_artifact_json(&mut artifact_writer, "final-report.json", &report)?;
            artifact_writer.finalize("final-report.json", false)?;
            return Ok(report);
        }
    };
    write_private_artifact_json(&mut artifact_writer, "scan-report.json", &scan)?;

    let selected_items = scan
        .items
        .iter()
        .filter(|item| item.selected)
        .cloned()
        .collect::<Vec<_>>();
    write_private_artifact_json(&mut artifact_writer, "selected-items.json", &selected_items)?;

    if scan.refused {
        let report = InboxRunReport {
            version: INBOX_SCHEMA_VERSION,
            run_id: options.run_id,
            repo: public_repo_path(),
            action_policy: scan.action_policy,
            permission_mode: scan.permission_mode,
            github_enabled: scan.github_enabled,
            success: false,
            status: InboxRunStatus::Refused,
            refusals: scan.refusals,
            artifacts,
            selected_item_count: 0,
            item_reports: Vec::new(),
            pr_intake_producer: overrides.pr_intake_producer.clone(),
            auto_merge_performed: false,
            next_action: "resolve inbox safety refusals, then rerun".to_string(),
        };
        write_private_artifact_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }

    if selected_items.is_empty() {
        let report = InboxRunReport {
            version: INBOX_SCHEMA_VERSION,
            run_id: options.run_id,
            repo: public_repo_path(),
            action_policy: scan.action_policy,
            permission_mode: scan.permission_mode,
            github_enabled: scan.github_enabled,
            success: true,
            status: InboxRunStatus::NoItems,
            refusals: Vec::new(),
            artifacts,
            selected_item_count: 0,
            item_reports: Vec::new(),
            pr_intake_producer: overrides.pr_intake_producer.clone(),
            auto_merge_performed: false,
            next_action: "no safe non-duplicate inbox items were available".to_string(),
        };
        write_private_artifact_json(&mut artifact_writer, "final-report.json", &report)?;
        artifact_writer.finalize("final-report.json", false)?;
        return Ok(report);
    }

    let real_runtime_requested = options.codex_bin.is_some() || loaded.config.codex_bin.is_some();
    let action_policy = scan.action_policy;
    let permission_mode = scan.permission_mode;
    let item_context = InboxItemRunContext {
        repo: &repo,
        run_dir: &run_dir,
        run_id: &options.run_id,
        config: &loaded.config,
        action_policy,
        permission_mode,
        codex_bin: options
            .codex_bin
            .clone()
            .or_else(|| loaded.config.codex_bin.clone()),
        machine_global: options.machine_global.clone(),
        rolling_budget_quota,
    };
    let mut item_reports = Vec::new();
    let mut refusals = Vec::new();
    for (zero_index, item) in selected_items.iter().enumerate() {
        let item_index = zero_index.saturating_add(1);
        let input = InboxItemRunInput {
            context: &item_context,
            item_index,
            item,
        };
        let outcome = match before_auditor_launch.as_mut() {
            Some(hook) => run_inbox_item(&mut artifact_writer, input, Some(&mut **hook))?,
            None => run_inbox_item(&mut artifact_writer, input, None)?,
        };
        item_reports.push(outcome.report);
        if let Some(refusal) = outcome.refusal {
            refusals.push(refusal);
            break;
        }
    }

    let success = refusals.is_empty() && item_reports.iter().all(|report| report.success);
    let status = if !refusals.is_empty() {
        InboxRunStatus::Refused
    } else if action_policy == InboxActionPolicy::DryRun {
        InboxRunStatus::DryRun
    } else if !permission_mode.launches_autopilot() {
        InboxRunStatus::Planned
    } else if success {
        InboxRunStatus::Succeeded
    } else {
        InboxRunStatus::Failed
    };
    let auto_merge_performed = item_reports.iter().any(|item| {
        item.independent_audit_lane
            .as_ref()
            .is_some_and(|lane| lane.auto_merge_performed && lane.merge_receipt.is_some())
    });
    let report = InboxRunReport {
        version: INBOX_SCHEMA_VERSION,
        run_id: options.run_id,
        repo: public_repo_path(),
        action_policy,
        permission_mode,
        github_enabled: scan.github_enabled,
        success,
        status,
        refusals,
        artifacts,
        selected_item_count: selected_items.len(),
        item_reports,
        pr_intake_producer: overrides.pr_intake_producer,
        auto_merge_performed,
        next_action: if status == InboxRunStatus::Refused {
            "increase or wait for the rolling inbox quota before starting another run".to_string()
        } else if success && auto_merge_performed {
            "review the verified authenticated pull-request merge receipt".to_string()
        } else if success {
            "review inbox item reports; no automatic merge was performed".to_string()
        } else {
            "inspect failed item reports and rerun after repair".to_string()
        },
    };
    write_private_artifact_json(&mut artifact_writer, "final-report.json", &report)?;
    let publish_requested =
        report.success && real_runtime_requested && permission_mode.publishes_real_branch_or_pr();
    artifact_writer.finalize("final-report.json", publish_requested)?;
    Ok(report)
}

pub fn inbox_status(repo: impl AsRef<Path>, run_id: RunId) -> Result<InboxStatusReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let (artifacts, final_report) = match inbox_artifact_run_state(&repo, &run_id)? {
        ArtifactRunState::Missing => (empty_artifact_status(), None),
        ArtifactRunState::Active(run_dir) => (unfinalized_artifact_status(&run_dir)?, None),
        ArtifactRunState::Finalized(reader) => {
            let final_report = Some(read_artifact_json(&reader, "final-report.json")?);
            (artifact_status(&reader), final_report)
        }
    };
    Ok(InboxStatusReport {
        run_dir: public_run_dir().join(run_id.as_str()),
        run_id,
        artifacts,
        final_report,
    })
}

pub fn collect_inbox_run(repo: impl AsRef<Path>, run_id: RunId) -> Result<Value> {
    let repo = discover_repo_root(repo.as_ref())?;
    match inbox_artifact_run_state(&repo, &run_id)? {
        ArtifactRunState::Missing => Ok(json!({
            "version": INBOX_SCHEMA_VERSION,
            "run_id": run_id,
            "status": "missing",
            "success": false,
            "next_action": "rerun maco inbox run for this run id"
        })),
        ArtifactRunState::Active(_) => bail!(
            "inbox run '{}' is active or unfinalized; collect requires a verified finalization marker",
            run_id.as_str()
        ),
        ArtifactRunState::Finalized(reader) => read_artifact_json(&reader, "final-report.json"),
    }
}

fn pr_discovery_refusal(cause: InboxPrDiscoveryRefusalCause) -> InboxPrIntakeProducerBatchReport {
    InboxPrIntakeProducerBatchReport {
        version: INBOX_SCHEMA_VERSION,
        repository: None,
        discovery_sentinel: GITHUB_WATCH_PR_DISCOVERY_SENTINEL,
        maximum_processable: MAX_GITHUB_WATCH_PR_PRODUCERS,
        discovered_count: 0,
        producer_report_count: 0,
        producer_refusal_count: 0,
        success: false,
        discovery_refusal: Some(cause),
        producer_reports: Vec::new(),
    }
}

fn bounded_pr_discovery_detail(detail: &str) -> String {
    sanitize_public_field(detail, MAX_PR_OBSERVATION_DETAIL_CHARS)
}

fn malformed_pr_discovery(detail: &str) -> InboxPrDiscoveryRefusalCause {
    InboxPrDiscoveryRefusalCause::MalformedProviderResponse {
        detail: bounded_pr_discovery_detail(detail),
    }
}

fn provider_pr_discovery(detail: &str) -> InboxPrDiscoveryRefusalCause {
    InboxPrDiscoveryRefusalCause::ProviderUnavailable {
        detail: bounded_pr_discovery_detail(detail),
    }
}

fn publication_pr_list_refusal(error: &anyhow::Error) -> InboxPrDiscoveryRefusalCause {
    let detail = format!("{error:#}");
    if [
        "did not return valid JSON",
        "did not return a JSON array",
        "exceeded its JSON byte limit",
        "returned more items than requested",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
    {
        malformed_pr_discovery(&detail)
    } else {
        provider_pr_discovery(&detail)
    }
}

fn github_watch_pr_list(
    options: &InboxRunOptions,
    kind: ExternalSourceObjectKind,
    limit: usize,
    labels: &[String],
) -> std::result::Result<(String, Value), InboxPrDiscoveryRefusalCause> {
    let preflight = || -> Result<(PathBuf, SourceRepositoryBindingContext)> {
        validate_cli_source_options(
            options.github,
            options.permission_mode,
            options.max_items,
            options.codex_bin.as_deref(),
        )?;
        let repo = discover_repo_root(&options.repo)?;
        let loaded = load_config(&repo)?;
        let permission_mode =
            effective_permission_mode(&loaded.config, options.github, options.permission_mode);
        if !permission_mode.uses_github_intake() {
            bail!("watch PR discovery requires an explicit GitHub Inbox permission mode");
        }
        let source_repository = source_repository_binding_context(&repo, &loaded.config, true)?;
        Ok((repo, source_repository))
    };
    let (repo, source_repository) =
        preflight().map_err(|error| provider_pr_discovery(&format!("{error:#}")))?;
    let output = publication::list_github_source_items(
        &repo,
        &source_repository.selector,
        kind,
        limit,
        labels,
    )
    .map_err(|error| publication_pr_list_refusal(&error))?;
    Ok((source_repository.selector, output))
}

fn parse_github_watch_pr_numbers(
    value: &Value,
) -> std::result::Result<Vec<u64>, InboxPrDiscoveryRefusalCause> {
    let values = value
        .as_array()
        .ok_or_else(|| malformed_pr_discovery("GitHub PR discovery response was not an array"))?;
    if values.len() >= GITHUB_WATCH_PR_DISCOVERY_SENTINEL {
        return Err(InboxPrDiscoveryRefusalCause::BoundExceeded {
            returned_count: values.len(),
            maximum_processable: MAX_GITHUB_WATCH_PR_PRODUCERS,
        });
    }
    let mut numbers = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let number = value
            .as_object()
            .and_then(|object| object.get("number"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                malformed_pr_discovery(&format!(
                    "GitHub PR discovery entry {} omitted an unsigned number",
                    index.saturating_add(1)
                ))
            })?;
        if number == 0 {
            return Err(InboxPrDiscoveryRefusalCause::ZeroNumber {
                entry_index: index.saturating_add(1),
            });
        }
        if !numbers.insert(number) {
            return Err(InboxPrDiscoveryRefusalCause::DuplicateNumber { number });
        }
    }
    Ok(numbers.into_iter().collect())
}

fn produce_github_watch_pr_intakes_with<L, P>(
    list: L,
    mut produce: P,
) -> InboxPrIntakeProducerBatchReport
where
    L: FnOnce(
        ExternalSourceObjectKind,
        usize,
        &[String],
    ) -> std::result::Result<(String, Value), InboxPrDiscoveryRefusalCause>,
    P: FnMut(u64) -> crate::pr_intake::PrIntakeProducerReport,
{
    let no_labels = Vec::new();
    let (repository, value) = match list(
        ExternalSourceObjectKind::PullRequest,
        GITHUB_WATCH_PR_DISCOVERY_SENTINEL,
        &no_labels,
    ) {
        Ok(response) => response,
        Err(cause) => return pr_discovery_refusal(cause),
    };
    let numbers = match parse_github_watch_pr_numbers(&value) {
        Ok(numbers) => numbers,
        Err(cause) => {
            let mut report = pr_discovery_refusal(cause);
            report.repository = Some(repository);
            return report;
        }
    };

    let mut producer_reports = Vec::with_capacity(numbers.len());
    for number in numbers {
        let mut report = produce(number);
        if report.repository.is_none() {
            report.repository = Some(repository.clone());
        }
        if report.number.is_none() {
            report.number = Some(number);
        }
        producer_reports.push(report);
    }
    let producer_refusal_count = producer_reports
        .iter()
        .filter(|report| {
            report.disposition == crate::pr_intake::PrIntakeProducerDisposition::Refused
        })
        .count();
    InboxPrIntakeProducerBatchReport {
        version: INBOX_SCHEMA_VERSION,
        repository: Some(repository),
        discovery_sentinel: GITHUB_WATCH_PR_DISCOVERY_SENTINEL,
        maximum_processable: MAX_GITHUB_WATCH_PR_PRODUCERS,
        discovered_count: producer_reports.len(),
        producer_report_count: producer_reports.len(),
        producer_refusal_count,
        success: producer_refusal_count == 0,
        discovery_refusal: None,
        producer_reports,
    }
}

fn watch_iteration_uses_github(options: &InboxRunOptions) -> Result<bool> {
    let repo = discover_repo_root(&options.repo)?;
    let loaded = load_config(&repo)?;
    Ok(
        effective_permission_mode(&loaded.config, options.github, options.permission_mode)
            .uses_github_intake(),
    )
}

fn run_github_watch_iteration_with<L, P, R>(
    options: InboxRunOptions,
    list: L,
    produce: P,
    run_ordinary: R,
) -> Result<InboxRunReport>
where
    L: FnOnce(
        &InboxRunOptions,
        ExternalSourceObjectKind,
        usize,
        &[String],
    ) -> std::result::Result<(String, Value), InboxPrDiscoveryRefusalCause>,
    P: FnMut(InboxRunOptions, u64) -> crate::pr_intake::PrIntakeProducerReport,
    R: FnOnce(InboxRunOptions, InboxConfigOverrides) -> Result<InboxRunReport>,
{
    let producer_options = options.clone();
    let mut produce = produce;
    let producer_report = produce_github_watch_pr_intakes_with(
        |kind, limit, labels| list(&producer_options, kind, limit, labels),
        |number| produce(producer_options.clone(), number),
    );
    run_ordinary(
        options,
        InboxConfigOverrides {
            pr_dispatch_mode: InboxPrDispatchMode::RepairOnly,
            pr_intake_producer: Some(producer_report),
            ..InboxConfigOverrides::default()
        },
    )
}

fn run_github_watch_iteration(options: InboxRunOptions) -> Result<InboxRunReport> {
    run_github_watch_iteration_with(
        options,
        |options, kind, limit, labels| github_watch_pr_list(options, kind, limit, labels),
        |options, number| crate::pr_intake::produce_repository_pr_intake(options, number),
        |options, overrides| run_inbox_with_overrides(options, None, overrides, None),
    )
}

fn retain_watch_run(runs: &mut VecDeque<InboxRunReport>, report: InboxRunReport) {
    if runs.len() == MAX_WATCH_RETAINED_ITERATIONS {
        runs.pop_front();
    }
    runs.push_back(report);
}

pub fn watch_inbox(options: InboxWatchOptions) -> Result<InboxWatchReport> {
    validate_poll_seconds(options.poll_seconds)?;
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        options.codex_bin.as_deref(),
    )?;
    let repo = discover_repo_root(&options.repo)?;
    let mut runs = VecDeque::with_capacity(MAX_WATCH_RETAINED_ITERATIONS);
    let mut iteration = 0usize;
    loop {
        iteration = iteration
            .checked_add(1)
            .context("inbox watch iteration count overflowed")?;
        let run_id =
            artifacts::generate_run_id(&repo, RunArtifactFamily::Inbox).with_context(|| {
                format!("failed to generate inbox watch run id for iteration {iteration}")
            })?;
        let run_options = InboxRunOptions {
            repo: repo.clone(),
            run_id,
            github: options.github,
            permission_mode: options.permission_mode,
            dry_run: options.dry_run,
            max_items: options.max_items,
            codex_bin: options.codex_bin.clone(),
            machine_global: options.machine_global.clone(),
        };
        let report = if watch_iteration_uses_github(&run_options)? {
            run_github_watch_iteration(run_options)?
        } else {
            run_inbox(run_options)?
        };
        retain_watch_run(&mut runs, report);
        if options.once {
            break;
        }
        thread::sleep(Duration::from_secs(options.poll_seconds));
    }
    let retained_iteration_count = runs.len();
    let dropped_iteration_count = iteration.saturating_sub(retained_iteration_count);
    Ok(InboxWatchReport {
        repo: public_repo_path(),
        poll_seconds: options.poll_seconds,
        once: options.once,
        iteration_count: iteration,
        retained_iteration_count,
        dropped_iteration_count,
        runs: runs.into_iter().collect(),
    })
}

pub fn scan_workspace_inbox(
    options: InboxWorkspaceScanOptions,
) -> Result<InboxWorkspaceScanReport> {
    let loaded = load_workspace_config(&options.config)?;
    let specs = workspace_repo_specs(&loaded)?;
    Ok(scan_workspace_specs(&loaded, &specs))
}

pub fn run_workspace_inbox(options: InboxWorkspaceRunOptions) -> Result<InboxWorkspaceRunReport> {
    if let Some(codex_bin) = &options.codex_bin {
        validate_path_text(codex_bin, "workspace codex-bin", MAX_CODEX_PATH_BYTES)?;
    }
    let loaded = load_workspace_config(&options.config)?;
    let specs = workspace_repo_specs(&loaded)?;
    let run_dir = workspace_run_dir(&loaded.config_dir, &options.run_id);
    ensure_workspace_run_dir_available(&run_dir, &options.run_id)?;
    fs::create_dir_all(&run_dir).with_context(|| {
        format!(
            "failed to create inbox workspace run dir {}",
            run_dir.display()
        )
    })?;

    let scan_report = scan_workspace_specs(&loaded, &specs);
    write_json_file(&run_dir.join("scan-report.json"), &scan_report)?;
    for entry in &scan_report.repositories {
        if let Some(scan) = &entry.scan_report {
            let artifact_id = workspace_artifact_id_for_entry(&specs, &entry.id)?;
            write_json_file(&run_dir.join(repo_scan_file_name(&artifact_id)), scan)?;
        } else if entry.enabled {
            let artifact_id = workspace_artifact_id_for_entry(&specs, &entry.id)?;
            write_json_file(
                &run_dir.join(repo_scan_file_name(&artifact_id)),
                &workspace_repo_failure_value(entry, "scan"),
            )?;
        }
    }

    let mut repositories = Vec::new();
    let dry_run = options.dry_run || loaded.config.safety.dry_run;
    for spec in specs {
        if !spec.enabled {
            repositories.push(disabled_workspace_repo_report(&spec));
            continue;
        }

        let scan_report = scan_report
            .repositories
            .iter()
            .find(|entry| entry.id == spec.id)
            .and_then(|entry| entry.scan_report.clone());
        if let Some(entry) = workspace_publication_validation_refusal(
            &spec,
            dry_run,
            loaded.config.safety.require_validation_for_publication,
            scan_report.clone(),
        )? {
            write_json_file(
                &run_dir.join(repo_run_file_name(&spec.artifact_id)),
                &workspace_repo_failure_value(&entry, "run"),
            )?;
            repositories.push(entry);
            continue;
        }
        let repo_run_id = workspace_repo_run_id(&options.run_id, &spec.artifact_id)?;
        let run_result = run_inbox_with_overrides(
            InboxRunOptions {
                repo: spec.repo_path.clone(),
                run_id: repo_run_id,
                github: false,
                permission_mode: Some(spec.permission_mode),
                dry_run,
                max_items: None,
                codex_bin: options.codex_bin.clone(),
                machine_global: options.machine_global.clone(),
            },
            None,
            workspace_overrides_for_repo(&spec),
            None,
        );
        match run_result {
            Ok(run_report) => {
                let refused = run_report.status == InboxRunStatus::Refused;
                let message = if refused {
                    run_report
                        .refusals
                        .first()
                        .map(|refusal| refusal.message.clone())
                } else {
                    None
                };
                write_json_file(
                    &run_dir.join(repo_run_file_name(&spec.artifact_id)),
                    &run_report,
                )?;
                repositories.push(InboxWorkspaceRepoReport {
                    id: spec.id,
                    enabled: true,
                    permission_mode: spec.permission_mode,
                    status: inbox_run_status_label(run_report.status).to_string(),
                    success: run_report.success,
                    refused,
                    message,
                    scan_report,
                    run_report: Some(run_report),
                });
            }
            Err(error) => {
                let entry = InboxWorkspaceRepoReport {
                    id: spec.id,
                    enabled: true,
                    permission_mode: spec.permission_mode,
                    status: "failed".to_string(),
                    success: false,
                    refused: false,
                    message: Some(sanitize_public_field(
                        &error.to_string(),
                        GH_DIAGNOSTIC_LIMIT,
                    )),
                    scan_report,
                    run_report: None,
                };
                write_json_file(
                    &run_dir.join(repo_run_file_name(&spec.artifact_id)),
                    &workspace_repo_failure_value(&entry, "run"),
                )?;
                repositories.push(entry);
            }
        }
    }

    let repo_counts = workspace_repo_counts(&repositories);
    let success = workspace_success(loaded.config.strict, &repo_counts);
    let public_run_dir = public_workspace_run_dir().join(options.run_id.as_str());
    let artifacts = InboxWorkspaceRunArtifacts {
        run_dir: public_run_dir.clone(),
        scan_report: public_run_dir.join("scan-report.json"),
        final_report: public_run_dir.join("final-report.json"),
    };
    let auto_merge_performed = repositories.iter().any(|repository| {
        repository
            .run_report
            .as_ref()
            .is_some_and(|report| report.auto_merge_performed)
    });
    let report = InboxWorkspaceRunReport {
        version: INBOX_SCHEMA_VERSION,
        run_id: options.run_id,
        config_path: loaded.public_config_path,
        run_dir: public_run_dir,
        strict: loaded.config.strict,
        success,
        repo_count: repo_counts.total,
        enabled_repo_count: repo_counts.enabled,
        disabled_repo_count: repo_counts.disabled,
        successful_repo_count: repo_counts.succeeded,
        failed_repo_count: repo_counts.failed,
        refused_repo_count: repo_counts.refused,
        repo_counts,
        artifacts,
        auto_merge_performed,
        auto_approval_performed: false,
        repositories,
        next_action: workspace_next_action(success, loaded.config.strict, "workspace run"),
    };
    write_json_file(&run_dir.join("final-report.json"), &report)?;
    Ok(report)
}

pub fn watch_workspace_inbox(
    options: InboxWorkspaceWatchOptions,
) -> Result<InboxWorkspaceWatchReport> {
    validate_poll_seconds(options.poll_seconds)?;
    if let Some(codex_bin) = &options.codex_bin {
        validate_path_text(codex_bin, "workspace codex-bin", MAX_CODEX_PATH_BYTES)?;
    }
    let public_config_path = public_config_path(&options.config);
    let mut runs = Vec::new();
    loop {
        let run_id = generate_workspace_run_id(&options.config)?;
        let report = run_workspace_inbox(InboxWorkspaceRunOptions {
            config: options.config.clone(),
            run_id,
            dry_run: options.dry_run,
            codex_bin: options.codex_bin.clone(),
            machine_global: options.machine_global.clone(),
        })?;
        runs.push(report);
        if options.once {
            break;
        }
        thread::sleep(Duration::from_secs(options.poll_seconds));
    }
    let success = runs.iter().all(|run| run.success);
    let auto_merge_performed = runs.iter().any(|run| run.auto_merge_performed);
    Ok(InboxWorkspaceWatchReport {
        version: INBOX_SCHEMA_VERSION,
        config_path: public_config_path,
        poll_seconds: options.poll_seconds,
        once: options.once,
        success,
        iteration_count: runs.len(),
        auto_merge_performed,
        auto_approval_performed: false,
        runs,
    })
}

fn scan_workspace_specs(
    loaded: &LoadedWorkspaceConfig,
    specs: &[WorkspaceRepoSpec],
) -> InboxWorkspaceScanReport {
    let mut repositories = Vec::new();
    for spec in specs {
        if !spec.enabled {
            repositories.push(disabled_workspace_repo_report(spec));
            continue;
        }
        let scan_result = scan_inbox_with_overrides(
            InboxScanOptions {
                repo: spec.repo_path.clone(),
                github: false,
                permission_mode: Some(spec.permission_mode),
                max_items: None,
                action_policy_override: None,
            },
            workspace_overrides_for_repo(spec),
        );
        match scan_result {
            Ok(scan_report) => repositories.push(InboxWorkspaceRepoReport {
                id: spec.id.clone(),
                enabled: true,
                permission_mode: spec.permission_mode,
                status: if scan_report.refused {
                    "refused".to_string()
                } else {
                    "scanned".to_string()
                },
                success: scan_report.success,
                refused: scan_report.refused,
                message: None,
                scan_report: Some(scan_report),
                run_report: None,
            }),
            Err(error) => repositories.push(InboxWorkspaceRepoReport {
                id: spec.id.clone(),
                enabled: true,
                permission_mode: spec.permission_mode,
                status: "failed".to_string(),
                success: false,
                refused: false,
                message: Some(sanitize_public_field(
                    &error.to_string(),
                    GH_DIAGNOSTIC_LIMIT,
                )),
                scan_report: None,
                run_report: None,
            }),
        }
    }
    let repo_counts = workspace_repo_counts(&repositories);
    let success = workspace_success(loaded.config.strict, &repo_counts);
    InboxWorkspaceScanReport {
        version: INBOX_SCHEMA_VERSION,
        config_path: loaded.public_config_path.clone(),
        strict: loaded.config.strict,
        success,
        repo_count: repo_counts.total,
        enabled_repo_count: repo_counts.enabled,
        disabled_repo_count: repo_counts.disabled,
        successful_repo_count: repo_counts.succeeded,
        failed_repo_count: repo_counts.failed,
        refused_repo_count: repo_counts.refused,
        repo_counts,
        repositories,
        next_action: workspace_next_action(success, loaded.config.strict, "workspace scan"),
    }
}

fn load_workspace_config(path: &Path) -> Result<LoadedWorkspaceConfig> {
    validate_path_text(path, "workspace inbox config path", MAX_CONFIG_PATH_BYTES)?;
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read current directory")?
            .join(path)
    };
    let parent = absolute_path
        .parent()
        .context("workspace inbox config path must have a parent directory")?;
    let file_name = absolute_path
        .file_name()
        .context("workspace inbox config path must have a file name")?;
    let canonical_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve workspace inbox config parent {}",
            public_config_path(path).display()
        )
    })?;
    let root = SafeRoot::open_existing(&canonical_parent)
        .context("failed to bind workspace inbox config directory")?;
    let contents = BoundedRegularReader::read_direct(&root, file_name, MAX_CONFIG_BYTES)
        .with_context(|| {
            format!(
                "failed to read bounded no-follow workspace inbox config {}",
                public_config_path(path).display()
            )
        })?;
    root.verify()
        .context("workspace inbox config directory changed during read")?;
    let contents =
        String::from_utf8(contents).context("workspace inbox config is not valid UTF-8")?;
    let config = serde_json::from_str::<InboxWorkspaceConfig>(&contents).with_context(|| {
        format!(
            "failed to parse workspace inbox config {}",
            public_config_path(path).display()
        )
    })?;
    Ok(LoadedWorkspaceConfig {
        config: validate_workspace_config(config)?,
        config_dir: root.path().to_path_buf(),
        public_config_path: public_config_path(path),
    })
}

pub(crate) fn load_workspace_repositories(path: &Path) -> Result<Vec<WorkspaceRepository>> {
    let loaded = load_workspace_config(path)?;
    Ok(workspace_repo_specs(&loaded)?
        .into_iter()
        .map(|repository| WorkspaceRepository {
            id: repository.id,
            path: repository.repo_path,
            enabled: repository.enabled,
        })
        .collect())
}

fn validate_workspace_config(mut config: InboxWorkspaceConfig) -> Result<InboxWorkspaceConfig> {
    validate_schema_version("workspace inbox config", config.version)?;
    validate_schema_version("workspace inbox safety", config.safety.version)?;
    validate_item_limit(
        config.default_max_items_per_repo,
        "workspace default_max_items_per_repo",
    )?;
    if config.repositories.is_empty() {
        bail!("workspace inbox config must contain at least one repository");
    }
    if config.repositories.len() > MAX_WORKSPACE_REPOSITORIES {
        bail!(
            "workspace inbox config exceeds its {} repository limit",
            MAX_WORKSPACE_REPOSITORIES
        );
    }
    if config.safety.allow_auto_approval {
        bail!("workspace inbox safety.allow_auto_approval=true is not supported");
    }
    if config.safety.allow_auto_merge {
        bail!("workspace inbox safety.allow_auto_merge=true is not supported");
    }
    if !config.safety.require_clean_primary {
        bail!("workspace inbox requires safety.require_clean_primary=true");
    }
    if !config.safety.require_validation_for_publication {
        bail!("workspace inbox requires safety.require_validation_for_publication=true");
    }

    let mut ids = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    for (index, repository) in config.repositories.iter_mut().enumerate() {
        validate_schema_version(
            &format!("workspace repository {}", index + 1),
            repository.version,
        )?;
        repository.id = repository.id.trim().to_string();
        validate_identifier(
            &repository.id,
            &format!("workspace repository {} id", index + 1),
            MAX_WORKSPACE_REPOSITORY_ID_BYTES,
        )?;
        if !ids.insert(repository.id.to_ascii_lowercase()) {
            bail!("workspace repository id '{}' is duplicated", repository.id);
        }
        let artifact_id = sanitize_workspace_repo_id(&repository.id);
        if !artifact_ids.insert(artifact_id.to_ascii_lowercase()) {
            bail!(
                "workspace repository id '{}' collides with another sanitized id '{}'",
                repository.id,
                artifact_id
            );
        }
        if repository.path.as_os_str().is_empty() {
            bail!(
                "workspace repository '{}' path cannot be empty",
                repository.id
            );
        }
        validate_path_text(
            &repository.path,
            &format!("workspace repository '{}' path", repository.id),
            MAX_CONFIG_PATH_BYTES,
        )?;
        if let Some(max_items) = repository.max_items {
            validate_item_limit(
                max_items,
                &format!("workspace repository '{}' max_items", repository.id),
            )?;
        }
        if repository.enabled && !repository.include_issues && !repository.include_pull_requests {
            bail!(
                "workspace repository '{}' must enable issues or pull requests",
                repository.id
            );
        }
        repository.labels = validate_labels(
            std::mem::take(&mut repository.labels),
            &format!("workspace repository '{}' labels", repository.id),
        )?;
    }
    validate_serialized_config_size(&config, "workspace inbox config")?;
    Ok(config)
}

fn workspace_repo_specs(loaded: &LoadedWorkspaceConfig) -> Result<Vec<WorkspaceRepoSpec>> {
    let mut specs = Vec::new();
    let mut canonical_paths = BTreeSet::new();
    for repository in &loaded.config.repositories {
        let configured_path = if repository.path.is_absolute() {
            repository.path.clone()
        } else {
            loaded.config_dir.join(&repository.path)
        };
        let repo_path = canonical_or_lexical_path(&configured_path)?;
        if !canonical_paths.insert(repo_path.clone()) {
            bail!(
                "workspace repository '{}' resolves to the same canonical path as another repository",
                repository.id
            );
        }
        specs.push(WorkspaceRepoSpec {
            id: repository.id.clone(),
            artifact_id: sanitize_workspace_repo_id(&repository.id),
            repo_path,
            enabled: repository.enabled,
            permission_mode: repository
                .permission_mode
                .unwrap_or(loaded.config.default_permission_mode),
            max_items: repository
                .max_items
                .unwrap_or(loaded.config.default_max_items_per_repo),
            labels: repository.labels.clone(),
            include_issues: repository.include_issues,
            include_pull_requests: repository.include_pull_requests,
        });
    }
    Ok(specs)
}

fn workspace_publication_validation_refusal(
    spec: &WorkspaceRepoSpec,
    dry_run: bool,
    require_validation_for_publication: bool,
    scan_report: Option<InboxScanReport>,
) -> Result<Option<InboxWorkspaceRepoReport>> {
    if dry_run
        || !require_validation_for_publication
        || !spec.permission_mode.publishes_real_branch_or_pr()
        || scan_report.is_none()
    {
        return Ok(None);
    }
    let loaded =
        load_config_with_config_overrides(&spec.repo_path, workspace_overrides_for_repo(spec))?;
    if !loaded.config.default_validation_commands.is_empty() {
        return Ok(None);
    }

    let permission_mode = permission_mode_label(spec.permission_mode);
    Ok(Some(InboxWorkspaceRepoReport {
        id: spec.id.clone(),
        enabled: true,
        permission_mode: spec.permission_mode,
        status: "refused".to_string(),
        success: false,
        refused: true,
        message: Some(format!(
            "workspace publication requires at least one validation command for permission mode {permission_mode}"
        )),
        scan_report,
        run_report: None,
    }))
}

fn workspace_overrides_for_repo(spec: &WorkspaceRepoSpec) -> InboxConfigOverrides {
    InboxConfigOverrides {
        max_items: Some(spec.max_items),
        action_policy: None,
        labels: Some(spec.labels.clone()),
        issues: Some(spec.include_issues),
        pull_requests: Some(spec.include_pull_requests),
        pr_event_target: None,
        pr_event_task: None,
        authenticated_pr_event: false,
        ..InboxConfigOverrides::default()
    }
}

fn disabled_workspace_repo_report(spec: &WorkspaceRepoSpec) -> InboxWorkspaceRepoReport {
    InboxWorkspaceRepoReport {
        id: spec.id.clone(),
        enabled: false,
        permission_mode: spec.permission_mode,
        status: "disabled".to_string(),
        success: true,
        refused: false,
        message: Some("repository is disabled in workspace inbox config".to_string()),
        scan_report: None,
        run_report: None,
    }
}

fn workspace_repo_counts(repositories: &[InboxWorkspaceRepoReport]) -> InboxWorkspaceRepoCounts {
    let total = repositories.len();
    let disabled = repositories.iter().filter(|repo| !repo.enabled).count();
    let enabled = total.saturating_sub(disabled);
    let succeeded = repositories
        .iter()
        .filter(|repo| repo.enabled && repo.success)
        .count();
    let refused = repositories
        .iter()
        .filter(|repo| repo.enabled && repo.refused)
        .count();
    let failed = repositories
        .iter()
        .filter(|repo| repo.enabled && !repo.success && !repo.refused)
        .count();
    InboxWorkspaceRepoCounts {
        total,
        enabled,
        disabled,
        succeeded,
        failed,
        refused,
    }
}

fn workspace_success(strict: bool, repo_counts: &InboxWorkspaceRepoCounts) -> bool {
    !strict || (repo_counts.failed == 0 && repo_counts.refused == 0)
}

fn workspace_next_action(success: bool, strict: bool, label: &str) -> String {
    if success {
        format!("{label} complete; no automatic approval or merge was performed")
    } else if strict {
        format!("{label} failed because strict mode or safety refusals require attention")
    } else {
        format!("{label} recorded per-repository safety refusals for review")
    }
}

fn workspace_artifact_id_for_entry(specs: &[WorkspaceRepoSpec], id: &str) -> Result<String> {
    specs
        .iter()
        .find(|spec| spec.id == id)
        .map(|spec| spec.artifact_id.clone())
        .with_context(|| format!("workspace repository '{id}' was not found"))
}

fn workspace_repo_failure_value(entry: &InboxWorkspaceRepoReport, phase: &str) -> Value {
    json!({
        "version": INBOX_SCHEMA_VERSION,
        "repo_id": entry.id,
        "phase": phase,
        "status": entry.status,
        "success": entry.success,
        "refused": entry.refused,
        "message": entry.message,
    })
}

fn workspace_repo_run_id(workspace_run_id: &RunId, artifact_id: &str) -> Result<RunId> {
    RunId::new(format!(
        "{}-repo-{}",
        workspace_run_id.as_str(),
        artifact_id
    ))
}

fn repo_scan_file_name(artifact_id: &str) -> String {
    format!("repo-{artifact_id}-scan-report.json")
}

fn repo_run_file_name(artifact_id: &str) -> String {
    format!("repo-{artifact_id}-run-report.json")
}

fn inbox_run_status_label(status: InboxRunStatus) -> &'static str {
    match status {
        InboxRunStatus::Succeeded => "succeeded",
        InboxRunStatus::Failed => "failed",
        InboxRunStatus::Refused => "refused",
        InboxRunStatus::DryRun => "dry_run",
        InboxRunStatus::Planned => "planned",
        InboxRunStatus::NoItems => "no_items",
    }
}

fn sanitize_workspace_repo_id(id: &str) -> String {
    let mut output = String::new();
    let mut last_was_separator = false;
    for character in id.trim().chars() {
        let safe = if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            character
        } else {
            '-'
        };
        if safe == '-' {
            if last_was_separator {
                continue;
            }
            last_was_separator = true;
        } else {
            last_was_separator = false;
        }
        output.push(safe);
    }
    let trimmed = output.trim_matches(|character| matches!(character, '-' | '.'));
    if trimmed.is_empty() || matches!(trimmed, "." | "..") {
        "repo".to_string()
    } else {
        trimmed.to_string()
    }
}

fn public_config_path(path: &Path) -> PathBuf {
    public_config_file_name(path)
}

fn public_config_file_name(path: &Path) -> PathBuf {
    path.file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("workspace-inbox.json"))
}

fn public_workspace_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("inbox-workspace").join("runs")
}

fn workspace_run_dir(config_dir: &Path, run_id: &RunId) -> PathBuf {
    config_dir
        .join(public_workspace_run_dir())
        .join(run_id.as_str())
}

fn ensure_workspace_run_dir_available(run_dir: &Path, run_id: &RunId) -> Result<()> {
    if run_dir.exists() {
        bail!(
            "inbox workspace run id '{}' already exists at {}; choose a new --run-id",
            run_id.as_str(),
            public_workspace_run_dir().join(run_id.as_str()).display()
        );
    }
    Ok(())
}

fn generate_workspace_run_id(config_path: &Path) -> Result<RunId> {
    let loaded = load_workspace_config(config_path)?;
    let run_root = loaded.config_dir.join(public_workspace_run_dir());
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    for suffix in 0..1000u16 {
        let candidate = RunId::new(format!(
            "inbox-workspace-{}-{}-{}",
            millis,
            process::id(),
            suffix
        ))?;
        if !run_root.join(candidate.as_str()).exists() {
            return Ok(candidate);
        }
    }
    bail!(
        "failed to generate a collision-free inbox workspace run id under {}",
        public_workspace_run_dir().display()
    )
}

struct InboxItemRunContext<'a> {
    repo: &'a Path,
    run_dir: &'a Path,
    run_id: &'a RunId,
    config: &'a InboxConfig,
    action_policy: InboxActionPolicy,
    permission_mode: InboxPermissionMode,
    codex_bin: Option<PathBuf>,
    machine_global: Option<InboxMachineGlobalInput>,
    rolling_budget_quota: Option<crate::budget_ledger::RollingBudgetQuota>,
}

struct InboxItemRunOutcome {
    report: InboxItemRunReport,
    refusal: Option<InboxRefusal>,
}

struct InboxItemRunInput<'a> {
    context: &'a InboxItemRunContext<'a>,
    item_index: usize,
    item: &'a InboxItem,
}

fn run_inbox_item(
    writer: &mut ArtifactRunWriter,
    input: InboxItemRunInput<'_>,
    before_auditor_launch: Option<
        &mut dyn FnMut(&str, &InboxIndependentAuditorSelectionEvidence) -> Result<()>,
    >,
) -> Result<InboxItemRunOutcome> {
    let context = input.context;
    let item_index = input.item_index;
    let item = input.item;
    let repo = context.repo;
    let run_id = context.run_id;
    let action_policy = context.action_policy;
    let permission_mode = context.permission_mode;
    let config = context.config;
    let pr_intake = pr_intake_report_for_item(item);
    let source_fresh = revalidate_inbox_item_source(repo, item).is_ok();
    if pr_intake.is_none() && !source_fresh {
        revalidate_inbox_item_source(repo, item)
            .context("inbox source changed before item processing started")?;
    }
    let review_loop = review_loop_entry::evaluate_inbox_item_review_loop(item);
    if let Some(report) = &review_loop {
        write_private_artifact_json(
            writer,
            format!("item-{item_index}-review-loop.json"),
            report,
        )?;
    }
    if let Some(pr_intake) = pr_intake {
        return run_independent_audit_intake_item(
            writer,
            input,
            review_loop,
            pr_intake,
            source_fresh,
            before_auditor_launch,
        );
    }
    let plan = autopilot_plan_for_item(item, config, permission_mode)?;
    let plan_relative = PathBuf::from(format!("item-{item_index}-plan.json"));
    write_private_artifact_json(writer, &plan_relative, &plan)?;
    let plan_path = context.run_dir.join(&plan_relative);
    let autopilot_report_relative =
        PathBuf::from(format!("item-{item_index}-autopilot-report.json"));
    let github_report_relative = PathBuf::from(format!("item-{item_index}-github-report.json"));
    let autopilot_run_id = RunId::new(format!("{}-item-{item_index}", run_id.as_str()))?;

    if action_policy == InboxActionPolicy::DryRun || !permission_mode.launches_autopilot() {
        let planned_only = action_policy != InboxActionPolicy::DryRun;
        write_private_artifact_json(
            writer,
            &autopilot_report_relative,
            &json!({
                "status": "skipped",
                "success": true,
                "reason": if planned_only {
                    "permission mode does not launch autopilot"
                } else {
                    "dry_run action policy does not launch autopilot"
                }
            }),
        )?;
        let github_report = InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "skipped".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some(if planned_only {
                "permission mode does not comment or publish".to_string()
            } else {
                "dry_run action policy does not comment or publish".to_string()
            }),
        };
        write_private_artifact_json(writer, &github_report_relative, &github_report)?;
        return Ok(InboxItemRunOutcome {
            report: InboxItemRunReport {
                item_index,
                item_id: item.item_id.clone(),
                kind: item.kind,
                title: item.title.clone(),
                success: true,
                status: if planned_only {
                    "planned".to_string()
                } else {
                    "dry_run".to_string()
                },
                plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
                autopilot_run_id: autopilot_run_id.as_str().to_string(),
                autopilot_report_path: public_item_path(
                    run_id,
                    &format!("item-{item_index}-autopilot-report.json"),
                ),
                github_report_path: public_item_path(
                    run_id,
                    &format!("item-{item_index}-github-report.json"),
                ),
                autopilot_success: None,
                github_success: true,
                review_loop,
                pr_intake: pr_intake_report_for_item(item),
                independent_audit_lane: None,
                next_action: if planned_only {
                    "review the plan; this permission mode does not launch work".to_string()
                } else {
                    "review the dry-run plan; no work was launched".to_string()
                },
            },
            refusal: None,
        });
    }

    revalidate_inbox_item_source(repo, item)
        .context("inbox source changed immediately before local work started")?;
    let machine_global_retention = context
        .machine_global
        .as_ref()
        .map(|input| input.retention_binding_for_run(&autopilot_run_id));
    let autopilot_result = {
        let _rolling_guard = context
            .rolling_budget_quota
            .map(|quota| {
                crate::budget_ledger::bind_rolling_budget(repo, quota, autopilot_run_id.as_str())
            })
            .transpose()?;
        autopilot::run_autopilot_plan_file_with_retention(
            AutopilotRunOptions {
                repo: repo.to_path_buf(),
                plan_file: plan_path.clone(),
                run_id: autopilot_run_id.clone(),
                codex_bin: context.codex_bin.clone(),
                reviewer_command: None,
                allow_dirty_primary: false,
                allow_live_run_collision: false,
                max_child_dispatches: None,
                budget_overrides: crate::supervise::RunBudgetLimits::default(),
                budget_max_duration_seconds: None,
                cancellation: None,
            },
            machine_global_retention,
        )
    };
    let mut refusal = None;
    let (autopilot_success, autopilot_message) = match autopilot_result {
        Ok(report) => {
            let success = report.success;
            let message = report.next_action.clone();
            refusal = inbox_budget_refusal(&report);
            write_private_artifact_json(writer, &autopilot_report_relative, &report)?;
            (success, Some(message))
        }
        Err(error) => {
            let message = sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text;
            write_private_artifact_json(
                writer,
                &autopilot_report_relative,
                &json!({
                    "status": "failed",
                    "success": false,
                    "error": message
                }),
            )?;
            (
                false,
                Some("autopilot failed before producing a final report".to_string()),
            )
        }
    };

    let github_report = if refusal.is_some() {
        InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "skipped".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some(
                "autopilot budget refusal stopped the downstream GitHub action".to_string(),
            ),
        }
    } else {
        github_action_for_item(
            repo,
            config,
            action_policy,
            permission_mode,
            item,
            autopilot_success,
            autopilot_message,
        )
    };
    write_private_artifact_json(writer, &github_report_relative, &github_report)?;
    let success = autopilot_success && github_report.success;
    Ok(InboxItemRunOutcome {
        report: InboxItemRunReport {
            item_index,
            item_id: item.item_id.clone(),
            kind: item.kind,
            title: item.title.clone(),
            success,
            status: if refusal.is_some() {
                "refused".to_string()
            } else if success {
                "succeeded".to_string()
            } else {
                "failed".to_string()
            },
            plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
            autopilot_run_id: autopilot_run_id.as_str().to_string(),
            autopilot_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-autopilot-report.json"),
            ),
            github_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-github-report.json"),
            ),
            autopilot_success: Some(autopilot_success),
            github_success: github_report.success,
            review_loop,
            pr_intake: pr_intake_report_for_item(item),
            independent_audit_lane: None,
            next_action: if refusal.is_some() {
                "wait for or increase the rolling inbox quota before retrying".to_string()
            } else if success {
                "review the generated autopilot and GitHub reports".to_string()
            } else {
                "inspect the item autopilot and GitHub reports before retrying".to_string()
            },
        },
        refusal,
    })
}

fn run_independent_audit_intake_item(
    writer: &mut ArtifactRunWriter,
    input: InboxItemRunInput<'_>,
    review_loop: Option<review_loop_entry::InboxReviewLoopReport>,
    pr_intake: InboxPrIntakeReport,
    source_fresh: bool,
    before_auditor_launch: Option<
        &mut dyn FnMut(&str, &InboxIndependentAuditorSelectionEvidence) -> Result<()>,
    >,
) -> Result<InboxItemRunOutcome> {
    run_independent_audit_intake_item_with_runner(
        writer,
        input,
        review_loop,
        pr_intake,
        source_fresh,
        None,
        before_auditor_launch,
        verified_independent_audit_runner,
    )
}

struct IndependentAuditRunnerResult {
    raw_output: Option<Vec<u8>>,
    report_sha256: Option<String>,
    exit_code: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    safely_executed: bool,
    publishable: bool,
    succeeded: bool,
    scratch_quiescence_verified: bool,
    error: Option<String>,
}

fn verified_independent_audit_runner(
    command: &ExternalAgentCommand,
) -> IndependentAuditRunnerResult {
    let external_run = run_external_agent(command);
    let raw_output = external_run.output_last_message().map(ToOwned::to_owned);
    IndependentAuditRunnerResult {
        report_sha256: raw_output
            .as_deref()
            .map(crate::artifacts::state_auth::sha256_hex),
        raw_output,
        exit_code: external_run.exit_code,
        duration_ms: external_run.duration_ms,
        timed_out: external_run.timed_out,
        safely_executed: external_run.safely_executed(),
        publishable: external_run.publishable,
        succeeded: external_run.succeeded(),
        scratch_quiescence_verified: external_run.scratch_quiescence_verified(),
        error: external_run.error,
    }
}

fn run_independent_audit_intake_item_with_runner<F>(
    writer: &mut ArtifactRunWriter,
    input: InboxItemRunInput<'_>,
    review_loop: Option<review_loop_entry::InboxReviewLoopReport>,
    pr_intake: InboxPrIntakeReport,
    source_fresh: bool,
    available_models_override: Option<&BTreeSet<String>>,
    before_auditor_launch: Option<
        &mut dyn FnMut(&str, &InboxIndependentAuditorSelectionEvidence) -> Result<()>,
    >,
    mut external_runner: F,
) -> Result<InboxItemRunOutcome>
where
    F: FnMut(&ExternalAgentCommand) -> IndependentAuditRunnerResult,
{
    let context = input.context;
    let item_index = input.item_index;
    let item = input.item;
    let run_id = context.run_id;
    let action_policy = context.action_policy;
    let permission_mode = context.permission_mode;
    let plan_relative = PathBuf::from(format!("item-{item_index}-plan.json"));
    let autopilot_report_relative =
        PathBuf::from(format!("item-{item_index}-autopilot-report.json"));
    let github_report_relative = PathBuf::from(format!("item-{item_index}-github-report.json"));
    let autopilot_run_id = RunId::new(format!("{}-item-{item_index}", run_id.as_str()))?;

    // The task itself is the plan artifact. Sending it through the existing
    // repair/producer executor would violate producer/auditor separation.
    write_private_artifact_json(writer, &plan_relative, &pr_intake)?;

    let planning_only =
        action_policy == InboxActionPolicy::DryRun || !permission_mode.launches_autopilot();
    if planning_only && pr_intake.status == InboxPrIntakeStatus::Ready && source_fresh {
        write_private_artifact_json(
            writer,
            &autopilot_report_relative,
            &json!({
                "status": "skipped",
                "success": true,
                "reason": if action_policy == InboxActionPolicy::DryRun {
                    "dry_run action policy does not launch the independent audit task"
                } else {
                    "permission mode records the independent audit task without launching it"
                }
            }),
        )?;
        let github_report = InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "skipped".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some(
                "independent audit task was recorded without launch; no GitHub action or merge was performed"
                    .to_string(),
            ),
        };
        write_private_artifact_json(writer, &github_report_relative, &github_report)?;
        return Ok(InboxItemRunOutcome {
            report: InboxItemRunReport {
                item_index,
                item_id: item.item_id.clone(),
                kind: item.kind,
                title: item.title.clone(),
                success: true,
                status: if action_policy == InboxActionPolicy::DryRun {
                    "dry_run".to_string()
                } else {
                    "planned".to_string()
                },
                plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
                autopilot_run_id: autopilot_run_id.as_str().to_string(),
                autopilot_report_path: public_item_path(
                    run_id,
                    &format!("item-{item_index}-autopilot-report.json"),
                ),
                github_report_path: public_item_path(
                    run_id,
                    &format!("item-{item_index}-github-report.json"),
                ),
                autopilot_success: None,
                github_success: true,
                review_loop,
                pr_intake: Some(pr_intake),
                independent_audit_lane: None,
                next_action:
                    "launch the recorded task through the independent-audit adapter; no merge was performed"
                        .to_string(),
            },
            refusal: None,
        });
    }

    let head_oid = item
        .source_snapshot
        .head_oid()
        .unwrap_or_default()
        .to_string();
    let mut initial_blockers = Vec::new();
    if !source_fresh {
        initial_blockers.push(
            review_loop_entry::InboxIndependentAuditLaneBlocker::StaleHead {
                expected_head_oid: head_oid.clone(),
            },
        );
    }
    if pr_intake.status == InboxPrIntakeStatus::LaunchBlocked {
        let block = pr_intake
            .launch_block
            .as_ref()
            .context("blocked PR intake omitted its launch-block report")?;
        initial_blockers.push(pr_intake_lane_blocker(block));
    }
    let task = pr_intake.task.as_ref();
    if task.is_none() && initial_blockers.is_empty() {
        initial_blockers.push(
            review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEvidence {
                evidence: vec!["source_bound_audit_task".to_string()],
            },
        );
    }
    if let Some(task) = task {
        initial_blockers.extend(review_loop_entry::independent_audit_task_blockers(
            item, task,
        ));
    }
    if !initial_blockers.is_empty() {
        let lane = review_loop_entry::blocked_independent_audit_lane_result(
            item,
            head_oid,
            initial_blockers,
            None,
            None,
        );
        return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
    }
    let Some(task) = task else {
        bail!("source-bound independent-audit task disappeared after blocker evaluation");
    };
    if item.source_snapshot.provider() == InboxSourceProvider::Github
        && materialize_and_verify_local_independent_audit_candidate(context.repo, item, task)
            .is_err()
    {
        let lane = review_loop_entry::blocked_independent_audit_lane_result(
            item,
            &task.head_oid,
            vec![
                review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEvidence {
                    evidence: vec!["local_exact_pull_request_diff".to_string()],
                },
            ],
            None,
            None,
        );
        return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
    }
    let timeout = Duration::from_secs(context.config.timeout_seconds.unwrap_or(600));
    let program = context
        .codex_bin
        .clone()
        .unwrap_or_else(|| PathBuf::from("codex"));
    let available_models = match available_models_override
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| independent_auditor_available_models(&program, context.repo, timeout))
    {
        Ok(models) => models,
        Err(blocker) => {
            let lane = review_loop_entry::blocked_independent_audit_lane_result(
                item,
                &task.head_oid,
                vec![blocker],
                None,
                None,
            );
            return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
        }
    };
    let decision = match review_loop_entry::select_critical_independent_auditor(&available_models) {
        Ok(decision) => decision,
        Err(error) => {
            let lane = review_loop_entry::blocked_independent_audit_lane_result(
                item,
                &task.head_oid,
                vec![
                    review_loop_entry::InboxIndependentAuditLaneBlocker::SelectorRejected {
                        detail: sanitize_public_text(
                            context.repo,
                            &error.to_string(),
                            GH_DIAGNOSTIC_LIMIT,
                        )
                        .text,
                    },
                ],
                None,
                None,
            );
            return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
        }
    };
    let selection = match review_loop_entry::compact_independent_auditor_selection(&decision) {
        Ok(selection) => selection,
        Err(_) => {
            let lane = review_loop_entry::blocked_independent_audit_lane_result(
                item,
                &task.head_oid,
                vec![
                    review_loop_entry::InboxIndependentAuditLaneBlocker::UnavailableEligibleAuditor {
                        detail: decision.decision_reason,
                    },
                ],
                None,
                None,
            );
            return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
        }
    };
    let auditor_session_id = format!("{}-item-{item_index}-auditor", run_id.as_str());
    let auditor =
        review_loop_entry::independent_auditor_actor(&auditor_session_id, &selection.model);
    if let Some(blocker) = review_loop_entry::producer_auditor_separation_blocker(
        &task.producer_login,
        &auditor,
        &task.head_oid,
    ) {
        let lane = review_loop_entry::blocked_independent_audit_lane_result(
            item,
            &task.head_oid,
            vec![blocker],
            Some(selection),
            None,
        );
        return finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane);
    }

    let prompt = review_loop_entry::independent_auditor_prompt(item, task, &selection)?;
    let prompt_sha256 = crate::artifacts::state_auth::sha256_hex(prompt.as_bytes());
    let prompt_relative = PathBuf::from(format!("item-{item_index}-independent-audit-prompt.txt"));
    writer.write_bytes(
        &prompt_relative,
        prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let incoming =
        writer.create_scratch_dir(format!("item-{item_index}-independent-audit-incoming"))?;
    let output_path = incoming.path().join("auditor-output.json");
    let json_log_path = incoming.path().join("auditor-events.jsonl");
    let mut command = ExternalAgentCommand::codex_read_only_consultant(
        &program,
        context.repo,
        writer.run_dir().join(&prompt_relative),
        &json_log_path,
        &output_path,
        timeout,
    )
    .with_model_selection(
        Some(selection.model.clone()),
        Some(selector_effort_label(selection.effort).to_string()),
    );
    if let Some(machine_global) = &context.machine_global {
        command = command.with_machine_global_retention(
            machine_global.retention_binding_for_run(&autopilot_run_id),
        );
    }
    if let Some(hook) = before_auditor_launch {
        hook(&auditor_session_id, &selection).context(
            "persist authenticated PR intake start immediately before independent-auditor launch",
        )?;
    }
    let runner_result = external_runner(&command);
    let raw_output = runner_result.raw_output.clone();
    let launch = review_loop_entry::InboxIndependentAuditLaunchEvidence {
        adapter: "codex_read_only_consultant".to_string(),
        permission_profile: review_loop_entry::independent_auditor_permission_profile().to_string(),
        auditor_identity: review_loop_entry::independent_auditor_stable_id().to_string(),
        auditor_session_id,
        prompt_sha256,
        report_sha256: runner_result.report_sha256.clone(),
        exit_code: runner_result.exit_code,
        duration_ms: runner_result.duration_ms,
        timed_out: runner_result.timed_out,
        safely_executed: runner_result.safely_executed,
        publishable: runner_result.publishable,
    };
    drop(command);
    if !runner_result.scratch_quiescence_verified {
        bail!(
            "independent-auditor scratch quiescence was not verified; leaving the Inbox run unfinalized"
        );
    }
    writer
        .discard_scratch(&incoming)
        .context("discard independent-auditor invocation scratch")?;

    let lane = if !runner_result.succeeded {
        let detail = runner_result
            .error
            .as_deref()
            .filter(|message| !message.is_empty())
            .unwrap_or(if runner_result.timed_out {
                "independent auditor timed out"
            } else {
                "independent auditor did not complete in the verified read-only boundary"
            });
        review_loop_entry::blocked_independent_audit_lane_result(
            item,
            &task.head_oid,
            vec![
                review_loop_entry::InboxIndependentAuditLaneBlocker::LaunchFailed {
                    detail: sanitize_public_text(context.repo, detail, GH_DIAGNOSTIC_LIMIT).text,
                },
            ],
            Some(selection),
            Some(launch),
        )
    } else if revalidate_inbox_item_source(context.repo, item).is_err() {
        review_loop_entry::blocked_independent_audit_lane_result(
            item,
            &task.head_oid,
            vec![
                review_loop_entry::InboxIndependentAuditLaneBlocker::StaleHead {
                    expected_head_oid: task.head_oid.clone(),
                },
            ],
            Some(selection),
            Some(launch),
        )
    } else {
        match raw_output {
            None => review_loop_entry::blocked_independent_audit_lane_result(
                item,
                &task.head_oid,
                vec![
                    review_loop_entry::InboxIndependentAuditLaneBlocker::MissingAuditEvidence {
                        evidence: vec!["auditor_output".to_string()],
                    },
                ],
                Some(selection),
                Some(launch),
            ),
            Some(raw_output) => {
                let report_sha256 = crate::artifacts::state_auth::sha256_hex(&raw_output);
                if launch.report_sha256.as_deref() != Some(report_sha256.as_str()) {
                    review_loop_entry::blocked_independent_audit_lane_result(
                        item,
                        &task.head_oid,
                        vec![
                            review_loop_entry::InboxIndependentAuditLaneBlocker::MissingAuditEvidence {
                                evidence: vec!["auditor_output_digest".to_string()],
                            },
                        ],
                        Some(selection),
                        Some(launch),
                    )
                } else {
                    let parsed = serde_json::from_slice::<
                        review_loop_entry::InboxIndependentAuditorOutput,
                    >(&raw_output);
                    match parsed {
                        Err(_) => review_loop_entry::blocked_independent_audit_lane_result(
                            item,
                            &task.head_oid,
                            vec![
                                review_loop_entry::InboxIndependentAuditLaneBlocker::MissingAuditEvidence {
                                    evidence: vec!["strict_auditor_output_json".to_string()],
                                },
                            ],
                            Some(selection),
                            Some(launch),
                        ),
                        Ok(output) => match review_loop_entry::validate_independent_auditor_output(
                            output, item, task, auditor,
                        ) {
                            Ok(auditor_evidence) => complete_authenticated_independent_audit_merge(
                                context,
                                item,
                                task,
                                selection,
                                launch,
                                auditor_evidence,
                            ),
                            Err(blocker) => {
                                review_loop_entry::blocked_independent_audit_lane_result(
                                    item,
                                    &task.head_oid,
                                    vec![blocker],
                                    Some(selection),
                                    Some(launch),
                                )
                            }
                        },
                    }
                }
            }
        }
    };
    finish_independent_audit_lane_item(writer, input, review_loop, pr_intake, lane)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedGithubPullRequestObjectRequest {
    remote_url: String,
    base_remote_ref: String,
    head_remote_ref: String,
    expected_base_oid: Oid,
    expected_head_oid: Oid,
}

fn materialize_and_verify_local_independent_audit_candidate(
    repo_path: &Path,
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
) -> Result<()> {
    materialize_and_verify_local_independent_audit_candidate_with(
        repo_path,
        item,
        task,
        materialize_trusted_github_pull_request_objects,
        revalidate_inbox_item_source,
    )
}

fn materialize_and_verify_local_independent_audit_candidate_with<M, R>(
    repo_path: &Path,
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
    mut materialize: M,
    mut revalidate: R,
) -> Result<()>
where
    M: FnMut(&Path, &TrustedGithubPullRequestObjectRequest) -> Result<()>,
    R: FnMut(&Path, &InboxItem) -> Result<()>,
{
    let request = trusted_github_pull_request_object_request(repo_path, item, task)?;
    let repository = crate::git_repository::open(repo_path)
        .context("open repository before exact pull-request object materialization")?;
    let has_exact_commits = repository.find_commit(request.expected_base_oid).is_ok()
        && repository.find_commit(request.expected_head_oid).is_ok();
    drop(repository);
    if !has_exact_commits {
        materialize(repo_path, &request)
            .context("bounded exact pull-request object transport failed")?;
    }

    // The transport is intentionally followed by a new provider observation.
    // No diff is inspected before this point, so a PR/base ref that moved while
    // objects were in flight cannot turn stale objects into audit evidence.
    revalidate(repo_path, item)
        .context("GitHub source changed after exact pull-request object materialization")?;
    verify_local_independent_audit_candidate(repo_path, task)
}

fn trusted_github_pull_request_object_request(
    repo_path: &Path,
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
) -> Result<TrustedGithubPullRequestObjectRequest> {
    item.source_snapshot.validate()?;
    if item.kind != InboxItemKind::PullRequest
        || item.source_snapshot.kind() != InboxItemKind::PullRequest
        || item.source_snapshot.provider() != InboxSourceProvider::Github
    {
        bail!("exact pull-request object materialization requires a GitHub PR snapshot");
    }
    let pull_request = item
        .pull_request
        .as_ref()
        .context("GitHub PR snapshot omitted its pull-request candidate")?;
    if pull_request.number != item.source_snapshot.number()
        || task.source_snapshot_digest != item.source_snapshot.digest()
        || task.source_updated_at != item.source_snapshot.updated_at()
        || task.head_oid != item.source_snapshot.head_oid().unwrap_or_default()
        || task.base_oid != item.source_snapshot.base_oid().unwrap_or_default()
        || task.changed_files != pull_request.changed_files
        || task.checks != pull_request.checks
        || task.head_repository != pull_request.head_repository
    {
        bail!("pull-request materialization input drifted from its source-bound audit task");
    }
    if pull_request.is_draft
        || task.is_draft
        || pull_request.source_trust != GithubPrSourceTrust::TrustedTargetRepository
        || task.source_trust != GithubPrSourceTrust::TrustedTargetRepository
    {
        bail!(
            "pull-request object materialization requires a trusted non-draft same-repository head"
        );
    }
    let target_owner_name = item
        .source_snapshot
        .repository_selector()
        .split_once('/')
        .map(|(_, owner_name)| owner_name)
        .context("GitHub source selector omitted its host")?;
    if target_owner_name.split('/').count() != 2
        || pull_request
            .head_repository
            .as_deref()
            .is_none_or(|repository| !repository.eq_ignore_ascii_case(target_owner_name))
    {
        bail!("pull-request object materialization refuses fork or unbound head repositories");
    }
    let base_ref = pull_request
        .base_ref
        .as_deref()
        .context("GitHub PR snapshot omitted its base branch")?;
    validate_github_materialization_branch(base_ref)?;
    let expected_head_oid =
        Oid::from_str(&task.head_oid).context("parse source-bound pull-request head OID")?;
    let expected_base_oid =
        Oid::from_str(&task.base_oid).context("parse source-bound pull-request base OID")?;
    if expected_head_oid.to_string() != task.head_oid
        || expected_base_oid.to_string() != task.base_oid
    {
        bail!("source-bound pull-request OIDs were not canonical SHA-1 identities");
    }

    let repository = crate::git_repository::open(repo_path)
        .context("open repository for trusted pull-request object transport")?;
    let common = SafeRoot::open_existing(repository.commondir())
        .context("bind repository identity for trusted pull-request object transport")?;
    if publication::external_source_repository_identity(
        common.identity().device,
        common.identity().file,
    ) != item.source_snapshot.repository_identity()
    {
        bail!("pull-request object materialization repository identity changed");
    }
    let origin = repository
        .find_remote("origin")
        .context("trusted pull-request object transport requires origin")?;
    let origin_url = origin
        .url()
        .context("trusted pull-request object transport origin was not UTF-8")?;
    let (origin_host, origin_selector) =
        publication::canonical_github_source_repository(origin_url)?;
    if origin_host != item.source_snapshot.repository_host()
        || origin_selector != item.source_snapshot.repository_selector()
    {
        bail!("pull-request object materialization origin changed from its source binding");
    }
    common.verify()?;

    Ok(TrustedGithubPullRequestObjectRequest {
        // Reconstruct the transport URL from validated canonical snapshot
        // fields. The command never consumes a caller-provided URL, remote
        // helper, or mutable fetch refspec.
        remote_url: format!(
            "https://{}/{}.git",
            item.source_snapshot.repository_host(),
            target_owner_name
        ),
        base_remote_ref: format!("refs/heads/{base_ref}"),
        head_remote_ref: format!("refs/pull/{}/head", item.source_snapshot.number()),
        expected_base_oid,
        expected_head_oid,
    })
}

fn validate_github_materialization_branch(branch: &str) -> Result<()> {
    if branch.is_empty()
        || branch.len() > MAX_GITHUB_REF_BYTES
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.starts_with('.')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("@{")
        || branch.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
        || branch.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || component.ends_with('.')
                || component.ends_with(".lock")
        })
    {
        bail!("GitHub PR base branch is not a strict transport-safe ref name");
    }
    Ok(())
}

fn materialize_trusted_github_pull_request_objects(
    repo_path: &Path,
    request: &TrustedGithubPullRequestObjectRequest,
) -> Result<()> {
    let target = crate::git_repository::open(repo_path)
        .context("open target repository for exact pull-request object materialization")?;
    let target_common = SafeRoot::open_existing(target.commondir())
        .context("bind target object database during pull-request materialization")?;
    let mut runtime = crate::merge::PrivateRuntimeDirectory::create(
        repo_path,
        crate::merge::PrivateRuntimeKind::PublicationGit,
    )?;
    let directory = runtime.path().to_path_buf();
    let execution = (|| -> Result<()> {
        initialize_pull_request_fetch_repository(&directory, request)?;
        let config_path = directory.join("config");
        let global_config = directory.join("disabled-global-config");
        let config_before =
            fs::read(&config_path).context("read sealed pull-request fetch configuration")?;
        let global_before =
            fs::read(&global_config).context("read sealed pull-request global configuration")?;
        let mut environment = crate::merge::minimal_network_environment()?;
        environment.insert(
            "GIT_CONFIG_GLOBAL".to_string(),
            global_config
                .to_str()
                .context("pull-request fetch global config path was not UTF-8")?
                .to_string(),
        );
        let primary = fs::canonicalize(
            target
                .commondir()
                .parent()
                .context("target Git common directory omitted its repository root")?,
        )
        .context("resolve primary worktree for pull-request fetch isolation")?;
        let source_worktree = fs::canonicalize(repo_path)
            .context("resolve source worktree for pull-request fetch isolation")?;
        let profile = TrustedFixedNetworkProfile::read_write(&directory)
            .with_resource_limits(ProcessResourceLimits {
                memory_max_bytes: 1024 * 1024 * 1024,
                tasks_max: 64,
                cpu_quota_percent: 400,
                open_files_max: 1024,
                file_size_max_bytes: PR_OBJECT_FETCH_MAX_BYTES,
            })
            .with_visible_read_only_file(&config_path)
            .with_visible_read_only_file(&global_config)
            .with_hidden_root(primary)
            .with_hidden_root(source_worktree);
        let base_refspec = format!("+{}:refs/maco-inbox/base", request.base_remote_ref);
        let head_refspec = format!("+{}:refs/maco-inbox/head", request.head_remote_ref);
        let args = vec![
            "--git-dir".into(),
            directory.as_os_str().to_os_string(),
            "-c".into(),
            "core.fsmonitor=false".into(),
            "-c".into(),
            "core.untrackedCache=false".into(),
            "-c".into(),
            "protocol.allow=never".into(),
            "-c".into(),
            "protocol.https.allow=always".into(),
            "fetch".into(),
            "--force".into(),
            "--no-tags".into(),
            "--no-recurse-submodules".into(),
            "--no-write-fetch-head".into(),
            "maco-inbox".into(),
            base_refspec.into(),
            head_refspec.into(),
        ];
        let output = crate::merge::run_required_network_direct(
            "fetch exact trusted pull-request objects",
            crate::merge::resolve_trusted_executable("git")?,
            args,
            &directory,
            environment,
            StdinMode::Null,
            PR_OBJECT_FETCH_TIMEOUT,
            PR_OBJECT_FETCH_CAPTURE_LIMIT,
            0,
            profile,
        )?;
        if !output.success {
            bail!(
                "exact pull-request object fetch failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        runtime
            .verify_identity()
            .context("pull-request fetch runtime changed during transport")?;
        if fs::read(&config_path)? != config_before || fs::read(&global_config)? != global_before {
            bail!("pull-request fetch configuration changed during transport");
        }
        let fetched = crate::git_repository::open_bare(&directory)
            .context("open bounded pull-request fetch repository")?;
        validate_materialized_pull_request_refs(&fetched, request)?;
        copy_pull_request_object_closure(
            &fetched,
            &target,
            request.expected_base_oid,
            request.expected_head_oid,
        )?;
        target_common.verify()
    })();
    let cleanup = runtime.close();
    match (execution, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.context("clean up pull-request fetch runtime")),
        (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
            "{error:#}; pull-request fetch runtime cleanup also failed: {cleanup:#}"
        )),
    }
}

fn initialize_pull_request_fetch_repository(
    directory: &Path,
    request: &TrustedGithubPullRequestObjectRequest,
) -> Result<()> {
    crate::merge::create_private_directory(&directory.join("objects"))?;
    crate::merge::create_private_directory(&directory.join("objects/info"))?;
    crate::merge::create_private_directory(&directory.join("objects/pack"))?;
    crate::merge::create_private_directory(&directory.join("refs"))?;
    crate::merge::create_private_directory(&directory.join("refs/heads"))?;
    crate::merge::create_private_directory(&directory.join("refs/tags"))?;
    crate::merge::create_private_directory(&directory.join("disabled-hooks"))?;
    crate::merge::write_private_file(&directory.join("HEAD"), b"ref: refs/heads/maco-inbox\n")?;
    let config_path = directory.join("config");
    crate::merge::write_private_file(&config_path, b"")?;
    crate::merge::write_private_file(&directory.join("disabled-global-config"), b"")?;
    let mut config = git2::Config::open(&config_path)
        .context("open private pull-request fetch configuration")?;
    config.set_i32("core.repositoryformatversion", 0)?;
    config.set_bool("core.bare", true)?;
    config.set_bool("core.fsmonitor", false)?;
    config.set_bool("core.untrackedcache", false)?;
    config.set_str(
        "core.hookspath",
        directory
            .join("disabled-hooks")
            .to_str()
            .context("pull-request disabled-hooks path was not UTF-8")?,
    )?;
    config.set_str("protocol.allow", "never")?;
    config.set_str("protocol.https.allow", "always")?;
    config.set_str("protocol.ext.allow", "never")?;
    config.set_str("protocol.file.allow", "never")?;
    config.set_str("http.followredirects", "false")?;
    config.set_bool("http.sslverify", true)?;
    config.set_str("http.proxy", "")?;
    config.set_str("credential.helper", "")?;
    config.set_str("core.askpass", "")?;
    config.set_bool("fetch.fsckobjects", true)?;
    config.set_bool("transfer.fsckobjects", true)?;
    config.set_i32("gc.auto", 0)?;
    config.set_bool("maintenance.auto", false)?;
    config.set_bool("submodule.recurse", false)?;
    config.set_str("remote.maco-inbox.url", &request.remote_url)?;
    config.set_str("remote.maco-inbox.tagopt", "--no-tags")?;
    Ok(())
}

fn validate_materialized_pull_request_refs(
    repository: &git2::Repository,
    request: &TrustedGithubPullRequestObjectRequest,
) -> Result<()> {
    let expected = [
        ("refs/maco-inbox/base", request.expected_base_oid),
        ("refs/maco-inbox/head", request.expected_head_oid),
    ];
    let mut observed_names = BTreeSet::new();
    for reference in repository.references()? {
        let reference = reference.context("inspect pull-request fetch reference")?;
        let name = reference
            .name()
            .context("pull-request fetch produced a non-UTF-8 reference")?;
        observed_names.insert(name.to_string());
    }
    if observed_names
        != expected
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect::<BTreeSet<_>>()
    {
        bail!("pull-request fetch produced refs outside its exact bounded destinations");
    }
    for (name, expected_oid) in expected {
        let reference = repository.find_reference(name)?;
        let target = reference
            .target()
            .context("pull-request fetch produced a symbolic destination ref")?;
        if target != expected_oid {
            bail!("pull-request fetch ref drifted from its source-snapshot OID");
        }
        repository
            .find_commit(target)
            .context("pull-request fetch destination was not an exact commit")?;
    }
    Ok(())
}

fn copy_pull_request_object_closure(
    source: &git2::Repository,
    target: &git2::Repository,
    base_oid: Oid,
    head_oid: Oid,
) -> Result<()> {
    let source_odb = source
        .odb()
        .context("open fetched pull-request object database")?;
    let target_odb = target
        .odb()
        .context("open target pull-request object database")?;
    let mut pending = vec![
        (base_oid, ObjectType::Commit),
        (head_oid, ObjectType::Commit),
    ];
    let mut objects = BTreeMap::<Oid, ObjectType>::new();
    let mut total_bytes = 0_u64;
    let mut steps = 0usize;
    while let Some((oid, expected_kind)) = pending.pop() {
        steps = steps
            .checked_add(1)
            .context("pull-request object graph step count overflow")?;
        if steps > PR_OBJECT_FETCH_MAX_GRAPH_STEPS {
            bail!("pull-request object graph exceeded its traversal bound");
        }
        if let Some(prior) = objects.get(&oid) {
            if *prior != expected_kind {
                bail!("pull-request object graph reused an OID with contradictory kinds");
            }
            continue;
        }
        if objects.len() >= PR_OBJECT_FETCH_MAX_OBJECTS {
            bail!("pull-request object graph exceeded its object-count bound");
        }
        let (size, kind) = source_odb
            .read_header(oid)
            .with_context(|| format!("fetched pull-request closure omitted object {oid}"))?;
        if kind != expected_kind {
            bail!("fetched pull-request closure contained an unexpected object kind");
        }
        total_bytes = total_bytes
            .checked_add(u64::try_from(size).context("pull-request object size did not fit")?)
            .context("pull-request object byte count overflow")?;
        if total_bytes > PR_OBJECT_FETCH_MAX_BYTES {
            bail!("pull-request object graph exceeded its aggregate byte bound");
        }
        objects.insert(oid, expected_kind);
        match expected_kind {
            ObjectType::Commit => {
                let commit = source
                    .find_commit(oid)
                    .with_context(|| format!("parse fetched pull-request commit {oid}"))?;
                pending.push((commit.tree_id(), ObjectType::Tree));
                pending.extend(
                    commit
                        .parent_ids()
                        .map(|parent| (parent, ObjectType::Commit)),
                );
            }
            ObjectType::Tree => {
                let tree = source
                    .find_tree(oid)
                    .with_context(|| format!("parse fetched pull-request tree {oid}"))?;
                for entry in tree.iter() {
                    match entry.kind() {
                        Some(ObjectType::Tree) => pending.push((entry.id(), ObjectType::Tree)),
                        Some(ObjectType::Blob) => pending.push((entry.id(), ObjectType::Blob)),
                        Some(ObjectType::Commit) if entry.filemode() == 0o160000 => {
                            // A gitlink names a commit in another repository. It is
                            // metadata only and is never fetched or traversed here.
                        }
                        _ => bail!("pull-request tree contained an unsupported entry kind"),
                    }
                }
            }
            ObjectType::Blob => {}
            _ => bail!("pull-request object graph contained an unsupported object kind"),
        }
    }
    for (oid, kind) in objects {
        let object = source_odb
            .read(oid)
            .with_context(|| format!("read bounded fetched pull-request object {oid}"))?;
        if object.kind() != kind {
            bail!("fetched pull-request object changed kind during materialization");
        }
        let written = target_odb
            .write(kind, object.data())
            .with_context(|| format!("materialize exact pull-request object {oid}"))?;
        if written != oid {
            bail!("pull-request object materialization changed an object identity");
        }
    }
    target
        .find_commit(base_oid)
        .context("materialized repository omitted exact pull-request base")?;
    target
        .find_commit(head_oid)
        .context("materialized repository omitted exact pull-request head")?;
    Ok(())
}

fn verify_local_independent_audit_candidate(
    repo_path: &Path,
    task: &InboxIndependentAuditMergeLaneTask,
) -> Result<()> {
    let repository = crate::git_repository::open(repo_path)
        .context("open repository for exact local pull-request audit")?;
    let head_oid = Oid::from_str(&task.head_oid).context("parse local pull-request head OID")?;
    let base_oid = Oid::from_str(&task.base_oid).context("parse local pull-request base OID")?;
    if head_oid.to_string() != task.head_oid || base_oid.to_string() != task.base_oid {
        bail!("local pull-request OIDs were not canonical SHA-1 object identities");
    }
    let head = repository
        .find_commit(head_oid)
        .context("local repository omitted the exact pull-request head commit")?;
    let base = repository
        .find_commit(base_oid)
        .context("local repository omitted the exact pull-request base commit")?;
    let merge_base_oid = repository
        .merge_base(base.id(), head.id())
        .context("local pull-request commits had no unique merge base")?;
    let merge_base = repository
        .find_commit(merge_base_oid)
        .context("local repository omitted the pull-request merge-base commit")?;
    let merge_base_tree = merge_base
        .tree()
        .context("load pull-request merge-base tree")?;
    let head_tree = head.tree().context("load pull-request head tree")?;
    let mut options = DiffOptions::new();
    options
        .include_typechange(true)
        .recurse_untracked_dirs(false);
    let mut diff = repository
        .diff_tree_to_tree(Some(&merge_base_tree), Some(&head_tree), Some(&mut options))
        .context("compute exact local pull-request diff")?;
    let mut find = DiffFindOptions::new();
    find.renames(true);
    diff.find_similar(Some(&mut find))
        .context("resolve exact local pull-request renames")?;
    let mut observed = BTreeSet::new();
    for delta in diff.deltas() {
        let path = if delta.status() == Delta::Deleted {
            delta.old_file().path()
        } else {
            delta.new_file().path().or_else(|| delta.old_file().path())
        }
        .context("local pull-request diff omitted a changed path")?;
        observed.insert(
            normalize_repo_relative_path(path)
                .context("local pull-request diff contained an invalid changed path")?,
        );
    }
    let expected = task.changed_files.iter().cloned().collect::<BTreeSet<_>>();
    if expected.is_empty() || expected.len() != task.changed_files.len() || observed != expected {
        bail!("local pull-request diff paths did not match provider-bound audit paths");
    }
    Ok(())
}

struct TrustedInboxPullRequestMergeGroundTruth {
    snapshot: PullRequestReviewSnapshot,
    producer: ProducerFingerprint,
    producer_login: String,
    changed_paths: Vec<PathBuf>,
    merges_cleanly: bool,
    is_draft: bool,
    is_open: bool,
    same_repository_head: bool,
}

fn complete_authenticated_independent_audit_merge(
    context: &InboxItemRunContext<'_>,
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
    selection: review_loop_entry::InboxIndependentAuditorSelectionEvidence,
    launch: review_loop_entry::InboxIndependentAuditLaunchEvidence,
    auditor_evidence: PullRequestAuditorEvidence,
) -> review_loop_entry::InboxIndependentAuditLaneResult {
    if context.action_policy == InboxActionPolicy::DryRun
        || (context.action_policy == InboxActionPolicy::Github
            && context.permission_mode != InboxPermissionMode::GithubFull)
    {
        return review_loop_entry::blocked_authenticated_merge_lane_result(
            item,
            selection,
            launch,
            auditor_evidence,
            review_loop_entry::InboxIndependentAuditLaneBlocker::MergeModeNotAuthorized {
                action_policy: format!("{:?}", context.action_policy).to_ascii_lowercase(),
                permission_mode: format!("{:?}", context.permission_mode).to_ascii_lowercase(),
            },
        );
    }
    #[cfg(not(test))]
    if context.action_policy == InboxActionPolicy::Fake {
        return review_loop_entry::blocked_authenticated_merge_lane_result(
            item,
            selection,
            launch,
            auditor_evidence,
            review_loop_entry::InboxIndependentAuditLaneBlocker::MergeModeNotAuthorized {
                action_policy: "fake".to_string(),
                permission_mode: format!("{:?}", context.permission_mode).to_ascii_lowercase(),
            },
        );
    }

    let ground_truth = match context.action_policy {
        InboxActionPolicy::DryRun => unreachable!("dry run returned before ground-truth access"),
        InboxActionPolicy::Fake => {
            #[cfg(test)]
            {
                fake_pull_request_merge_ground_truth(item, task, &auditor_evidence)
            }
            #[cfg(not(test))]
            {
                unreachable!("production fake merge mode returned before ground-truth access")
            }
        }
        InboxActionPolicy::Github => publication::observe_github_pull_request_merge_ground_truth(
            context.repo,
            item.source_snapshot.repository_selector(),
            item.source_snapshot.number(),
        )
        .map(|truth| TrustedInboxPullRequestMergeGroundTruth {
            snapshot: truth.snapshot,
            producer: truth.producer,
            producer_login: truth.producer_login,
            changed_paths: truth.changed_paths,
            merges_cleanly: truth.merges_cleanly,
            is_draft: truth.is_draft,
            is_open: truth.is_open,
            same_repository_head: truth.same_repository_head,
        }),
    };
    let ground_truth = match ground_truth {
        Ok(ground_truth) => ground_truth,
        Err(error) => {
            return review_loop_entry::blocked_authenticated_merge_lane_result(
                item,
                selection,
                launch,
                auditor_evidence,
                review_loop_entry::InboxIndependentAuditLaneBlocker::MergeGroundTruthUnavailable {
                    detail: sanitize_public_text(
                        context.repo,
                        &format!("{error:#}"),
                        GH_DIAGNOSTIC_LIMIT,
                    )
                    .text,
                },
            );
        }
    };
    let (candidate, evidence) = match authenticated_merge_evidence_from_ground_truth(
        task,
        &auditor_evidence,
        &ground_truth,
    ) {
        Ok(value) => value,
        Err(error) => {
            return review_loop_entry::blocked_authenticated_merge_lane_result(
                item,
                selection,
                launch,
                auditor_evidence,
                review_loop_entry::InboxIndependentAuditLaneBlocker::MergeGroundTruthMismatch {
                    field: sanitize_public_text(
                        context.repo,
                        &error.to_string(),
                        GH_DIAGNOSTIC_LIMIT,
                    )
                    .text,
                },
            );
        }
    };

    let merge = match context.action_policy {
        InboxActionPolicy::DryRun => unreachable!("dry run returned before merge execution"),
        InboxActionPolicy::Fake => {
            #[cfg(test)]
            {
                let mut transport = FakeForgeTransport::new();
                transport
                    .register_pull_request_merge_observation(
                        &candidate,
                        ground_truth.snapshot.clone(),
                    )
                    .and_then(|()| {
                        publication::execute_authenticated_pull_request_merge(
                            context.repo,
                            &candidate,
                            Some(&evidence),
                            &transport,
                        )
                    })
            }
            #[cfg(not(test))]
            {
                unreachable!("production fake merge mode returned before merge execution")
            }
        }
        InboxActionPolicy::Github => publication::execute_authenticated_github_pull_request_merge(
            context.repo,
            item.source_snapshot.repository_selector(),
            &candidate,
            Some(&evidence),
        ),
    };
    match merge {
        Ok(AuthenticatedPullRequestMergeOutcome::Merged { receipt, .. }) => {
            review_loop_entry::accepted_independent_audit_lane_result(
                item,
                selection,
                launch,
                auditor_evidence,
                inbox_merge_receipt(receipt.as_ref()),
            )
        }
        Ok(AuthenticatedPullRequestMergeOutcome::NotMerged { blockers, .. }) => {
            review_loop_entry::blocked_authenticated_merge_lane_result(
                item,
                selection,
                launch,
                auditor_evidence,
                review_loop_entry::InboxIndependentAuditLaneBlocker::AuthenticatedMergeBlocked {
                    blockers,
                },
            )
        }
        Err(error) => review_loop_entry::blocked_authenticated_merge_lane_result(
            item,
            selection,
            launch,
            auditor_evidence,
            review_loop_entry::InboxIndependentAuditLaneBlocker::AuthenticatedMergeFailed {
                detail: sanitize_public_text(
                    context.repo,
                    &format!("{error:#}"),
                    GH_DIAGNOSTIC_LIMIT,
                )
                .text,
            },
        ),
    }
}

#[cfg(test)]
fn fake_pull_request_merge_ground_truth(
    item: &InboxItem,
    task: &InboxIndependentAuditMergeLaneTask,
    auditor_evidence: &PullRequestAuditorEvidence,
) -> Result<TrustedInboxPullRequestMergeGroundTruth> {
    let synthesized = review_loop_entry::synthesize_inbox_review_observation(item)?;
    let provider = synthesized.item.repository().provider_id();
    let auditor_actor = ForgeActor::new(
        provider,
        ProviderObjectId::new(
            provider,
            ProviderObjectKind::Actor,
            auditor_evidence.auditor.agent.stable_id.clone(),
        )?,
        auditor_evidence
            .auditor
            .agent
            .stable_id
            .to_ascii_lowercase(),
        ReportedActorKind::Human,
    )?;
    let approval = ForgeReview::new(
        ProviderObjectId::new(
            provider,
            ProviderObjectKind::Review,
            format!(
                "review:{}:independent-auditor",
                item.source_snapshot.number()
            ),
        )?,
        auditor_actor,
        ForgeReviewState::Approved,
        "authenticated independent audit acceptance",
        synthesized.observed_at.clone(),
        &task.head_oid,
    )?;
    let snapshot = PullRequestReviewSnapshot::new(
        synthesized.item.clone(),
        synthesized.observed_at,
        vec![approval],
        Vec::new(),
        synthesized.snapshot.checks().to_vec(),
    )?;
    let producer_id = format!("actor:{}", task.producer_login.to_ascii_lowercase());
    Ok(TrustedInboxPullRequestMergeGroundTruth {
        snapshot,
        producer: ProducerFingerprint {
            actor: MergeActor {
                agent: AgentIdentity {
                    stable_id: producer_id.clone(),
                },
                session: SessionId {
                    id: format!("fake-pr-head:{}", task.head_oid),
                },
                model_label: "fake-pr-producer".to_string(),
            },
            commit_authors: vec![producer_id.clone()],
            commit_committers: vec![producer_id],
        },
        producer_login: task.producer_login.clone(),
        changed_paths: task.changed_files.clone(),
        merges_cleanly: true,
        is_draft: task.is_draft,
        is_open: true,
        same_repository_head: task.source_trust == GithubPrSourceTrust::TrustedTargetRepository,
    })
}

fn authenticated_merge_evidence_from_ground_truth(
    task: &InboxIndependentAuditMergeLaneTask,
    local_auditor: &PullRequestAuditorEvidence,
    truth: &TrustedInboxPullRequestMergeGroundTruth,
) -> Result<(ForgeItem, AuthenticatedPullRequestMergeEvidence)> {
    let candidate = truth.snapshot.item();
    if candidate.head_oid() != Some(task.head_oid.as_str()) {
        bail!("head_oid");
    }
    if candidate.base_oid() != Some(task.base_oid.as_str()) {
        bail!("base_oid");
    }
    if local_auditor.head_oid != task.head_oid {
        bail!("auditor_head_oid");
    }
    if truth.is_draft {
        bail!("draft_pull_request");
    }
    if !truth.is_open {
        bail!("open_pull_request");
    }
    if !truth.same_repository_head {
        bail!("trusted_same_repository_head");
    }
    if !truth
        .producer_login
        .eq_ignore_ascii_case(&task.producer_login)
    {
        bail!("producer_identity");
    }
    let mut task_paths = task.changed_files.clone();
    task_paths.sort();
    if task_paths != truth.changed_paths {
        bail!("changed_paths");
    }
    if !truth.merges_cleanly {
        bail!("merge_simulation");
    }

    let mut required_checks = task
        .checks
        .iter()
        .map(|check| check.name.trim().to_string())
        .collect::<Vec<_>>();
    required_checks.sort();
    if required_checks.is_empty()
        || required_checks.iter().any(|check| check.is_empty())
        || required_checks.windows(2).any(|pair| pair[0] == pair[1])
    {
        bail!("required_checks");
    }
    let mut observed_check_names = truth
        .snapshot
        .checks()
        .iter()
        .map(|check| check.name().to_string())
        .collect::<Vec<_>>();
    observed_check_names.sort();
    if observed_check_names != required_checks {
        bail!("required_check_set");
    }
    if truth.snapshot.checks().iter().any(|check| {
        check.status() != ForgeCheckStatus::Completed
            || check.conclusion() != Some(ForgeCheckConclusion::Success)
    }) {
        bail!("incomplete_or_unsuccessful_check");
    }
    for required in &required_checks {
        let matches = truth
            .snapshot
            .checks()
            .iter()
            .filter(|check| check.name() == required)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!("required_check:{required}");
        }
        let check = matches[0];
        if check.status() != ForgeCheckStatus::Completed
            || check.conclusion() != Some(ForgeCheckConclusion::Success)
        {
            bail!("required_check_not_successful:{required}");
        }
    }

    let mut approvals = truth
        .snapshot
        .reviews()
        .iter()
        .filter(|review| review.state() == ForgeReviewState::Approved)
        .filter(|review| {
            let actor = review.author().provider_actor_id().stable_id();
            actor != truth.producer.actor.agent.stable_id
                && !truth.producer.commit_authors.iter().any(|id| id == actor)
                && !truth
                    .producer
                    .commit_committers
                    .iter()
                    .any(|id| id == actor)
        })
        .collect::<Vec<_>>();
    approvals.sort_by(|left, right| {
        left.submitted_at().cmp(right.submitted_at()).then_with(|| {
            left.provider_review_id()
                .stable_id()
                .cmp(right.provider_review_id().stable_id())
        })
    });
    let approval = approvals.pop().context("independent_approved_review")?;
    let auditor = local_auditor.auditor.clone();
    if !assess_independence(&truth.producer, &auditor).independent {
        bail!("producer_auditor_separation");
    }
    let provider_auditor = PullRequestAuditorEvidence {
        head_oid: task.head_oid.clone(),
        snapshot_observed_at: truth.snapshot.observed_at().clone(),
        auditor,
        lenses: local_auditor.lenses.clone(),
    };
    let evidence = AuthenticatedPullRequestMergeEvidence::from_authenticated_acceptance(
        candidate.clone(),
        approval.provider_review_id().clone(),
        approval.author().clone(),
        required_checks,
        PullRequestProducerEvidence {
            head_oid: task.head_oid.clone(),
            producer: truth.producer.clone(),
        },
        provider_auditor,
        PullRequestMergeSimulationEvidence {
            head_oid: task.head_oid.clone(),
            base_oid: task.base_oid.clone(),
            snapshot_observed_at: truth.snapshot.observed_at().clone(),
            merges_cleanly: true,
        },
        CompletionMode::MergeCommit,
        PullRequestChangedPathsEvidence {
            head_oid: task.head_oid.clone(),
            paths: truth.changed_paths.clone(),
        },
    )?;
    Ok((candidate.clone(), evidence))
}

fn inbox_merge_receipt(
    receipt: &PullRequestMergeReceipt,
) -> review_loop_entry::InboxAuthenticatedPullRequestMergeReceipt {
    review_loop_entry::InboxAuthenticatedPullRequestMergeReceipt {
        provider_merge_id: receipt.provider_merge_id().stable_id().to_string(),
        merged_oid: receipt.merged_oid().to_string(),
        url: receipt.url().to_string(),
        merged_at: receipt.merged_at().as_str().to_string(),
    }
}

fn pr_intake_lane_blocker(
    block: &InboxPrLaunchBlockReport,
) -> review_loop_entry::InboxIndependentAuditLaneBlocker {
    match block.reason.as_str() {
        "draft_pull_request" => {
            review_loop_entry::InboxIndependentAuditLaneBlocker::DraftPullRequest
        }
        "fork_source" => review_loop_entry::InboxIndependentAuditLaneBlocker::ForkSource,
        "untrusted_source" => review_loop_entry::InboxIndependentAuditLaneBlocker::UntrustedSource,
        "missing_eligibility" => {
            review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEligibility {
                evidence: block.missing_evidence.clone(),
            }
        }
        _ => review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEvidence {
            evidence: block.missing_evidence.clone(),
        },
    }
}

fn independent_auditor_available_models(
    program: &Path,
    repo: &Path,
    timeout: Duration,
) -> std::result::Result<BTreeSet<String>, review_loop_entry::InboxIndependentAuditLaneBlocker> {
    let priors = crate::selection::built_in_prior_dataset().map_err(|error| {
        review_loop_entry::InboxIndependentAuditLaneBlocker::SelectorRejected {
            detail: error.to_string(),
        }
    })?;
    let known = priors
        .models
        .iter()
        .filter(|prior| prior.runtime == "codex")
        .map(|prior| prior.model.clone())
        .collect::<BTreeSet<_>>();
    let catalog = load_codex_runtime_model_catalog(program, repo, timeout).map_err(|failure| {
        review_loop_entry::InboxIndependentAuditLaneBlocker::UnavailableEligibleAuditor {
            detail: failure.summary,
        }
    })?;
    Ok(known
        .into_iter()
        .filter(|model| catalog.contains(model))
        .collect())
}

fn selector_effort_label(effort: crate::selection::ReasoningEffort) -> &'static str {
    match effort {
        crate::selection::ReasoningEffort::Low => "low",
        crate::selection::ReasoningEffort::Medium => "medium",
        crate::selection::ReasoningEffort::High => "high",
        crate::selection::ReasoningEffort::Xhigh => "xhigh",
        crate::selection::ReasoningEffort::Max => "max",
        crate::selection::ReasoningEffort::Ultra => "ultra",
    }
}

fn finish_independent_audit_lane_item(
    writer: &mut ArtifactRunWriter,
    input: InboxItemRunInput<'_>,
    review_loop: Option<review_loop_entry::InboxReviewLoopReport>,
    pr_intake: InboxPrIntakeReport,
    lane: review_loop_entry::InboxIndependentAuditLaneResult,
) -> Result<InboxItemRunOutcome> {
    let context = input.context;
    let item_index = input.item_index;
    let item = input.item;
    let run_id = context.run_id;
    let autopilot_run_id = RunId::new(format!("{}-item-{item_index}", run_id.as_str()))?;
    let autopilot_report_relative =
        PathBuf::from(format!("item-{item_index}-autopilot-report.json"));
    let github_report_relative = PathBuf::from(format!("item-{item_index}-github-report.json"));
    write_private_artifact_json(writer, &autopilot_report_relative, &lane)?;
    let github_report = InboxGithubActionReport {
        mode: context.action_policy,
        permission_mode: context.permission_mode,
        status: if lane.auto_merge_performed {
            "merged".to_string()
        } else {
            "blocked".to_string()
        },
        success: lane.success,
        target: item_target(item),
        comment_url: lane
            .merge_receipt
            .as_ref()
            .map(|receipt| receipt.url.clone()),
        message: Some(if lane.auto_merge_performed {
            "independent audit evidence was accepted and one authenticated merge receipt was verified"
                .to_string()
        } else {
            "independent audit or authenticated merge lane was blocked; no verified merge was reported"
                .to_string()
        }),
    };
    write_private_artifact_json(writer, &github_report_relative, &github_report)?;
    let next_action = lane.next_action.clone();
    Ok(InboxItemRunOutcome {
        report: InboxItemRunReport {
            item_index,
            item_id: item.item_id.clone(),
            kind: item.kind,
            title: item.title.clone(),
            success: lane.success,
            status: if lane.auto_merge_performed {
                "merged".to_string()
            } else if lane.auditor_evidence.is_some() {
                "merge_blocked".to_string()
            } else {
                "launch_blocked".to_string()
            },
            plan_path: public_item_path(run_id, &format!("item-{item_index}-plan.json")),
            autopilot_run_id: autopilot_run_id.as_str().to_string(),
            autopilot_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-autopilot-report.json"),
            ),
            github_report_path: public_item_path(
                run_id,
                &format!("item-{item_index}-github-report.json"),
            ),
            autopilot_success: None,
            github_success: github_report.success,
            review_loop,
            pr_intake: Some(pr_intake),
            independent_audit_lane: Some(lane),
            next_action,
        },
        refusal: None,
    })
}

fn inbox_budget_refusal(report: &autopilot::AutopilotFinalReport) -> Option<InboxRefusal> {
    if !matches!(
        report.status,
        AutopilotRunStatus::Failed | AutopilotRunStatus::Refused
    ) {
        return None;
    }
    let supervisor = report.supervisor.as_ref()?;
    let has_budget_admission_denial = report
        .gate_denials
        .iter()
        .chain(supervisor.gate_denials.iter())
        .any(|denial| matches!(&denial.reason, GateDenialReason::BudgetAdmission { .. }));
    if !has_budget_admission_denial {
        return None;
    }
    let reasons = &supervisor.run_budget.as_ref()?.reasons;
    let (kind, message) =
        if reasons.contains(&crate::supervise::BudgetReason::HardTokenCeilingReached) {
            (
                "hard_token_ceiling",
                "the rolling token quota refused this inbox autopilot dispatch",
            )
        } else if reasons.contains(&crate::supervise::BudgetReason::HardCostCeilingReached) {
            (
                "hard_cost_ceiling",
                "the rolling cost quota refused this inbox autopilot dispatch",
            )
        } else {
            return None;
        };
    Some(InboxRefusal {
        kind: kind.to_string(),
        message: message.to_string(),
        paths: Vec::new(),
        lock_details: Vec::new(),
    })
}

fn autopilot_plan_for_item(
    item: &InboxItem,
    config: &InboxConfig,
    permission_mode: InboxPermissionMode,
) -> Result<AutopilotPlan> {
    let assigned_paths = assigned_paths_for_item(item, config)?;
    let path_proposal = item
        .issue
        .as_ref()
        .map(|issue| issue.path_proposal.clone())
        .unwrap_or_default();
    let mut validation_commands = config
        .default_validation_commands
        .iter()
        .map(AutopilotValidationCommand::from)
        .collect::<Vec<_>>();
    for command in &mut validation_commands {
        if command.timeout_seconds.is_none() {
            command.timeout_seconds = config.timeout_seconds;
        }
    }
    Ok(AutopilotPlan {
        version: 1,
        task: AutopilotTask {
            title: format!("Inbox {}: {}", item_label(item.kind), item.title),
            body: task_body_for_item(item),
        },
        assigned_paths,
        path_proposal,
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        validation_commands,
        max_repair_attempts: config.max_repair_attempts,
        forge_mode: if permission_mode.publishes_github_pr() {
            AutopilotForgeMode::Github
        } else if permission_mode.publishes_git_branch() {
            AutopilotForgeMode::Git
        } else {
            AutopilotForgeMode::Fake
        },
        reviewer: ReviewerConfig {
            mode: ReviewerMode::Fake,
            timeout_seconds: config.timeout_seconds,
            ..ReviewerConfig::default()
        },
        publish_mode: AutopilotPublishMode::DraftOnly,
        auto_merge: false,
        external_source: item.source_snapshot.external_source_guard()?,
    })
}

fn task_body_for_item(item: &InboxItem) -> String {
    match (&item.issue, &item.pull_request) {
        (Some(issue), _) => format!(
            "React to GitHub issue #{}.\nURL: {}\n\nIssue body summary:\n{}\n\nCreate a focused repair or implementation plan for the assigned paths. Do not merge automatically.",
            issue.number,
            issue.url.as_deref().unwrap_or("unknown"),
            issue.body_summary
        ),
        (_, Some(pr)) => {
            let checks = pr
                .checks
                .iter()
                .map(|check| {
                    format!(
                        "- {} status={} conclusion={} summary={}",
                        check.name,
                        check.status.as_deref().unwrap_or("unknown"),
                        check.conclusion.as_deref().unwrap_or("unknown"),
                        check.summary
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let reviews = pr.review_feedback.summaries.join("\n");
            let failing_checks = pr
                .checks
                .iter()
                .filter(|check| {
                    check_failed(check.conclusion.as_deref(), check.status.as_deref())
                })
                .map(|check| check.name.clone())
                .collect::<Vec<_>>();
            let needs_repair = pr_needs_repair(pr);
            let path_reasons = pr_path_reasons(pr, &failing_checks);
            let validation_expectation = pr_validation_expectation(pr, &failing_checks);
            let action = if needs_repair {
                "Repair failing checks or requested changes in isolated autopilot work. Do not merge automatically."
            } else {
                "Perform an independent audit for merge-lane evidence. Revalidate source freshness and CI, preserve producer/auditor separation, and do not edit or merge the pull request."
            };
            format!(
                "React to GitHub PR #{}.\nURL: {}\nHead: {}\nBase: {}\n\nChanged files:\n{}\n\nTarget paths and reasons:\n{}\n\nChecks:\n{}\n\nReview feedback:\n{}\n\nValidation expectation:\n{}\n\n{}",
                pr.number,
                pr.url.as_deref().unwrap_or("unknown"),
                pr.head_ref.as_deref().unwrap_or("unknown"),
                pr.base_ref.as_deref().unwrap_or("unknown"),
                path_list(&pr.changed_files),
                path_reasons,
                if checks.is_empty() { "no failing check metadata" } else { &checks },
                if reviews.is_empty() { "no review summaries" } else { &reviews },
                validation_expectation,
                action
            )
        }
        _ => format!(
            "React to inbox item {}. Do not merge automatically.",
            item.item_id
        ),
    }
}

fn pr_path_reasons(pr: &GithubPrCandidate, failing_checks: &[String]) -> String {
    let check_reason = if !failing_checks.is_empty() {
        format!(
            "review feedback requested changes; failing checks: {}",
            failing_checks.join(", ")
        )
    } else if pr.review_feedback.requested_changes {
        "review feedback requested changes".to_string()
    } else {
        "independent audit scope for merge-lane evidence".to_string()
    };
    let paths = if pr.changed_files.is_empty() {
        vec![PathBuf::from("README.md")]
    } else {
        pr.changed_files.clone()
    };
    paths
        .iter()
        .map(|path| format!("- {}: {}", path.display(), check_reason))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pr_validation_expectation(pr: &GithubPrCandidate, failing_checks: &[String]) -> String {
    if !failing_checks.is_empty() {
        format!(
            "run or preserve configured validation and address failing check context: {}",
            failing_checks.join(", ")
        )
    } else if pr.review_feedback.requested_changes {
        "preserve configured validation and confirm requested review changes are addressed"
            .to_string()
    } else {
        "independently verify the observed checks and fail closed on stale, missing, pending, skipped, or non-success CI evidence"
            .to_string()
    }
}

fn github_action_for_item(
    repo: &Path,
    _config: &InboxConfig,
    action_policy: InboxActionPolicy,
    permission_mode: InboxPermissionMode,
    item: &InboxItem,
    autopilot_success: bool,
    autopilot_message: Option<String>,
) -> InboxGithubActionReport {
    if !permission_mode.comments_on_source() {
        return InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "local_report_only".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some(format!(
                "GitHub source comments are disabled in permission mode {}",
                permission_mode_label(permission_mode)
            )),
        };
    }
    if !autopilot_success {
        return InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "skipped".to_string(),
            success: true,
            target: item_target(item),
            comment_url: None,
            message: Some("autopilot did not succeed; GitHub comment skipped".to_string()),
        };
    }
    if let Err(error) = revalidate_inbox_item_source(repo, item) {
        return InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "source_drift".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some(sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text),
        };
    }

    let Some(_number) = item_number(item) else {
        return InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "failed".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some("item has no GitHub number to comment on".to_string()),
        };
    };
    let body = sanitize_public_text(
        repo,
        &format!(
            "maco inbox processed this item in explicit GitHub mode.\n\nResult: succeeded\nNext action: {}",
            autopilot_message.unwrap_or_else(|| "review generated reports".to_string())
        ),
        COMMENT_BODY_LIMIT,
    )
    .text;
    let guard = match item.source_snapshot.external_source_guard() {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            return InboxGithubActionReport {
                mode: action_policy,
                permission_mode,
                status: "failed".to_string(),
                success: false,
                target: item_target(item),
                comment_url: None,
                message: Some(
                    "GitHub comment source omitted its authenticated freshness guard".to_string(),
                ),
            };
        }
        Err(error) => {
            return InboxGithubActionReport {
                mode: action_policy,
                permission_mode,
                status: "failed".to_string(),
                success: false,
                target: item_target(item),
                comment_url: None,
                message: Some(
                    sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text,
                ),
            };
        }
    };
    match publication::publish_github_source_comment(repo, guard, &body) {
        Ok(url) => InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "commented".to_string(),
            success: true,
            target: item_target(item),
            comment_url: Some(url),
            message: None,
        },
        Err(error) => InboxGithubActionReport {
            mode: action_policy,
            permission_mode,
            status: "failed".to_string(),
            success: false,
            target: item_target(item),
            comment_url: None,
            message: Some(sanitize_public_text(repo, &error.to_string(), GH_DIAGNOSTIC_LIMIT).text),
        },
    }
}

fn revalidate_inbox_item_source(repo: &Path, item: &InboxItem) -> Result<()> {
    item.source_snapshot.validate()?;
    if let Some(guard) = item.source_snapshot.external_source_guard()? {
        publication::revalidate_external_source(repo, &guard)?;
    }
    Ok(())
}

fn issue_item(
    raw: RawIssueCandidate,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
    duplicates: &BTreeMap<String, String>,
) -> Result<InboxItem> {
    let source_key = format!("github_issue:{}", raw.number);
    validate_candidate_repository_url(
        raw.provider,
        raw.url.as_deref(),
        &source_repository.selector,
        InboxItemKind::Issue,
        raw.number,
    )?;
    let source_snapshot = InboxSourceSnapshotBinding::for_issue(
        raw.provider,
        source_repository.host.clone(),
        source_repository.selector.clone(),
        source_repository.identity.clone(),
        raw.number,
        raw.updated_at.clone(),
        raw.state.clone(),
        raw.content_digest.clone(),
        raw.action_revision_digest.clone(),
    )?;
    let mut privacy = privacy_scan(&raw.body, &config.privacy);
    extend_privacy_reasons(&mut privacy, "title", &raw.title, &config.privacy);
    let duplicate = duplicate_result(&source_key, duplicates);
    let mut skip_reason = None;
    if !privacy.safe {
        skip_reason = Some("privacy_refused".to_string());
    } else if duplicate.duplicate {
        skip_reason = Some("duplicate".to_string());
    }
    let selected = skip_reason.is_none();
    let title = sanitize_public_field(&raw.title, 512);
    let url = raw
        .url
        .as_ref()
        .map(|value| sanitize_public_field(value, MAX_GITHUB_URL_BYTES));
    let author = raw
        .author
        .as_ref()
        .map(|value| sanitize_public_field(value, MAX_GITHUB_LOGIN_BYTES));
    let labels = sanitize_public_fields(&raw.labels, MAX_LABEL_BYTES);
    Ok(InboxItem {
        item_id: format!("issue-{}", raw.number),
        source_key,
        source_snapshot,
        kind: InboxItemKind::Issue,
        title: title.clone(),
        url: url.clone(),
        issue: Some(GithubIssueCandidate {
            number: raw.number,
            title,
            url,
            author,
            labels,
            updated_at: Some(raw.updated_at),
            body_summary: privacy.body_summary.clone(),
            body_truncated: privacy.body_truncated,
            assigned_paths: normalize_or_default(raw.assigned_paths, config)?,
            path_proposal: raw.path_proposal,
        }),
        pull_request: None,
        privacy,
        duplicate,
        selected,
        skip_reason,
    })
}

fn pr_item(
    raw: RawPrCandidate,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
    duplicates: &BTreeMap<String, String>,
) -> Result<InboxItem> {
    let source_key = format!("github_pr:{}", raw.number);
    validate_candidate_repository_url(
        raw.provider,
        raw.url.as_deref(),
        &source_repository.selector,
        InboxItemKind::PullRequest,
        raw.number,
    )?;
    let source_snapshot = InboxSourceSnapshotBinding::for_pull_request(
        raw.provider,
        source_repository.host.clone(),
        source_repository.selector.clone(),
        source_repository.identity.clone(),
        raw.number,
        raw.updated_at.clone(),
        raw.state.clone(),
        raw.head_oid.clone(),
        raw.base_oid.clone(),
        raw.content_digest.clone(),
        raw.action_revision_digest.clone(),
    )?;
    let mut privacy = privacy_scan(&raw.body, &config.privacy);
    extend_privacy_reasons(&mut privacy, "title", &raw.title, &config.privacy);
    let duplicate = duplicate_result(&source_key, duplicates);
    let mut skip_reason = None;
    if !privacy.safe {
        skip_reason = Some("privacy_refused".to_string());
    } else if duplicate.duplicate {
        skip_reason = Some("duplicate".to_string());
    }
    let selected = skip_reason.is_none();
    let title = sanitize_public_field(&raw.title, 512);
    let url = raw
        .url
        .as_ref()
        .map(|value| sanitize_public_field(value, MAX_GITHUB_URL_BYTES));
    let author = raw
        .author
        .as_ref()
        .map(|value| sanitize_public_field(value, MAX_GITHUB_LOGIN_BYTES));
    let labels = sanitize_public_fields(&raw.labels, MAX_LABEL_BYTES);
    let checks = raw
        .checks
        .into_iter()
        .map(|check| {
            let name = sanitize_public_field(&check.name, MAX_GITHUB_TITLE_BYTES);
            let status = check
                .status
                .map(|value| sanitize_public_field(&value, MAX_GITHUB_STATUS_BYTES));
            let conclusion = check
                .conclusion
                .map(|value| sanitize_public_field(&value, MAX_GITHUB_STATUS_BYTES));
            GithubCheckSummary {
                summary: check_summary(&name, status.as_deref(), conclusion.as_deref()),
                name,
                status,
                conclusion,
                details_url: check
                    .details_url
                    .map(|value| sanitize_public_field(&value, MAX_GITHUB_URL_BYTES)),
            }
        })
        .collect();
    let review_feedback = GithubReviewFeedbackSummary {
        review_decision: raw
            .review_feedback
            .review_decision
            .map(|value| sanitize_public_field(&value, MAX_GITHUB_STATUS_BYTES)),
        requested_changes: raw.review_feedback.requested_changes,
        unresolved_thread_count: raw.review_feedback.unresolved_thread_count,
        reviewer_logins: sanitize_public_fields(
            &raw.review_feedback.reviewer_logins,
            MAX_GITHUB_LOGIN_BYTES,
        ),
        summaries: sanitize_public_fields(&raw.review_feedback.summaries, 512),
    };
    Ok(InboxItem {
        item_id: format!("pr-{}", raw.number),
        source_key,
        source_snapshot,
        kind: InboxItemKind::PullRequest,
        title: title.clone(),
        url: url.clone(),
        issue: None,
        pull_request: Some(GithubPrCandidate {
            number: raw.number,
            title,
            url,
            author,
            labels,
            updated_at: Some(raw.updated_at),
            head_ref: raw
                .head_ref
                .map(|value| sanitize_public_field(&value, MAX_GITHUB_REF_BYTES)),
            base_ref: raw
                .base_ref
                .map(|value| sanitize_public_field(&value, MAX_GITHUB_REF_BYTES)),
            is_draft: raw.is_draft,
            source_trust: raw.source_trust,
            head_repository: raw.head_repository,
            // Preserve an explicitly empty GitHub file observation. Repair
            // planning may still use configured fallback paths, but the
            // independent-audit lane must not mistake a fallback for source
            // evidence about the PR's actual change set.
            changed_files: raw.changed_files,
            checks,
            review_feedback,
            body_summary: privacy.body_summary.clone(),
            body_truncated: privacy.body_truncated,
        }),
        privacy,
        duplicate,
        selected,
        skip_reason,
    })
}

fn should_include_pr_candidate(config: &InboxConfig, candidate: &RawPrCandidate) -> bool {
    config.selection.include_draft_prs || !candidate.is_draft
}

fn pr_needs_repair(pull_request: &GithubPrCandidate) -> bool {
    pull_request.review_feedback.requested_changes
        || pull_request
            .checks
            .iter()
            .any(|check| check_failed(check.conclusion.as_deref(), check.status.as_deref()))
}

fn pr_dispatch_mode_allows_item(mode: InboxPrDispatchMode, item: &InboxItem) -> bool {
    match (mode, item.kind, item.pull_request.as_ref()) {
        (InboxPrDispatchMode::RepairOnly, InboxItemKind::PullRequest, Some(pull_request)) => {
            pr_needs_repair(pull_request)
        }
        (InboxPrDispatchMode::RepairOnly, InboxItemKind::PullRequest, None) => false,
        _ => true,
    }
}

fn pr_intake_report_for_item(item: &InboxItem) -> Option<InboxPrIntakeReport> {
    let pull_request = item.pull_request.as_ref()?;
    if item.kind != InboxItemKind::PullRequest || pr_needs_repair(pull_request) {
        return None;
    }

    let task_kind = InboxPrIntakeTaskKind::IndependentAuditMergeLane;
    let mut missing_evidence = Vec::new();
    let mut missing_eligibility = Vec::new();
    let producer_login = pull_request
        .author
        .as_deref()
        .filter(|login| !login.trim().is_empty());
    if producer_login.is_none() {
        missing_evidence.push("producer_identity".to_string());
    }
    if pull_request.changed_files.is_empty() {
        missing_evidence.push("changed_files".to_string());
    }
    if pull_request.checks.is_empty() {
        missing_evidence.push("ci_checks".to_string());
    } else {
        for check in &pull_request.checks {
            if check.status.as_deref().is_none_or(str::is_empty) {
                missing_evidence.push("ci_check_status".to_string());
            }
            if check
                .conclusion
                .as_deref()
                .is_none_or(|conclusion| !conclusion.eq_ignore_ascii_case("success"))
                || check
                    .status
                    .as_deref()
                    .is_none_or(|status| !status.eq_ignore_ascii_case("completed"))
            {
                missing_eligibility.push("passing_completed_ci".to_string());
            }
        }
    }
    if pull_request
        .review_feedback
        .unresolved_thread_count
        .is_some_and(|count| count > 0)
    {
        missing_eligibility.push("resolved_review_threads".to_string());
    }

    let head_oid = item.source_snapshot.head_oid();
    if head_oid.is_none() {
        missing_evidence.push("head_oid".to_string());
    }
    let base_oid = item.source_snapshot.base_oid();
    if base_oid.is_none() {
        missing_evidence.push("base_oid".to_string());
    }
    missing_evidence.sort();
    missing_evidence.dedup();
    missing_eligibility.sort();
    missing_eligibility.dedup();

    let block_reason = if pull_request.is_draft {
        Some(("draft_pull_request", Vec::new()))
    } else {
        match pull_request.source_trust {
            GithubPrSourceTrust::Fork => Some(("fork_source", Vec::new())),
            GithubPrSourceTrust::Untrusted => Some(("untrusted_source", Vec::new())),
            GithubPrSourceTrust::TrustedTargetRepository if !missing_eligibility.is_empty() => {
                Some(("missing_eligibility", missing_eligibility))
            }
            GithubPrSourceTrust::TrustedTargetRepository if !missing_evidence.is_empty() => {
                Some(("missing_required_evidence", missing_evidence))
            }
            GithubPrSourceTrust::TrustedTargetRepository => None,
        }
    };

    let ready_evidence = match (head_oid, base_oid, producer_login) {
        (Some(head_oid), Some(base_oid), Some(producer_login)) => {
            Some((head_oid, base_oid, producer_login))
        }
        _ => None,
    };
    let (status, task, launch_block) = match (block_reason, ready_evidence) {
        (None, Some((head_oid, base_oid, producer_login))) => (
            InboxPrIntakeStatus::Ready,
            Some(InboxIndependentAuditMergeLaneTask {
                version: INBOX_SCHEMA_VERSION,
                task_kind,
                source_snapshot_digest: item.source_snapshot.digest().to_string(),
                source_updated_at: item.source_snapshot.updated_at().to_string(),
                head_oid: head_oid.to_string(),
                base_oid: base_oid.to_string(),
                producer_login: producer_login.to_string(),
                is_draft: pull_request.is_draft,
                source_trust: pull_request.source_trust,
                head_repository: pull_request.head_repository.clone(),
                changed_files: pull_request.changed_files.clone(),
                checks: pull_request.checks.clone(),
                requires_trusted_actor_binding: true,
                requires_fresh_source_revalidation: true,
                requires_passing_ci: true,
                requires_independent_auditor: true,
                grants_merge_permission: false,
                auto_merge_performed: false,
                next_action:
                    "launch an independent auditor through the merge-lane evidence adapter; do not merge"
                        .to_string(),
            }),
            None,
        ),
        (Some((reason, evidence)), _) => (
            InboxPrIntakeStatus::LaunchBlocked,
            None,
            Some(InboxPrLaunchBlockReport {
                version: INBOX_SCHEMA_VERSION,
                status: InboxPrIntakeStatus::LaunchBlocked,
                success: false,
                reason: reason.to_string(),
                missing_evidence: evidence,
                grants_merge_permission: false,
                auto_merge_performed: false,
                next_action:
                    "refresh the PR observation and supply the missing evidence before launching an independent auditor"
                        .to_string(),
            }),
        ),
        (None, None) => (
            InboxPrIntakeStatus::LaunchBlocked,
            None,
            Some(InboxPrLaunchBlockReport {
                version: INBOX_SCHEMA_VERSION,
                status: InboxPrIntakeStatus::LaunchBlocked,
                success: false,
                reason: "missing_required_evidence".to_string(),
                missing_evidence: vec!["internally_inconsistent_ready_evidence".to_string()],
                grants_merge_permission: false,
                auto_merge_performed: false,
                next_action:
                    "refresh the PR observation and supply the missing evidence before launching an independent auditor"
                        .to_string(),
            }),
        ),
    };

    Some(InboxPrIntakeReport {
        version: INBOX_SCHEMA_VERSION,
        item_id: item.item_id.clone(),
        source_key: item.source_key.clone(),
        number: pull_request.number,
        task_kind,
        status,
        success: status == InboxPrIntakeStatus::Ready,
        task,
        launch_block,
        grants_merge_permission: false,
        auto_merge_performed: false,
    })
}

fn verify_pr_event_task(
    items: &[InboxItem],
    expected: &InboxIndependentAuditMergeLaneTask,
) -> Result<()> {
    let observed = items
        .iter()
        .find_map(pr_intake_report_for_item)
        .and_then(|report| report.task)
        .context("authenticated PR event rescan produced no source-bound audit task")?;
    if &observed != expected {
        bail!("authenticated PR event evidence changed before dispatch");
    }
    Ok(())
}

type PrSnapshotDuplicateKey = (String, String);

/// Prior issue behavior remains keyed by source object identity. PRs also bind
/// duplicate suppression to the exact observed snapshot so a later source
/// update becomes visible again while an unchanged observation stays quiet.
fn load_duplicate_pr_snapshots(repo: &Path) -> Result<BTreeMap<PrSnapshotDuplicateKey, String>> {
    let mut duplicates = BTreeMap::new();
    let list = artifacts::list_runs(repo, RunArtifactFamily::Inbox)?;
    for run in list.runs {
        if !run.finalized {
            continue;
        }
        let run_id = RunId::new(&run.run_id)?;
        let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, &run_id)
            .with_context(|| {
                format!(
                    "finalized inbox run '{}' changed during PR duplicate scan",
                    run.run_id
                )
            })?;
        let final_report = read_artifact_json(&reader, "final-report.json")?;
        let completed_successfully = final_report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = final_report.get("status").and_then(Value::as_str);
        if !completed_successfully || matches!(status, Some("dry_run" | "refused")) {
            continue;
        }
        let selected = reader.read("selected-items.json")?;
        let value: Value = serde_json::from_slice(&selected).with_context(|| {
            format!(
                "failed to parse finalized selected-items.json for inbox run '{}'",
                run.run_id
            )
        })?;
        let Some(items) = value.as_array() else {
            continue;
        };
        for item in items {
            if item.get("kind").and_then(Value::as_str) != Some("pull_request") {
                continue;
            }
            let Some(source_key) = item.get("source_key").and_then(Value::as_str) else {
                continue;
            };
            let Some(snapshot_digest) = item
                .get("source_snapshot")
                .and_then(|snapshot| snapshot.get("digest"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            duplicates
                .entry((source_key.to_string(), snapshot_digest.to_string()))
                .or_insert(run.run_id.clone());
        }
    }
    Ok(duplicates)
}

fn apply_pr_snapshot_duplicate(
    item: &mut InboxItem,
    duplicates: &BTreeMap<PrSnapshotDuplicateKey, String>,
) {
    if item.kind != InboxItemKind::PullRequest {
        return;
    }
    let matched_run_id = duplicates
        .get(&(
            item.source_key.clone(),
            item.source_snapshot.digest().to_string(),
        ))
        .cloned();
    item.duplicate = DuplicateDetectionResult {
        duplicate: matched_run_id.is_some(),
        key: item.source_key.clone(),
        reason: matched_run_id
            .as_ref()
            .map(|run_id| format!("exact PR snapshot already selected by inbox run {run_id}")),
        matched_run_id,
    };
    if item.skip_reason.as_deref() == Some("duplicate") {
        item.skip_reason = None;
    }
    if !item.privacy.safe {
        item.selected = false;
        item.skip_reason = Some("privacy_refused".to_string());
    } else if item.duplicate.duplicate {
        item.selected = false;
        item.skip_reason = Some("duplicate".to_string());
    } else if item.privacy.safe && item.skip_reason.is_none() {
        item.selected = true;
    }
}

fn apply_scan_decisions(items: &mut [InboxItem], max_items: usize) {
    let mut selected_count = 0usize;
    let mut seen_source_keys = BTreeSet::new();
    for item in items {
        if !seen_source_keys.insert(item.source_key.clone()) {
            item.selected = false;
            item.skip_reason = Some("duplicate".to_string());
            item.duplicate.duplicate = true;
            if item.duplicate.reason.is_none() {
                item.duplicate.reason =
                    Some("duplicate inbox candidate in current scan".to_string());
            }
            continue;
        }

        if !item.selected {
            continue;
        }

        if selected_count >= max_items {
            item.selected = false;
            item.skip_reason = Some("selection_limit".to_string());
            continue;
        }

        selected_count = selected_count.saturating_add(1);
    }
}

fn fake_issue_candidates(config: &InboxConfig) -> Vec<RawIssueCandidate> {
    vec![
        RawIssueCandidate {
            provider: InboxSourceProvider::Fake,
            number: 101,
            title: "Fake inbox issue: implement a focused local task".to_string(),
            body: "Implement the smallest safe code change for this deterministic fake issue."
                .to_string(),
            url: Some("fake://github/issues/101".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: "1970-01-01T00:00:00Z".to_string(),
            state: "OPEN".to_string(),
            content_digest: fake_source_content_digest(InboxItemKind::Issue, 101),
            action_revision_digest: fake_source_content_digest(InboxItemKind::Issue, 101),
            assigned_paths: config.default_assigned_paths.clone(),
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
        },
        RawIssueCandidate {
            provider: InboxSourceProvider::Fake,
            number: 101,
            title: "Fake inbox issue: duplicate local task".to_string(),
            body: "Duplicate copy of the deterministic fake issue; it should be skipped."
                .to_string(),
            url: Some("fake://github/issues/101#duplicate".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: "1970-01-01T00:00:00Z".to_string(),
            state: "OPEN".to_string(),
            content_digest: fake_source_content_digest(InboxItemKind::Issue, 101),
            action_revision_digest: fake_source_content_digest(InboxItemKind::Issue, 101),
            assigned_paths: config.default_assigned_paths.clone(),
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
        },
        RawIssueCandidate {
            provider: InboxSourceProvider::Fake,
            number: 303,
            title: "Fake inbox issue: unsafe private context".to_string(),
            body: "Do not publish local path /home/example/project or API_TOKEN=secret-value."
                .to_string(),
            url: Some("fake://github/issues/303".to_string()),
            author: Some("maco-fake".to_string()),
            labels: config.selection.labels.clone(),
            updated_at: "1970-01-01T00:00:00Z".to_string(),
            state: "OPEN".to_string(),
            content_digest: fake_source_content_digest(InboxItemKind::Issue, 303),
            action_revision_digest: fake_source_content_digest(InboxItemKind::Issue, 303),
            assigned_paths: config.default_assigned_paths.clone(),
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
        },
    ]
}

fn fake_pr_candidates(config: &InboxConfig) -> Vec<RawPrCandidate> {
    vec![RawPrCandidate {
        provider: InboxSourceProvider::Fake,
        number: 202,
        title: "Fake inbox PR: repair requested changes and failing checks".to_string(),
        body: "A deterministic fake pull request with requested changes and a failing check."
            .to_string(),
        url: Some("fake://github/pulls/202".to_string()),
        author: Some("maco-fake".to_string()),
        labels: config.selection.labels.clone(),
        updated_at: "1970-01-01T00:00:00Z".to_string(),
        state: "OPEN".to_string(),
        content_digest: fake_source_content_digest(InboxItemKind::PullRequest, 202),
        action_revision_digest: fake_source_content_digest(InboxItemKind::PullRequest, 202),
        head_ref: Some("fake/inbox-pr".to_string()),
        base_ref: config.repository.default_branch.clone(),
        head_oid: "1111111111111111111111111111111111111111".to_string(),
        base_oid: "2222222222222222222222222222222222222222".to_string(),
        is_draft: false,
        source_trust: GithubPrSourceTrust::TrustedTargetRepository,
        head_repository: Some("fake/maco/inbox".to_string()),
        changed_files: config.default_assigned_paths.clone(),
        checks: vec![GithubCheckSummary {
            name: "fake-ci".to_string(),
            status: Some("completed".to_string()),
            conclusion: Some("failure".to_string()),
            details_url: Some("fake://github/checks/fake-ci".to_string()),
            summary: "deterministic fake failing check; logs omitted".to_string(),
        }],
        review_feedback: GithubReviewFeedbackSummary {
            review_decision: Some("CHANGES_REQUESTED".to_string()),
            requested_changes: true,
            unresolved_thread_count: Some(1),
            reviewer_logins: vec!["maco-fake-reviewer".to_string()],
            summaries: vec!["deterministic fake requested change".to_string()],
        },
    }]
}

fn fake_source_content_digest(kind: InboxItemKind, number: u64) -> String {
    publication::stable_external_digest(
        format!("maco-fake-source-v1:{kind:?}:{number}:1970-01-01T00:00:00Z").as_bytes(),
    )
}

fn github_issue_candidates(
    repo: &Path,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
) -> Result<Vec<RawIssueCandidate>> {
    let output = publication::list_github_source_items(
        repo,
        &source_repository.selector,
        ExternalSourceObjectKind::Issue,
        config.selection.max_items,
        &config.selection.labels,
    )?;
    let Some(values) = output.as_array() else {
        bail!("gh issue list did not return a JSON array");
    };
    validate_count(values.len(), "gh issue list items", MAX_GITHUB_ITEMS)?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            raw_issue_from_value(repo, value, config, source_repository)
                .with_context(|| format!("invalid gh issue list item {}", index + 1))
        })
        .collect()
}

fn github_pr_candidates(
    repo: &Path,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
) -> Result<Vec<RawPrCandidate>> {
    let output = publication::list_github_source_items(
        repo,
        &source_repository.selector,
        ExternalSourceObjectKind::PullRequest,
        config.selection.max_items,
        &config.selection.labels,
    )?;
    let Some(values) = output.as_array() else {
        bail!("gh pr list did not return a JSON array");
    };
    validate_count(values.len(), "gh pr list items", MAX_GITHUB_ITEMS)?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            raw_pr_from_value(value, config, source_repository)
                .with_context(|| format!("invalid gh pr list item {}", index + 1))
        })
        .collect()
}

fn github_pr_candidate(
    repo: &Path,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
    number: u64,
) -> Result<RawPrCandidate> {
    let value = publication::view_github_source_item(
        repo,
        &source_repository.selector,
        number,
        ExternalSourceObjectKind::PullRequest,
    )?;
    raw_pr_from_value(&value, config, source_repository).context("invalid exact gh pr view item")
}

fn raw_issue_from_value(
    repo: &Path,
    value: &Value,
    config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
) -> Result<RawIssueCandidate> {
    let object = value
        .as_object()
        .context("GitHub issue candidate must be an object")?;
    let number = object
        .get("number")
        .and_then(Value::as_u64)
        .context("GitHub issue candidate requires an unsigned number")?;
    if number == 0 {
        bail!("GitHub issue number must be positive");
    }
    let title = required_input_string(
        object.get("title"),
        "GitHub issue title",
        MAX_GITHUB_TITLE_BYTES,
    )?;
    let body = optional_input_body(
        object.get("body"),
        "GitHub issue body",
        MAX_GITHUB_BODY_BYTES,
    )?
    .unwrap_or_default();
    let updated_at = required_input_string(
        object.get("updatedAt"),
        "GitHub issue updatedAt",
        MAX_TIMESTAMP_BYTES,
    )?;
    validate_timestamp(&updated_at)?;
    let source_guard = publication::github_source_guard_from_value(
        &source_repository.host,
        &source_repository.selector,
        &source_repository.identity,
        ExternalSourceObjectKind::Issue,
        value,
    )?;
    let (assigned_paths, path_proposal) = issue_path_proposal(repo, &title, &body, config);
    Ok(RawIssueCandidate {
        provider: InboxSourceProvider::Github,
        number,
        title,
        body,
        url: Some(required_input_string(
            object.get("url"),
            "GitHub issue URL",
            MAX_GITHUB_URL_BYTES,
        )?),
        author: optional_nested_login(object.get("author"), "GitHub issue author")?,
        labels: labels_from_value(object.get("labels"))?,
        updated_at,
        state: source_guard.state,
        content_digest: source_guard.content_digest,
        action_revision_digest: source_guard.action_revision_digest,
        assigned_paths,
        path_proposal,
    })
}

fn issue_path_proposal(
    repo: &Path,
    title: &str,
    body: &str,
    config: &InboxConfig,
) -> (Vec<PathBuf>, planning::TaskPathProposalDiagnostics) {
    match planning::propose_task_path_proposal(repo, title, body) {
        Ok(proposal) => {
            let paths = if proposal.paths.is_empty() {
                config.default_assigned_paths.clone()
            } else {
                proposal.paths
            };
            (paths, proposal.diagnostics)
        }
        Err(_) => {
            let mut diagnostics = planning::TaskPathProposalDiagnostics {
                degraded: true,
                notes: Vec::new(),
            };
            diagnostics
                .notes
                .push("task path proposal failed; used inbox default paths".to_string());
            (config.default_assigned_paths.clone(), diagnostics)
        }
    }
}

fn raw_pr_from_value(
    value: &Value,
    _config: &InboxConfig,
    source_repository: &SourceRepositoryBindingContext,
) -> Result<RawPrCandidate> {
    let object = value
        .as_object()
        .context("GitHub PR candidate must be an object")?;
    let number = object
        .get("number")
        .and_then(Value::as_u64)
        .context("GitHub PR candidate requires an unsigned number")?;
    if number == 0 {
        bail!("GitHub PR number must be positive");
    }
    let updated_at = required_input_string(
        object.get("updatedAt"),
        "GitHub PR updatedAt",
        MAX_TIMESTAMP_BYTES,
    )?;
    validate_timestamp(&updated_at)?;
    let source_guard = publication::github_source_guard_from_value(
        &source_repository.host,
        &source_repository.selector,
        &source_repository.identity,
        ExternalSourceObjectKind::PullRequest,
        value,
    )?;
    let head_oid = required_input_string(object.get("headRefOid"), "GitHub PR headRefOid", 64)?;
    let base_oid = required_input_string(object.get("baseRefOid"), "GitHub PR baseRefOid", 64)?;
    validate_git_oid(&head_oid, "headRefOid")?;
    validate_git_oid(&base_oid, "baseRefOid")?;
    let is_draft = match object.get("isDraft") {
        None | Some(Value::Null) => false,
        Some(value) => value
            .as_bool()
            .context("GitHub PR isDraft must be a boolean")?,
    };
    let (source_trust, head_repository) =
        github_pr_source_trust(object, &source_repository.selector)?;
    Ok(RawPrCandidate {
        provider: InboxSourceProvider::Github,
        number,
        title: required_input_string(
            object.get("title"),
            "GitHub PR title",
            MAX_GITHUB_TITLE_BYTES,
        )?,
        body: optional_input_body(object.get("body"), "GitHub PR body", MAX_GITHUB_BODY_BYTES)?
            .unwrap_or_default(),
        url: Some(required_input_string(
            object.get("url"),
            "GitHub PR URL",
            MAX_GITHUB_URL_BYTES,
        )?),
        author: optional_nested_login(object.get("author"), "GitHub PR author")?,
        labels: labels_from_value(object.get("labels"))?,
        updated_at,
        state: source_guard.state,
        content_digest: source_guard.content_digest,
        action_revision_digest: source_guard.action_revision_digest,
        head_ref: optional_input_string(
            object.get("headRefName"),
            "GitHub PR headRefName",
            MAX_GITHUB_REF_BYTES,
        )?,
        base_ref: optional_input_string(
            object.get("baseRefName"),
            "GitHub PR baseRefName",
            MAX_GITHUB_REF_BYTES,
        )?,
        head_oid,
        base_oid,
        is_draft,
        source_trust,
        head_repository,
        changed_files: files_from_value(object.get("files"))?,
        checks: checks_from_value(object.get("statusCheckRollup"))?,
        review_feedback: review_feedback_from_value(value)?,
    })
}

fn github_pr_source_trust(
    object: &serde_json::Map<String, Value>,
    target_repository_selector: &str,
) -> Result<(GithubPrSourceTrust, Option<String>)> {
    let is_cross_repository = match object.get("isCrossRepository") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_bool()
                .context("GitHub PR isCrossRepository must be a boolean")?,
        ),
    };
    let head_repository = match object.get("headRepository") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let repository = value
                .as_object()
                .context("GitHub PR headRepository must be an object")?;
            let name_with_owner = required_input_string(
                repository.get("nameWithOwner"),
                "GitHub PR headRepository.nameWithOwner",
                MAX_GITHUB_REF_BYTES,
            )?;
            let components = name_with_owner.split('/').collect::<Vec<_>>();
            if components.len() != 2
                || components.iter().any(|component| {
                    component.is_empty()
                        || !component.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
            {
                bail!("GitHub PR headRepository.nameWithOwner must be canonical owner/name");
            }
            Some(name_with_owner.to_ascii_lowercase())
        }
    };
    if is_cross_repository == Some(true) {
        return Ok((GithubPrSourceTrust::Fork, head_repository));
    }
    let target_owner_name = target_repository_selector
        .split('/')
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/");
    let trusted = is_cross_repository == Some(false)
        && head_repository
            .as_deref()
            .is_some_and(|repository| repository.eq_ignore_ascii_case(&target_owner_name));
    Ok((
        if trusted {
            GithubPrSourceTrust::TrustedTargetRepository
        } else {
            GithubPrSourceTrust::Untrusted
        },
        head_repository,
    ))
}

fn labels_from_value(value: Option<&Value>) -> Result<Vec<String>> {
    let values = optional_input_array(value, "GitHub labels", MAX_LABELS)?;
    let mut labels = Vec::with_capacity(values.len());
    for (index, label) in values.iter().enumerate() {
        let object = label
            .as_object()
            .with_context(|| format!("GitHub label {} must be an object", index + 1))?;
        labels.push(required_input_string(
            object.get("name"),
            &format!("GitHub label {} name", index + 1),
            MAX_LABEL_BYTES,
        )?);
    }
    validate_labels(labels, "GitHub labels")
}

fn files_from_value(value: Option<&Value>) -> Result<Vec<PathBuf>> {
    let values = optional_input_array(value, "GitHub changed files", MAX_GITHUB_FILES)?;
    let mut files = Vec::with_capacity(values.len());
    for (index, file) in values.iter().enumerate() {
        let object = file
            .as_object()
            .with_context(|| format!("GitHub changed file {} must be an object", index + 1))?;
        let path = required_input_string(
            object.get("path"),
            &format!("GitHub changed file {} path", index + 1),
            MAX_CONFIG_PATH_BYTES,
        )?;
        files.push(
            normalize_repo_relative_path(&path)
                .with_context(|| format!("GitHub changed file {} path is invalid", index + 1))?,
        );
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn checks_from_value(value: Option<&Value>) -> Result<Vec<GithubCheckSummary>> {
    let values = optional_input_array(value, "GitHub checks", MAX_GITHUB_CHECKS)?;
    let mut checks = Vec::with_capacity(values.len());
    for (index, check) in values.iter().enumerate() {
        let object = check
            .as_object()
            .with_context(|| format!("GitHub check {} must be an object", index + 1))?;
        let name = first_required_input_string(
            object,
            &["name", "workflowName", "context"],
            &format!("GitHub check {} name", index + 1),
            MAX_GITHUB_TITLE_BYTES,
        )?;
        let status = first_optional_input_string(
            object,
            &["status", "state"],
            &format!("GitHub check {} status", index + 1),
            MAX_GITHUB_STATUS_BYTES,
        )?;
        let conclusion = first_optional_input_string(
            object,
            &["conclusion"],
            &format!("GitHub check {} conclusion", index + 1),
            MAX_GITHUB_STATUS_BYTES,
        )?;
        checks.push(GithubCheckSummary {
            summary: check_summary(&name, status.as_deref(), conclusion.as_deref()),
            name,
            status,
            conclusion,
            details_url: first_optional_input_string(
                object,
                &["detailsUrl", "targetUrl", "url"],
                &format!("GitHub check {} details URL", index + 1),
                MAX_GITHUB_URL_BYTES,
            )?,
        });
    }
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(checks)
}

fn review_feedback_from_value(value: &Value) -> Result<GithubReviewFeedbackSummary> {
    let object = value
        .as_object()
        .context("GitHub PR review payload must be an object")?;
    let review_decision = optional_input_string(
        object.get("reviewDecision"),
        "GitHub PR reviewDecision",
        MAX_GITHUB_STATUS_BYTES,
    )?;
    let mut reviewer_logins = Vec::new();
    let mut summaries = Vec::new();
    let mut requested_changes = review_decision
        .as_deref()
        .is_some_and(|decision| decision.eq_ignore_ascii_case("CHANGES_REQUESTED"));
    let reviews = optional_input_array(
        object.get("latestReviews"),
        "GitHub latest reviews",
        MAX_GITHUB_REVIEWS,
    )?;
    for (index, review) in reviews.iter().enumerate() {
        let review = review
            .as_object()
            .with_context(|| format!("GitHub review {} must be an object", index + 1))?;
        if let Some(login) = optional_nested_login(
            review.get("author"),
            &format!("GitHub review {} author", index + 1),
        )? {
            reviewer_logins.push(login);
        }
        if optional_input_string(
            review.get("state"),
            &format!("GitHub review {} state", index + 1),
            MAX_GITHUB_STATUS_BYTES,
        )?
        .as_deref()
        .is_some_and(|state| state.eq_ignore_ascii_case("CHANGES_REQUESTED"))
        {
            requested_changes = true;
        }
        if let Some(body) = optional_input_body(
            review.get("body"),
            &format!("GitHub review {} body", index + 1),
            MAX_GITHUB_REVIEW_BODY_BYTES,
        )? {
            let summary = summarize_text(&body, 512).text;
            if !summary.trim().is_empty() {
                summaries.push(summary);
            }
        }
    }
    reviewer_logins.sort();
    reviewer_logins.dedup();
    Ok(GithubReviewFeedbackSummary {
        review_decision,
        requested_changes,
        unresolved_thread_count: None,
        reviewer_logins,
        summaries,
    })
}

fn preflight_refusals(repo: &Path, target_paths: &[PathBuf]) -> Result<Vec<InboxRefusal>> {
    let mut refusals = Vec::new();
    let target_paths = non_runtime_paths(target_paths);
    let dirty_paths = dirty_primary_paths(repo)?;
    if !dirty_paths.is_empty() {
        refusals.push(InboxRefusal {
            kind: "dirty_primary".to_string(),
            message: "primary worktree has local changes outside ignored runtime paths".to_string(),
            paths: dirty_paths,
            lock_details: Vec::new(),
        });
    }

    let sync_claims = SyncStore::open(repo)?.snapshot()?;
    let mut sync_details = Vec::new();
    for claim in &sync_claims {
        let claim_paths = non_runtime_paths(&claim.paths);
        for path in planning::any_path_overlaps(&target_paths, &claim_paths) {
            sync_details.push(InboxLockRefusalDetail {
                path,
                owner: Some(claim.agent_id.clone()),
                token: Some(claim.token.get()),
                claim_id: None,
            });
        }
    }
    if !sync_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_sync_claims".to_string(),
            message: "active durable sync claims overlap selected inbox target paths".to_string(),
            paths: inbox_detail_paths(&sync_details),
            lock_details: sync_details,
        });
    }

    let semantic_intents = SemanticIntentStore::open(repo)?.snapshot()?;
    let mut semantic_details = Vec::new();
    for intent in &semantic_intents {
        let related_paths = intent
            .paths
            .iter()
            .chain(intent.impacted_files.iter())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let related_paths = non_runtime_paths(&related_paths);
        for path in planning::any_path_overlaps(&target_paths, &related_paths) {
            semantic_details.push(InboxLockRefusalDetail {
                path,
                owner: Some(intent.agent_id.clone()),
                token: Some(intent.token.get()),
                claim_id: None,
            });
        }
    }
    if !semantic_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_semantic_intents".to_string(),
            message: "active semantic coordination intents overlap selected inbox target paths"
                .to_string(),
            paths: inbox_detail_paths(&semantic_details),
            lock_details: semantic_details,
        });
    }

    let live = live_claim::status(repo, &LiveClock::now())?;
    let mut live_details = Vec::new();
    for claim in live.claims.into_iter().filter(|claim| claim.is_lock) {
        let owned_files = non_runtime_paths(&claim.owned_files);
        for path in planning::any_path_overlaps(&target_paths, &owned_files) {
            live_details.push(InboxLockRefusalDetail {
                path,
                owner: claim.owner.clone(),
                token: None,
                claim_id: Some(claim.claim_id.clone()),
            });
        }
    }
    if !live_details.is_empty() {
        refusals.push(InboxRefusal {
            kind: "active_live_locks".to_string(),
            message: "active or blocked live claim locks overlap selected inbox target paths"
                .to_string(),
            paths: inbox_detail_paths(&live_details),
            lock_details: live_details,
        });
    }

    Ok(refusals)
}

include!("inbox/part2.rs");

#[cfg(test)]
mod pr_intake_always_on_audit_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn clean_non_draft_pr_is_visible_as_independent_audit_task() {
        let config = InboxConfig::default();
        let raw = fake_pr(901);
        assert!(should_include_pr_candidate(&config, &raw));

        let item = pr_item(raw, &config, &fake_source(), &BTreeMap::new()).expect("clean PR");
        assert!(item.selected);
        assert_eq!(item.skip_reason, None);
        let intake = pr_intake_report_for_item(&item).expect("independent audit intake");
        assert_eq!(
            intake.task_kind,
            InboxPrIntakeTaskKind::IndependentAuditMergeLane
        );
        assert_eq!(intake.status, InboxPrIntakeStatus::Ready);
        assert!(intake.success);
        assert!(intake.launch_block.is_none());
        let task = intake.task.expect("audit task");
        assert_eq!(task.producer_login, "producer");
        assert!(task.requires_trusted_actor_binding);
        assert!(task.requires_fresh_source_revalidation);
        assert!(task.requires_passing_ci);
        assert!(task.requires_independent_auditor);
        assert!(!task.grants_merge_permission);
        assert!(!task.auto_merge_performed);
    }

    #[test]
    fn same_head_pr_event_task_drift_is_refused_before_dispatch() {
        let config = InboxConfig::default();
        let initial =
            pr_item(fake_pr(912), &config, &fake_source(), &BTreeMap::new()).expect("initial PR");
        let expected = pr_intake_report_for_item(&initial)
            .and_then(|report| report.task)
            .expect("initial source-bound task");

        let mut changed = fake_pr(912);
        changed.base_oid = "e".repeat(40);
        let changed = pr_item(changed, &config, &fake_source(), &BTreeMap::new())
            .expect("same-head changed PR");
        let error = verify_pr_event_task(&[changed], &expected)
            .expect_err("same-head evidence drift must block before dispatch");

        assert!(error
            .to_string()
            .contains("evidence changed before dispatch"));
    }

    #[test]
    fn unhealthy_pr_keeps_the_existing_repair_lane() {
        let config = InboxConfig::default();
        let mut raw = fake_pr(902);
        raw.checks[0].conclusion = Some("failure".to_string());
        raw.review_feedback.requested_changes = true;
        raw.review_feedback.review_decision = Some("CHANGES_REQUESTED".to_string());

        let item = pr_item(raw, &config, &fake_source(), &BTreeMap::new()).expect("unhealthy PR");
        assert!(item.selected);
        assert!(pr_intake_report_for_item(&item).is_none());
        let body = task_body_for_item(&item);
        assert!(body.contains("Repair failing checks or requested changes"));
        assert!(body.contains("failing checks: ci"));
    }

    #[test]
    fn draft_filtering_remains_default_deny() {
        let mut raw = fake_pr(903);
        raw.is_draft = true;
        let mut config = InboxConfig::default();
        assert!(!should_include_pr_candidate(&config, &raw));
        config.selection.include_draft_prs = true;
        assert!(should_include_pr_candidate(&config, &raw));
    }

    #[test]
    fn missing_merge_lane_evidence_emits_typed_launch_block() {
        let config = InboxConfig::default();
        let mut raw = fake_pr(904);
        raw.author = None;
        raw.changed_files.clear();
        raw.checks.clear();

        let item =
            pr_item(raw, &config, &fake_source(), &BTreeMap::new()).expect("evidence-deficient PR");
        assert!(item.selected, "blocked PR must remain visible");
        let intake = pr_intake_report_for_item(&item).expect("blocked audit intake");
        assert_eq!(intake.status, InboxPrIntakeStatus::LaunchBlocked);
        assert!(!intake.success);
        assert!(intake.task.is_none());
        let block = intake.launch_block.expect("launch block");
        assert_eq!(block.reason, "missing_required_evidence");
        assert!(!block.success);
        assert_eq!(
            block.missing_evidence,
            vec![
                "changed_files".to_string(),
                "ci_checks".to_string(),
                "producer_identity".to_string()
            ]
        );
        assert!(!block.grants_merge_permission);
        assert!(!block.auto_merge_performed);
    }

    #[test]
    fn github_pr_source_trust_requires_explicit_same_repository_evidence() {
        let absent = serde_json::Map::new();
        assert_eq!(
            github_pr_source_trust(&absent, "github.com/acme/repo").expect("absent provenance"),
            (GithubPrSourceTrust::Untrusted, None)
        );

        let fork = json!({
            "isCrossRepository": true,
            "headRepository": {"nameWithOwner": "contributor/fork"}
        });
        assert_eq!(
            github_pr_source_trust(
                fork.as_object().expect("fork object"),
                "github.com/acme/repo"
            )
            .expect("fork provenance")
            .0,
            GithubPrSourceTrust::Fork
        );

        let trusted = json!({
            "isCrossRepository": false,
            "headRepository": {"nameWithOwner": "acme/repo"}
        });
        assert_eq!(
            github_pr_source_trust(
                trusted.as_object().expect("trusted object"),
                "github.com/acme/repo"
            )
            .expect("trusted provenance")
            .0,
            GithubPrSourceTrust::TrustedTargetRepository
        );
    }

    #[test]
    fn independent_audit_adapter_accepts_strict_fake_command_evidence_and_merges_once() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo, "main")
            .expect("initialize repository");
        let config = InboxConfig::default();
        let item = pr_item(fake_pr(906), &config, &fake_source(), &BTreeMap::new())
            .expect("clean PR item");
        let pr_intake = pr_intake_report_for_item(&item).expect("audit intake");
        let task = pr_intake.task.as_ref().expect("audit task").clone();
        let output = review_loop_entry::InboxIndependentAuditorOutput {
            version: 1,
            item_id: item.item_id.clone(),
            source_snapshot_digest: task.source_snapshot_digest.clone(),
            head_oid: task.head_oid.clone(),
            accepted: true,
            lenses: vec![
                crate::optimizer::merge_authority::LensVerdict {
                    lens_id: "diff".to_string(),
                    model_label: "gpt-5.6-sol".to_string(),
                    framing: "adversarial-diff".to_string(),
                    information_scope: "diff-only".to_string(),
                    decision: crate::optimizer::merge_authority::LensDecision::Accept,
                },
                crate::optimizer::merge_authority::LensVerdict {
                    lens_id: "tests".to_string(),
                    model_label: "gpt-5.6-sol".to_string(),
                    framing: "tests-as-contract".to_string(),
                    information_scope: "tests-only".to_string(),
                    decision: crate::optimizer::merge_authority::LensDecision::Accept,
                },
            ],
            summary: "accepted exact candidate".to_string(),
            no_further_delegation: true,
            read_only: true,
        };
        let raw_output = serde_json::to_vec(&output).expect("serialize fake auditor output");
        let report_sha256 = crate::artifacts::state_auth::sha256_hex(&raw_output);
        let run_id = RunId::new("independent-audit-fake-command").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Inbox,
            run_id.clone(),
            "inbox-test",
        )
        .expect("reserve Inbox artifacts");
        let run_dir = writer.run_dir().to_path_buf();
        let context = InboxItemRunContext {
            repo: &repo,
            run_dir: &run_dir,
            run_id: &run_id,
            config: &config,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
            rolling_budget_quota: None,
        };
        let review_loop = review_loop_entry::evaluate_inbox_item_review_loop(&item);
        let available_models = ["gpt-5.6-sol".to_string()].into_iter().collect();
        let callback_called = Cell::new(false);
        let mut before_launch =
            |session_id: &str, selection: &InboxIndependentAuditorSelectionEvidence| {
                assert_eq!(session_id, "independent-audit-fake-command-item-1-auditor");
                assert_eq!(selection.model, "gpt-5.6-sol");
                assert_eq!(selection.effort, crate::selection::ReasoningEffort::Xhigh);
                callback_called.set(true);
                Ok(())
            };
        let outcome = run_independent_audit_intake_item_with_runner(
            &mut writer,
            InboxItemRunInput {
                context: &context,
                item_index: 1,
                item: &item,
            },
            review_loop,
            pr_intake,
            true,
            Some(&available_models),
            Some(&mut before_launch),
            |command| {
                assert!(
                    callback_called.get(),
                    "prelaunch callback must complete before the external runner"
                );
                assert_eq!(
                    command.workspace_access,
                    crate::process_runner::WorkspaceAccess::ReadOnly
                );
                assert_eq!(command.model.as_deref(), Some("gpt-5.6-sol"));
                assert_eq!(command.reasoning_effort.as_deref(), Some("xhigh"));
                IndependentAuditRunnerResult {
                    raw_output: Some(raw_output.clone()),
                    report_sha256: Some(report_sha256.clone()),
                    exit_code: Some(0),
                    duration_ms: 7,
                    timed_out: false,
                    safely_executed: true,
                    publishable: true,
                    succeeded: true,
                    scratch_quiescence_verified: true,
                    error: None,
                }
            },
        )
        .expect("run fake independent-audit adapter");
        assert!(callback_called.get());

        let lane = outcome.report.independent_audit_lane.expect("lane result");
        assert_eq!(
            lane.status,
            review_loop_entry::InboxIndependentAuditLaneStatus::Accepted
        );
        assert!(lane.success);
        assert!(!lane.grants_merge_permission);
        assert!(lane.auto_merge_performed);
        assert!(lane.merge_receipt.is_some());
        assert_eq!(outcome.report.status, "merged");
    }

    #[test]
    fn independent_audit_dry_run_neither_launches_nor_merges() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo, "main")
            .expect("initialize repository");
        let config = InboxConfig::default();
        let item = pr_item(fake_pr(907), &config, &fake_source(), &BTreeMap::new())
            .expect("clean PR item");
        let pr_intake = pr_intake_report_for_item(&item).expect("audit intake");
        let run_id = RunId::new("independent-audit-dry-run").expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Inbox,
            run_id.clone(),
            "inbox-test",
        )
        .expect("reserve Inbox artifacts");
        let run_dir = writer.run_dir().to_path_buf();
        let context = InboxItemRunContext {
            repo: &repo,
            run_dir: &run_dir,
            run_id: &run_id,
            config: &config,
            action_policy: InboxActionPolicy::DryRun,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/must-not-run/codex")),
            machine_global: None,
            rolling_budget_quota: None,
        };
        let outcome = run_independent_audit_intake_item_with_runner(
            &mut writer,
            InboxItemRunInput {
                context: &context,
                item_index: 1,
                item: &item,
            },
            review_loop_entry::evaluate_inbox_item_review_loop(&item),
            pr_intake,
            true,
            None,
            None,
            |_| panic!("dry run must not launch the independent auditor"),
        )
        .expect("dry-run audit plan");

        assert_eq!(outcome.report.status, "dry_run");
        assert!(outcome.report.independent_audit_lane.is_none());
        assert!(outcome.report.github_success);
    }

    #[test]
    fn independent_auditor_requires_the_exact_local_head_diff() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo_path, "main")
            .expect("initialize repository");
        let repository = Repository::open(&repo_path).expect("open repository");
        let signature =
            git2::Signature::now("Audit Test", "audit@example.invalid").expect("test signature");
        fs::write(repo_path.join("base.txt"), "base\n").expect("write base file");
        let mut index = repository.index().expect("repository index");
        index
            .add_path(Path::new("base.txt"))
            .expect("add base file");
        index.write().expect("write base index");
        let base_tree_oid = index.write_tree().expect("write base tree");
        let base_tree = repository.find_tree(base_tree_oid).expect("find base tree");
        let base = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "base",
                &base_tree,
                &[],
            )
            .expect("commit base");
        fs::write(repo_path.join("audit.txt"), "audited\n").expect("write audited file");
        let mut index = repository.index().expect("updated repository index");
        index
            .add_path(Path::new("audit.txt"))
            .expect("add audited file");
        index.write().expect("write index");
        let tree_oid = index.write_tree().expect("write tree");
        let tree = repository.find_tree(tree_oid).expect("find tree");
        let parent = repository.find_commit(base).expect("find parent");
        let head = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "audited head",
                &tree,
                &[&parent],
            )
            .expect("commit audited head");

        let config = InboxConfig::default();
        let mut raw = fake_pr(908);
        raw.base_oid = base.to_string();
        raw.head_oid = head.to_string();
        raw.changed_files = vec![PathBuf::from("audit.txt")];
        let item =
            pr_item(raw, &config, &fake_source(), &BTreeMap::new()).expect("local audit item");
        let intake = pr_intake_report_for_item(&item).expect("local audit intake");
        let task = intake.task.expect("local audit task");
        verify_local_independent_audit_candidate(&repo_path, &task)
            .expect("exact local audit candidate");

        let mut mismatched = task;
        mismatched.changed_files = vec![PathBuf::from("different.txt")];
        assert!(verify_local_independent_audit_candidate(&repo_path, &mismatched).is_err());
    }

    #[test]
    fn github_pr_materialization_missing_objects_fails_closed() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let (item, task) = github_materialization_test_item(&target_path, base, head);
        let transported = std::cell::Cell::new(false);
        let revalidated = std::cell::Cell::new(false);
        let error = materialize_and_verify_local_independent_audit_candidate_with(
            &target_path,
            &item,
            &task,
            |_, _| {
                transported.set(true);
                Ok(())
            },
            |_, _| {
                revalidated.set(true);
                Ok(())
            },
        )
        .expect_err("missing transported objects must fail closed");
        assert!(transported.get());
        assert!(revalidated.get());
        assert!(error.to_string().contains("omitted the exact pull-request"));
    }

    #[test]
    fn github_pr_materialization_ref_swap_is_rejected() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let (item, task) = github_materialization_test_item(&target_path, base, head);
        let request = trusted_github_pull_request_object_request(&target_path, &item, &task)
            .expect("trusted materialization request");

        let fetched_path = target_temp.path().join("fetched.git");
        let fetched = Repository::init_bare(&fetched_path).expect("initialize fetched repository");
        let source = Repository::open(&source_path).expect("open source repository");
        copy_pull_request_object_closure(&source, &fetched, base, head)
            .expect("copy test object closure");
        fetched
            .reference("refs/maco-inbox/base", head, true, "test swapped base")
            .expect("write swapped base");
        fetched
            .reference("refs/maco-inbox/head", base, true, "test swapped head")
            .expect("write swapped head");

        let error = validate_materialized_pull_request_refs(&fetched, &request)
            .expect_err("swapped transport refs must fail closed");
        assert!(error.to_string().contains("drifted"));
    }

    #[test]
    fn github_pr_materialization_rejects_stale_snapshot_after_valid_objects() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);
        let source = Repository::open(&source_path).expect("open source repository");

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let target = Repository::open(&target_path).expect("open target repository");
        let (item, task) = github_materialization_test_item(&target_path, base, head);
        let error = materialize_and_verify_local_independent_audit_candidate_with(
            &target_path,
            &item,
            &task,
            |_, request| {
                copy_pull_request_object_closure(
                    &source,
                    &target,
                    request.expected_base_oid,
                    request.expected_head_oid,
                )
            },
            |_, _| bail!("external source changed from its exact freshness snapshot"),
        )
        .expect_err("stale source snapshot must fail after object materialization");
        assert!(target.find_commit(base).is_ok());
        assert!(target.find_commit(head).is_ok());
        assert!(error
            .to_string()
            .contains("GitHub source changed after exact pull-request object materialization"));
    }

    #[test]
    fn github_pr_materialization_refuses_untrusted_and_fork_inputs() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let (trusted_item, trusted_task) =
            github_materialization_test_item(&target_path, base, head);
        for trust in [GithubPrSourceTrust::Fork, GithubPrSourceTrust::Untrusted] {
            let mut item = trusted_item.clone();
            item.pull_request
                .as_mut()
                .expect("pull request")
                .source_trust = trust;
            let mut task = trusted_task.clone();
            task.source_trust = trust;
            let transported = std::cell::Cell::new(false);
            let revalidated = std::cell::Cell::new(false);
            materialize_and_verify_local_independent_audit_candidate_with(
                &target_path,
                &item,
                &task,
                |_, _| {
                    transported.set(true);
                    Ok(())
                },
                |_, _| {
                    revalidated.set(true);
                    Ok(())
                },
            )
            .expect_err("untrusted materialization input must fail closed");
            assert!(!transported.get());
            assert!(!revalidated.get());
        }
    }

    #[test]
    fn github_pr_materialization_propagates_bounded_transport_failure() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let (item, task) = github_materialization_test_item(&target_path, base, head);
        let revalidated = std::cell::Cell::new(false);
        let error = materialize_and_verify_local_independent_audit_candidate_with(
            &target_path,
            &item,
            &task,
            |_, _| bail!("transport resource bound exceeded"),
            |_, _| {
                revalidated.set(true);
                Ok(())
            },
        )
        .expect_err("bounded transport failure must fail closed");
        assert!(!revalidated.get());
        assert!(error
            .to_string()
            .contains("bounded exact pull-request object transport failed"));
    }

    #[test]
    fn github_pr_materialization_accepts_valid_exact_objects_after_revalidation() {
        let source_temp = tempfile::TempDir::new().expect("source tempdir");
        let source_path = source_temp.path().join("source");
        crate::worktree::WorktreeManager::init_repository(&source_path, "main")
            .expect("initialize source repository");
        let (base, head) = create_materialization_test_commits(&source_path);
        let source = Repository::open(&source_path).expect("open source repository");

        let target_temp = tempfile::TempDir::new().expect("target tempdir");
        let target_path = target_temp.path().join("target");
        crate::worktree::WorktreeManager::init_repository(&target_path, "main")
            .expect("initialize target repository");
        let target = Repository::open(&target_path).expect("open target repository");
        let (item, task) = github_materialization_test_item(&target_path, base, head);
        let transported = std::cell::Cell::new(false);
        let revalidated = std::cell::Cell::new(false);
        materialize_and_verify_local_independent_audit_candidate_with(
            &target_path,
            &item,
            &task,
            |_, request| {
                transported.set(true);
                copy_pull_request_object_closure(
                    &source,
                    &target,
                    request.expected_base_oid,
                    request.expected_head_oid,
                )
            },
            |_, _| {
                assert!(
                    transported.get(),
                    "revalidation must follow materialization"
                );
                assert!(target.find_commit(base).is_ok());
                assert!(target.find_commit(head).is_ok());
                revalidated.set(true);
                Ok(())
            },
        )
        .expect("valid exact materialized objects");
        assert!(transported.get());
        assert!(revalidated.get());
    }

    #[test]
    fn updated_pr_snapshot_is_not_suppressed_as_the_old_observation() {
        let config = InboxConfig::default();
        let raw = fake_pr(905);
        let source_key = format!("github_pr:{}", raw.number);
        let prior_objects = BTreeMap::from([(source_key, "old-run".to_string())]);
        let mut item =
            pr_item(raw, &config, &fake_source(), &prior_objects).expect("historically seen PR");
        assert!(
            !item.selected,
            "legacy object-key suppression starts closed"
        );

        let old_snapshot = publication::stable_external_digest(b"older-pr-observation");
        let prior_snapshots = BTreeMap::from([(
            (item.source_key.clone(), old_snapshot),
            "old-run".to_string(),
        )]);
        apply_pr_snapshot_duplicate(&mut item, &prior_snapshots);
        assert!(item.selected, "updated snapshot must re-enter intake");
        assert!(!item.duplicate.duplicate);

        let exact_snapshots = BTreeMap::from([(
            (
                item.source_key.clone(),
                item.source_snapshot.digest().to_string(),
            ),
            "exact-run".to_string(),
        )]);
        apply_pr_snapshot_duplicate(&mut item, &exact_snapshots);
        assert!(!item.selected, "unchanged snapshot remains suppressed");
        assert_eq!(item.skip_reason.as_deref(), Some("duplicate"));
    }

    fn create_materialization_test_commits(repo_path: &Path) -> (Oid, Oid) {
        let repository = Repository::open(repo_path).expect("open materialization repository");
        let signature = git2::Signature::now("Materialization Test", "test@example.invalid")
            .expect("test signature");
        fs::write(repo_path.join("base.txt"), "base\n").expect("write base file");
        let mut index = repository.index().expect("base index");
        index
            .add_path(Path::new("base.txt"))
            .expect("add base file");
        index.write().expect("write base index");
        let base_tree_oid = index.write_tree().expect("write base tree");
        let base_tree = repository.find_tree(base_tree_oid).expect("find base tree");
        let base = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "base",
                &base_tree,
                &[],
            )
            .expect("commit base");
        drop(base_tree);

        fs::write(repo_path.join("audit.txt"), "audited\n").expect("write audit file");
        let mut index = repository.index().expect("head index");
        index
            .add_path(Path::new("audit.txt"))
            .expect("add audit file");
        index.write().expect("write head index");
        let head_tree_oid = index.write_tree().expect("write head tree");
        let head_tree = repository.find_tree(head_tree_oid).expect("find head tree");
        let parent = repository.find_commit(base).expect("find base parent");
        let head = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "head",
                &head_tree,
                &[&parent],
            )
            .expect("commit head");
        (base, head)
    }

    fn github_materialization_test_item(
        repo_path: &Path,
        base: Oid,
        head: Oid,
    ) -> (InboxItem, InboxIndependentAuditMergeLaneTask) {
        let repository = Repository::open(repo_path).expect("open target materialization repo");
        repository
            .remote("origin", "https://github.com/acme/repo.git")
            .expect("set canonical origin");
        let common = SafeRoot::open_existing(repository.commondir()).expect("bind common dir");
        let source = SourceRepositoryBindingContext {
            host: "github.com".to_string(),
            selector: "github.com/acme/repo".to_string(),
            identity: publication::external_source_repository_identity(
                common.identity().device,
                common.identity().file,
            ),
        };
        let mut raw = fake_pr(909);
        raw.provider = InboxSourceProvider::Github;
        raw.url = Some("https://github.com/acme/repo/pull/909".to_string());
        raw.base_oid = base.to_string();
        raw.head_oid = head.to_string();
        raw.base_ref = Some("main".to_string());
        raw.head_ref = Some("feature/exact-audit".to_string());
        raw.head_repository = Some("acme/repo".to_string());
        raw.source_trust = GithubPrSourceTrust::TrustedTargetRepository;
        raw.changed_files = vec![PathBuf::from("audit.txt")];
        let item = pr_item(raw, &InboxConfig::default(), &source, &BTreeMap::new())
            .expect("GitHub materialization item");
        let task = pr_intake_report_for_item(&item)
            .expect("materialization intake")
            .task
            .expect("materialization task");
        (item, task)
    }

    fn fake_source() -> SourceRepositoryBindingContext {
        SourceRepositoryBindingContext {
            host: "fake".to_string(),
            selector: ".".to_string(),
            identity: publication::stable_external_digest(b"clean-pr-intake-test"),
        }
    }

    fn fake_pr(number: u64) -> RawPrCandidate {
        RawPrCandidate {
            provider: InboxSourceProvider::Fake,
            number,
            title: "Clean PR".to_string(),
            body: "Ready for an independent audit.".to_string(),
            url: Some(format!("fake://github/pulls/{number}")),
            author: Some("producer".to_string()),
            labels: Vec::new(),
            updated_at: "2026-08-30T00:00:00Z".to_string(),
            state: "OPEN".to_string(),
            content_digest: publication::stable_external_digest(
                format!("clean-pr-content:{number}").as_bytes(),
            ),
            action_revision_digest: publication::stable_external_digest(
                format!("clean-pr-action:{number}").as_bytes(),
            ),
            head_ref: Some(format!("feature/{number}")),
            base_ref: Some("main".to_string()),
            head_oid: format!("{number:040x}"),
            base_oid: "2222222222222222222222222222222222222222".to_string(),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            head_repository: Some("fake/maco/inbox".to_string()),
            changed_files: vec![PathBuf::from("src/feature.rs")],
            checks: vec![GithubCheckSummary {
                name: "ci".to_string(),
                status: Some("completed".to_string()),
                conclusion: Some("success".to_string()),
                details_url: Some("fake://github/checks/ci".to_string()),
                summary: "passing CI".to_string(),
            }],
            review_feedback: GithubReviewFeedbackSummary {
                review_decision: None,
                requested_changes: false,
                unresolved_thread_count: None,
                reviewer_logins: Vec::new(),
                summaries: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod pr_intake_observation_seam_tests {
    use super::*;
    use tempfile::TempDir;

    fn observation_options() -> (TempDir, InboxRunOptions) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let repository = Repository::init(&repo_path).expect("initialize repository");
        repository
            .remote("origin", "https://github.com/acme/repo.git")
            .expect("configure canonical origin");
        let options = InboxRunOptions {
            repo: repo_path,
            run_id: RunId::new("typed-pr-observation").expect("run id"),
            github: true,
            permission_mode: Some(InboxPermissionMode::GithubRead),
            dry_run: false,
            max_items: None,
            codex_bin: None,
            machine_global: None,
        };
        (temp, options)
    }

    fn exact_pr_value(number: u64) -> Value {
        json!({
            "number": number,
            "title": "Contributor PR",
            "body": "Ready for independent audit",
            "url": format!("https://github.com/acme/repo/pull/{number}"),
            "author": {"login": "external-contributor"},
            "labels": [],
            "updatedAt": "2026-09-03T00:00:00Z",
            "state": "OPEN",
            "headRefName": "feature/typed-observation",
            "baseRefName": "main",
            "headRefOid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "baseRefOid": "cccccccccccccccccccccccccccccccccccccccc",
            "isDraft": false,
            "headRepository": {"nameWithOwner": "acme/repo"},
            "isCrossRepository": false,
            "files": [{"path": "src/lib.rs"}],
            "statusCheckRollup": [{
                "name": "test",
                "status": "completed",
                "conclusion": "success"
            }],
            "reviewDecision": null,
            "latestReviews": []
        })
    }

    #[test]
    fn pr_intake_observation_seam_classifies_provider_unavailability() {
        let (_temp, options) = observation_options();
        let error = observe_inbox_pr_event_with(&options, 17, |_, _, _| {
            Err(InboxPrObservationError::new(
                InboxPrObservationFailureClass::ProviderUnavailable,
                "injected transport failure",
            ))
        })
        .expect_err("transport failure must refuse observation");
        assert_eq!(
            error.classification,
            InboxPrObservationFailureClass::ProviderUnavailable
        );
    }

    #[test]
    fn pr_intake_observation_seam_classifies_malformed_provider_schema() {
        let (_temp, options) = observation_options();
        let error = observe_inbox_pr_event_with(&options, 17, |_, _, _| Ok(json!({"number": 17})))
            .expect_err("malformed schema must refuse observation");
        assert_eq!(
            error.classification,
            InboxPrObservationFailureClass::MalformedProviderResponse
        );
    }

    #[test]
    fn pr_intake_observation_seam_classifies_invalid_provider_identity() {
        let (_temp, options) = observation_options();
        let error = observe_inbox_pr_event_with(&options, 17, |_, _, _| Ok(exact_pr_value(18)))
            .expect_err("cross-field identity mismatch must refuse observation");
        assert_eq!(
            error.classification,
            InboxPrObservationFailureClass::InvalidProviderGroundTruth
        );
    }
}

#[cfg(test)]
mod github_watch_pr_producer_tests {
    use super::*;
    use crate::pr_intake::{
        PrIntakeObservationFailureClass, PrIntakeProducerDisposition, PrIntakeProducerRefusalCause,
        PrIntakeRefusalCause,
    };
    use std::cell::{Cell, RefCell};

    fn synthetic_producer_report(
        number: u64,
        disposition: PrIntakeProducerDisposition,
        refusal: Option<PrIntakeProducerRefusalCause>,
    ) -> crate::pr_intake::PrIntakeProducerReport {
        crate::pr_intake::PrIntakeProducerReport {
            version: 1,
            repository: None,
            number: Some(number),
            delivery_id: None,
            logical_id: None,
            effect_id: None,
            disposition,
            success: disposition != PrIntakeProducerDisposition::Refused,
            intake_report: None,
            refusal,
            grants_merge_permission: false,
            auto_merge_performed: false,
        }
    }

    fn synthetic_batch(number: u64) -> InboxPrIntakeProducerBatchReport {
        let producer_reports = vec![synthetic_producer_report(
            number,
            PrIntakeProducerDisposition::Refused,
            Some(PrIntakeProducerRefusalCause::ProviderObservation {
                classification: PrIntakeObservationFailureClass::ProviderUnavailable,
                detail: "bounded synthetic refusal".to_string(),
            }),
        )];
        InboxPrIntakeProducerBatchReport {
            version: INBOX_SCHEMA_VERSION,
            repository: Some("github.com/acme/repo".to_string()),
            discovery_sentinel: GITHUB_WATCH_PR_DISCOVERY_SENTINEL,
            maximum_processable: MAX_GITHUB_WATCH_PR_PRODUCERS,
            discovered_count: 1,
            producer_report_count: 1,
            producer_refusal_count: 1,
            success: false,
            discovery_refusal: None,
            producer_reports,
        }
    }

    fn synthetic_run(
        run_id: RunId,
        producer: Option<InboxPrIntakeProducerBatchReport>,
    ) -> InboxRunReport {
        InboxRunReport {
            version: INBOX_SCHEMA_VERSION,
            run_id,
            repo: PathBuf::from("."),
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            github_enabled: false,
            success: true,
            status: InboxRunStatus::NoItems,
            refusals: Vec::new(),
            artifacts: InboxRunArtifacts {
                run_dir: PathBuf::from(".maco/inbox/runs/test"),
                scan_report: PathBuf::from("scan-report.json"),
                selected_items: PathBuf::from("selected-items.json"),
                final_report: PathBuf::from("final-report.json"),
            },
            selected_item_count: 0,
            item_reports: Vec::new(),
            pr_intake_producer: producer,
            auto_merge_performed: false,
            next_action: "none".to_string(),
        }
    }

    fn test_pr_item(number: u64, needs_repair: bool) -> InboxItem {
        let config = InboxConfig::default();
        let mut raw = fake_pr_candidates(&config)
            .into_iter()
            .next()
            .expect("fake PR candidate");
        raw.number = number;
        raw.title = format!("PR {number}");
        raw.url = Some(format!("fake://github/pulls/{number}"));
        raw.updated_at = format!("2026-09-04T00:00:{:02}Z", number % 60);
        raw.content_digest = fake_source_content_digest(InboxItemKind::PullRequest, number);
        raw.action_revision_digest = raw.content_digest.clone();
        raw.head_oid = format!("{number:040x}");
        raw.checks[0].conclusion =
            Some(if needs_repair { "failure" } else { "success" }.to_string());
        raw.review_feedback.requested_changes = needs_repair;
        let source = SourceRepositoryBindingContext {
            host: "fake".to_string(),
            selector: ".".to_string(),
            identity: publication::stable_external_digest(b"watch-repair-mode"),
        };
        pr_item(raw, &config, &source, &BTreeMap::new()).expect("test PR item")
    }

    fn test_issue_item(number: u64) -> InboxItem {
        let config = InboxConfig::default();
        let mut raw = fake_issue_candidates(&config)
            .into_iter()
            .next()
            .expect("fake issue candidate");
        raw.number = number;
        raw.title = format!("Issue {number}");
        raw.url = Some(format!("fake://github/issues/{number}"));
        raw.content_digest = fake_source_content_digest(InboxItemKind::Issue, number);
        raw.action_revision_digest = raw.content_digest.clone();
        let source = SourceRepositoryBindingContext {
            host: "fake".to_string(),
            selector: ".".to_string(),
            identity: publication::stable_external_digest(b"watch-repair-mode"),
        };
        issue_item(raw, &config, &source, &BTreeMap::new()).expect("test issue item")
    }

    #[test]
    fn github_watch_discovery_uses_the_overflow_sentinel_and_offers_all_99_prs() {
        assert!(MAX_GITHUB_WATCH_PR_PRODUCERS > DEFAULT_MAX_ITEMS);
        let listed = (1..=MAX_GITHUB_WATCH_PR_PRODUCERS as u64)
            .rev()
            .map(|number| {
                json!({
                    "number": number,
                    "title": "ignored listing title",
                    "labels": ["ignored-selection-label"],
                    "issue_pressure": 10_000
                })
            })
            .collect::<Vec<_>>();
        let produced = RefCell::new(Vec::new());

        let report = produce_github_watch_pr_intakes_with(
            |kind, limit, labels| {
                assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                assert_eq!(limit, GITHUB_WATCH_PR_DISCOVERY_SENTINEL);
                assert!(
                    labels.is_empty(),
                    "selection labels must not constrain discovery"
                );
                Ok(("github.com/acme/repo".to_string(), Value::Array(listed)))
            },
            |number| {
                produced.borrow_mut().push(number);
                synthetic_producer_report(number, PrIntakeProducerDisposition::Launched, None)
            },
        );

        assert!(report.success, "{report:#?}");
        assert_eq!(report.discovered_count, MAX_GITHUB_WATCH_PR_PRODUCERS);
        assert_eq!(report.producer_report_count, MAX_GITHUB_WATCH_PR_PRODUCERS);
        assert_eq!(report.producer_refusal_count, 0);
        assert!(report.producer_reports.iter().all(|producer| {
            producer.repository.as_deref() == Some("github.com/acme/repo")
                && producer.number.is_some()
        }));
        assert_eq!(
            produced.into_inner(),
            (1..=MAX_GITHUB_WATCH_PR_PRODUCERS as u64).collect::<Vec<_>>(),
            "producer inputs must be the sorted number field only"
        );
    }

    #[test]
    fn github_watch_discovery_failures_are_typed_and_never_partially_produce() {
        let malformed = json!([{"number": "17"}]);
        let duplicate = json!([{"number": 17}, {"number": 17}]);
        let zero = json!([{"number": 0}]);
        let bound = Value::Array(
            (1..=GITHUB_WATCH_PR_DISCOVERY_SENTINEL)
                .map(|number| json!({"number": number}))
                .collect(),
        );
        for (label, value) in [
            ("malformed", malformed),
            ("duplicate", duplicate),
            ("zero", zero),
            ("bound", bound),
        ] {
            let producer_calls = Cell::new(0usize);
            let report = produce_github_watch_pr_intakes_with(
                |kind, limit, labels| {
                    assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                    assert_eq!(limit, GITHUB_WATCH_PR_DISCOVERY_SENTINEL);
                    assert!(labels.is_empty());
                    Ok(("github.com/acme/repo".to_string(), value))
                },
                |number| {
                    producer_calls.set(producer_calls.get().saturating_add(1));
                    synthetic_producer_report(number, PrIntakeProducerDisposition::Launched, None)
                },
            );
            assert_eq!(producer_calls.get(), 0, "{label} partially produced");
            assert!(report.producer_reports.is_empty(), "{label}: {report:#?}");
            assert!(match (label, report.discovery_refusal) {
                (
                    "malformed",
                    Some(InboxPrDiscoveryRefusalCause::MalformedProviderResponse { .. }),
                )
                | (
                    "duplicate",
                    Some(InboxPrDiscoveryRefusalCause::DuplicateNumber { number: 17 }),
                )
                | ("zero", Some(InboxPrDiscoveryRefusalCause::ZeroNumber { entry_index: 1 }))
                | (
                    "bound",
                    Some(InboxPrDiscoveryRefusalCause::BoundExceeded {
                        returned_count: GITHUB_WATCH_PR_DISCOVERY_SENTINEL,
                        maximum_processable: MAX_GITHUB_WATCH_PR_PRODUCERS,
                    }),
                ) => true,
                _ => false,
            });
        }

        let producer_calls = Cell::new(0usize);
        let provider_failure = produce_github_watch_pr_intakes_with(
            |kind, _, _| {
                assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                Err(provider_pr_discovery(
                    "provider unavailable at /home/private/token-123456789012345678901234567890 API_TOKEN=secret-value",
                ))
            },
            |number| {
                producer_calls.set(producer_calls.get().saturating_add(1));
                synthetic_producer_report(number, PrIntakeProducerDisposition::Launched, None)
            },
        );
        assert_eq!(producer_calls.get(), 0);
        assert!(matches!(
            provider_failure.discovery_refusal,
            Some(InboxPrDiscoveryRefusalCause::ProviderUnavailable { .. })
        ));
        let serialized = serde_json::to_string(&provider_failure).expect("serialize refusal");
        assert!(!serialized.contains("/home/private"));
        assert!(!serialized.contains("token-123456789012345678901234567890"));
        assert!(!serialized.contains("secret-value"));

        let private_key_failure = pr_discovery_refusal(provider_pr_discovery(
            "provider emitted -----BEGIN PRIVATE KEY----- private-material",
        ));
        let serialized =
            serde_json::to_string(&private_key_failure).expect("serialize private-key refusal");
        assert!(serialized.contains("redacted:private-key-material"));
        assert!(!serialized.contains("BEGIN PRIVATE KEY"));
        assert!(!serialized.contains("private-material"));
    }

    #[test]
    fn github_watch_empty_discovery_is_a_successful_zero_report_batch() {
        let producer_calls = Cell::new(0usize);
        let report = produce_github_watch_pr_intakes_with(
            |kind, limit, labels| {
                assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                assert_eq!(limit, GITHUB_WATCH_PR_DISCOVERY_SENTINEL);
                assert!(labels.is_empty());
                Ok(("github.com/acme/repo".to_string(), json!([])))
            },
            |number| {
                producer_calls.set(producer_calls.get().saturating_add(1));
                synthetic_producer_report(number, PrIntakeProducerDisposition::Launched, None)
            },
        );

        assert_eq!(producer_calls.get(), 0);
        assert_eq!(report.repository.as_deref(), Some("github.com/acme/repo"));
        assert_eq!(report.discovered_count, 0);
        assert_eq!(report.producer_report_count, 0);
        assert_eq!(report.producer_refusal_count, 0);
        assert!(report.success);
        assert!(report.discovery_refusal.is_none());
        assert!(report.producer_reports.is_empty());
    }

    #[test]
    fn github_watch_producer_continues_after_draft_and_other_refusals() {
        let produced = RefCell::new(Vec::new());
        let report = produce_github_watch_pr_intakes_with(
            |kind, _, _| {
                assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                Ok((
                    "github.com/acme/repo".to_string(),
                    json!([{"number": 3}, {"number": 1}, {"number": 2}]),
                ))
            },
            |number| {
                produced.borrow_mut().push(number);
                let refusal = match number {
                    1 => None,
                    2 => Some(PrIntakeProducerRefusalCause::IntakeRefused {
                        refusal: PrIntakeRefusalCause::DraftPullRequest,
                    }),
                    _ => Some(PrIntakeProducerRefusalCause::ProviderObservation {
                        classification: PrIntakeObservationFailureClass::ProviderUnavailable,
                        detail: "bounded refusal".to_string(),
                    }),
                };
                synthetic_producer_report(
                    number,
                    if refusal.is_some() {
                        PrIntakeProducerDisposition::Refused
                    } else {
                        PrIntakeProducerDisposition::Launched
                    },
                    refusal,
                )
            },
        );

        assert_eq!(produced.into_inner(), vec![1, 2, 3]);
        assert_eq!(report.producer_report_count, 3);
        assert_eq!(report.producer_refusal_count, 2);
        assert_eq!(report.producer_reports.len(), 3);
        assert!(!report.success);
    }

    #[test]
    fn github_watch_connected_iteration_discovers_all_then_runs_repair_only_once() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo, "main")
            .expect("initialize repository");
        Repository::open(&repo)
            .expect("open repository")
            .remote("origin", "https://github.com/acme/repo.git")
            .expect("create origin");

        let listed_count = DEFAULT_MAX_ITEMS.saturating_add(2);
        assert!(listed_count < GITHUB_WATCH_PR_DISCOVERY_SENTINEL);
        let listed = (1..=listed_count as u64)
            .rev()
            .map(|number| json!({"number": number}))
            .collect::<Vec<_>>();
        let produced = RefCell::new(Vec::new());
        let ordinary_calls = Cell::new(0usize);
        let ordinary_auditor_launches = Cell::new(0usize);
        let options = InboxRunOptions {
            repo: repo.clone(),
            run_id: RunId::new("watch-structural-no-double-launch").expect("run id"),
            github: true,
            permission_mode: Some(InboxPermissionMode::GithubRead),
            dry_run: true,
            max_items: Some(DEFAULT_MAX_ITEMS),
            codex_bin: None,
            machine_global: None,
        };
        let fixed_scan_items = vec![
            test_pr_item(1, false),
            test_pr_item(2, true),
            test_pr_item(3, true),
            test_pr_item(4, true),
            test_pr_item(5, true),
            test_issue_item(101),
        ];

        let report = run_github_watch_iteration_with(
            options,
            |options, kind, limit, labels| {
                assert_eq!(options.repo, repo);
                assert_eq!(kind, ExternalSourceObjectKind::PullRequest);
                assert_eq!(limit, GITHUB_WATCH_PR_DISCOVERY_SENTINEL);
                assert!(labels.is_empty());
                Ok(("github.com/acme/repo".to_string(), Value::Array(listed)))
            },
            |options, number| {
                assert_eq!(options.repo, repo);
                produced.borrow_mut().push(number);
                let (disposition, refusal) = match number {
                    1 => (PrIntakeProducerDisposition::Launched, None),
                    2 => (
                        PrIntakeProducerDisposition::Refused,
                        Some(PrIntakeProducerRefusalCause::ProviderObservation {
                            classification: PrIntakeObservationFailureClass::ProviderUnavailable,
                            detail: "bounded refusal".to_string(),
                        }),
                    ),
                    _ => (PrIntakeProducerDisposition::Replayed, None),
                };
                synthetic_producer_report(number, disposition, refusal)
            },
            |options, mut overrides| {
                ordinary_calls.set(ordinary_calls.get().saturating_add(1));
                assert_eq!(overrides.pr_dispatch_mode, InboxPrDispatchMode::RepairOnly);
                overrides.fixed_scan_items = Some(fixed_scan_items);
                let mut before_auditor_launch =
                    |_: &str, _: &InboxIndependentAuditorSelectionEvidence| {
                        ordinary_auditor_launches
                            .set(ordinary_auditor_launches.get().saturating_add(1));
                        Ok(())
                    };
                run_inbox_with_overrides(options, None, overrides, Some(&mut before_auditor_launch))
            },
        )
        .expect("watch iteration");

        assert_eq!(
            produced.into_inner(),
            (1..=listed_count as u64).collect::<Vec<_>>()
        );
        assert_eq!(ordinary_calls.get(), 1);
        assert_eq!(ordinary_auditor_launches.get(), 0);
        assert_eq!(report.selected_item_count, DEFAULT_MAX_ITEMS);
        assert!(report
            .item_reports
            .iter()
            .any(|item| item.item_id == "issue-101" && item.kind == InboxItemKind::Issue));
        assert!(report
            .item_reports
            .iter()
            .any(|item| item.item_id == "pr-2" && item.kind == InboxItemKind::PullRequest));
        assert!(!report
            .item_reports
            .iter()
            .any(|item| item.item_id == "pr-1"));
        assert_eq!(
            report
                .pr_intake_producer
                .as_ref()
                .map(|batch| batch.producer_refusal_count),
            Some(1)
        );
        assert_eq!(
            report
                .pr_intake_producer
                .as_ref()
                .into_iter()
                .flat_map(|batch| &batch.producer_reports)
                .filter(|producer| {
                    producer.disposition == PrIntakeProducerDisposition::Launched
                })
                .count(),
            1
        );

        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Inbox, &report.run_id)
            .expect("open connected watch run");
        let scan: Value =
            serde_json::from_slice(&reader.read("scan-report.json").expect("read scan report"))
                .expect("parse scan report");
        assert_eq!(scan["candidate_count"], listed_count - 1);
        assert_eq!(scan["selected_count"], DEFAULT_MAX_ITEMS);
        assert!(scan["items"]
            .as_array()
            .expect("scan items")
            .iter()
            .any(|item| { item["item_id"] == "pr-5" && item["skip_reason"] == "selection_limit" }));
        assert!(!scan["items"]
            .as_array()
            .expect("scan items")
            .iter()
            .any(|item| item["item_id"] == "pr-1"));
    }

    #[test]
    fn fake_watch_once_keeps_empty_producer_json_compatible_and_final_report_empty() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo, "main")
            .expect("initialize repository");

        let report = watch_inbox(InboxWatchOptions {
            repo: repo.clone(),
            poll_seconds: 1,
            once: true,
            github: false,
            permission_mode: None,
            dry_run: true,
            max_items: Some(1),
            codex_bin: None,
            machine_global: None,
        })
        .expect("fake watch once");

        assert_eq!(report.iteration_count, 1);
        assert_eq!(report.retained_iteration_count, 1);
        assert_eq!(report.dropped_iteration_count, 0);
        assert_eq!(report.runs.len(), 1);
        assert!(report.runs[0].pr_intake_producer.is_none());
        let watch_json = serde_json::to_value(&report).expect("serialize watch report");
        assert!(watch_json["runs"][0].get("pr_intake_producer").is_none());
        let final_report =
            collect_inbox_run(&repo, report.runs[0].run_id.clone()).expect("collect final report");
        assert!(final_report.get("pr_intake_producer").is_none());
    }

    #[test]
    fn watch_iteration_final_report_artifact_contains_every_producer_disposition() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        crate::worktree::WorktreeManager::init_repository(&repo, "main")
            .expect("initialize repository");
        let run_id = RunId::new("watch-producer-final-report").expect("run id");
        let mut batch = synthetic_batch(17);
        batch.producer_reports.push(synthetic_producer_report(
            18,
            PrIntakeProducerDisposition::Replayed,
            None,
        ));
        batch.discovered_count = 2;
        batch.producer_report_count = 2;

        let report = run_inbox_with_overrides(
            InboxRunOptions {
                repo: repo.clone(),
                run_id: run_id.clone(),
                github: false,
                permission_mode: None,
                dry_run: true,
                max_items: Some(1),
                codex_bin: None,
                machine_global: None,
            },
            None,
            InboxConfigOverrides {
                pr_dispatch_mode: InboxPrDispatchMode::RepairOnly,
                pr_intake_producer: Some(batch),
                ..InboxConfigOverrides::default()
            },
            None,
        )
        .expect("watch-augmented ordinary run");

        assert_eq!(
            report
                .pr_intake_producer
                .as_ref()
                .map(|batch| batch.producer_reports.len()),
            Some(2)
        );
        let final_report = collect_inbox_run(&repo, run_id).expect("collect final report");
        assert_eq!(
            final_report["pr_intake_producer"]["producer_reports"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            final_report["pr_intake_producer"]["producer_reports"][0]["disposition"],
            "refused"
        );
        assert_eq!(
            final_report["pr_intake_producer"]["producer_reports"][1]["disposition"],
            "replayed"
        );
    }

    #[test]
    fn watch_retention_drops_ordinary_and_producer_detail_together_beyond_cap() {
        let total = MAX_WATCH_RETAINED_ITERATIONS.saturating_add(7);
        let mut runs = VecDeque::new();
        for index in 0..total {
            let run_id =
                RunId::new(format!("watch-retention-{index}")).expect("bounded retention run id");
            retain_watch_run(
                &mut runs,
                synthetic_run(run_id, Some(synthetic_batch(index as u64 + 1))),
            );
        }

        assert_eq!(runs.len(), MAX_WATCH_RETAINED_ITERATIONS);
        let first = runs.front().expect("retained first run");
        assert_eq!(first.run_id.as_str(), "watch-retention-7");
        assert_eq!(
            first
                .pr_intake_producer
                .as_ref()
                .and_then(|batch| batch.producer_reports.first())
                .and_then(|report| report.number),
            Some(8)
        );
        let report = InboxWatchReport {
            repo: PathBuf::from("."),
            poll_seconds: 1,
            once: false,
            iteration_count: total,
            retained_iteration_count: runs.len(),
            dropped_iteration_count: total.saturating_sub(runs.len()),
            runs: runs.into_iter().collect(),
        };
        assert_eq!(report.dropped_iteration_count, 7);
        assert_eq!(report.iteration_count, MAX_WATCH_RETAINED_ITERATIONS + 7);
    }
}

#[cfg(test)]
mod tests;
