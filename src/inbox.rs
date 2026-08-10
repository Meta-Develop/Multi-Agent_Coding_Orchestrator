use crate::{
    artifacts::{
        self, ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily,
    },
    autopilot::{
        self, AutopilotForgeMode, AutopilotPlan, AutopilotPublishMode, AutopilotRunOptions,
        AutopilotTask, AutopilotValidationCommand,
    },
    live_claim::{self, LiveClock},
    llm::{RedactionSummary, Redactor},
    orchestrator::RunId,
    planning,
    publication::{self, ExternalSourceGuard, ExternalSourceObjectKind},
    review::{ReviewerConfig, ReviewerMode},
    safe_state::{stable_checksum, BoundedRegularReader, SafeRoot},
    semantic_coord::SemanticIntentStore,
    sync::normalize_repo_relative_path,
    sync_store::SyncStore,
};
use anyhow::{bail, Context, Result};
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

#[derive(Debug, Clone)]
pub struct InboxScanOptions {
    pub repo: PathBuf,
    pub github: bool,
    pub permission_mode: Option<InboxPermissionMode>,
    pub max_items: Option<usize>,
    pub action_policy_override: Option<InboxActionPolicy>,
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
}

#[derive(Debug, Clone)]
pub struct InboxWorkspaceWatchOptions {
    pub config: PathBuf,
    pub poll_seconds: u64,
    pub once: bool,
    pub dry_run: bool,
    pub codex_bin: Option<PathBuf>,
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
    pub runs: Vec<InboxRunReport>,
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
    let loaded = load_config_with_config_overrides(&repo, overrides)?;
    let permission_mode =
        effective_permission_mode(&loaded.config, options.github, options.permission_mode);
    let action_policy = effective_action_policy(loaded.config.action_policy, permission_mode);
    let github_enabled = permission_mode.uses_github_intake();
    let duplicate_keys = load_duplicate_keys(&repo)?;
    let source_repository =
        source_repository_binding_context(&repo, &loaded.config, github_enabled)?;
    let mut items = Vec::new();
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
            github_pr_candidates(&repo, &loaded.config, &source_repository)?
        } else {
            fake_pr_candidates(&loaded.config)
        };
        for pull_request in pull_requests {
            if !loaded.config.selection.include_draft_prs && pull_request.is_draft {
                continue;
            }
            items.push(pr_item(
                pull_request,
                &loaded.config,
                &source_repository,
                &duplicate_keys,
            )?);
        }
    }
    validate_count(items.len(), "inbox candidate items", MAX_GITHUB_ITEMS)?;
    items.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.item_id.cmp(&right.item_id))
    });
    apply_scan_decisions(&mut items, loaded.config.selection.max_items);

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
        next_action: if selected_count == 0 {
            "no safe non-duplicate inbox items selected".to_string()
        } else {
            "run maco inbox run with a stable run id".to_string()
        },
    })
}

pub fn run_inbox(_options: InboxRunOptions) -> Result<InboxRunReport> {
    Err(autopilot::effectful_autopilot_unavailable_error())
}

fn run_inbox_with_overrides(
    _options: InboxRunOptions,
    _overrides: InboxConfigOverrides,
) -> Result<InboxRunReport> {
    Err(autopilot::effectful_autopilot_unavailable_error())
}

#[allow(dead_code)]
fn run_inbox_with_overrides_disabled_legacy(
    options: InboxRunOptions,
    mut overrides: InboxConfigOverrides,
) -> Result<InboxRunReport> {
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        options.codex_bin.as_deref(),
    )?;
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
    if preflight_permission_mode.publishes_real_branch_or_pr()
        && preflight_action_policy != InboxActionPolicy::DryRun
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
    };
    let mut item_reports = Vec::new();
    for (zero_index, item) in selected_items.iter().enumerate() {
        let item_index = zero_index.saturating_add(1);
        let item_report = run_inbox_item(
            &mut artifact_writer,
            InboxItemRunInput {
                context: &item_context,
                item_index,
                item,
            },
        )?;
        item_reports.push(item_report);
    }

    let success = item_reports.iter().all(|report| report.success);
    let status = if action_policy == InboxActionPolicy::DryRun {
        InboxRunStatus::DryRun
    } else if !permission_mode.launches_autopilot() {
        InboxRunStatus::Planned
    } else if success {
        InboxRunStatus::Succeeded
    } else {
        InboxRunStatus::Failed
    };
    let report = InboxRunReport {
        version: INBOX_SCHEMA_VERSION,
        run_id: options.run_id,
        repo: public_repo_path(),
        action_policy,
        permission_mode,
        github_enabled: scan.github_enabled,
        success,
        status,
        refusals: Vec::new(),
        artifacts,
        selected_item_count: selected_items.len(),
        item_reports,
        auto_merge_performed: false,
        next_action: if success {
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

pub fn watch_inbox(_options: InboxWatchOptions) -> Result<InboxWatchReport> {
    Err(autopilot::effectful_autopilot_unavailable_error())
}

#[allow(dead_code)]
fn watch_inbox_disabled_legacy(options: InboxWatchOptions) -> Result<InboxWatchReport> {
    validate_poll_seconds(options.poll_seconds)?;
    validate_cli_source_options(
        options.github,
        options.permission_mode,
        options.max_items,
        options.codex_bin.as_deref(),
    )?;
    let repo = discover_repo_root(&options.repo)?;
    let mut runs = Vec::new();
    let mut iteration = 0usize;
    loop {
        iteration = iteration.saturating_add(1);
        let run_id =
            artifacts::generate_run_id(&repo, RunArtifactFamily::Inbox).with_context(|| {
                format!("failed to generate inbox watch run id for iteration {iteration}")
            })?;
        let report = run_inbox(InboxRunOptions {
            repo: repo.clone(),
            run_id,
            github: options.github,
            permission_mode: options.permission_mode,
            dry_run: options.dry_run,
            max_items: options.max_items,
            codex_bin: options.codex_bin.clone(),
        })?;
        runs.push(report);
        if options.once {
            break;
        }
        thread::sleep(Duration::from_secs(options.poll_seconds));
    }
    Ok(InboxWatchReport {
        repo: public_repo_path(),
        poll_seconds: options.poll_seconds,
        once: options.once,
        iteration_count: runs.len(),
        runs,
    })
}

pub fn scan_workspace_inbox(
    options: InboxWorkspaceScanOptions,
) -> Result<InboxWorkspaceScanReport> {
    let loaded = load_workspace_config(&options.config)?;
    let specs = workspace_repo_specs(&loaded)?;
    Ok(scan_workspace_specs(&loaded, &specs))
}

pub fn run_workspace_inbox(_options: InboxWorkspaceRunOptions) -> Result<InboxWorkspaceRunReport> {
    Err(autopilot::effectful_autopilot_unavailable_error())
}

#[allow(dead_code)]
fn run_workspace_inbox_disabled_legacy(
    options: InboxWorkspaceRunOptions,
) -> Result<InboxWorkspaceRunReport> {
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
            },
            workspace_overrides_for_repo(&spec),
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
        auto_merge_performed: false,
        auto_approval_performed: false,
        repositories,
        next_action: workspace_next_action(success, loaded.config.strict, "workspace run"),
    };
    write_json_file(&run_dir.join("final-report.json"), &report)?;
    Ok(report)
}

pub fn watch_workspace_inbox(
    _options: InboxWorkspaceWatchOptions,
) -> Result<InboxWorkspaceWatchReport> {
    Err(autopilot::effectful_autopilot_unavailable_error())
}

#[allow(dead_code)]
fn watch_workspace_inbox_disabled_legacy(
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
        })?;
        runs.push(report);
        if options.once {
            break;
        }
        thread::sleep(Duration::from_secs(options.poll_seconds));
    }
    let success = runs.iter().all(|run| run.success);
    Ok(InboxWorkspaceWatchReport {
        version: INBOX_SCHEMA_VERSION,
        config_path: public_config_path,
        poll_seconds: options.poll_seconds,
        once: options.once,
        success,
        iteration_count: runs.len(),
        auto_merge_performed: false,
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
}

struct InboxItemRunInput<'a> {
    context: &'a InboxItemRunContext<'a>,
    item_index: usize,
    item: &'a InboxItem,
}

fn run_inbox_item(
    writer: &mut ArtifactRunWriter,
    input: InboxItemRunInput<'_>,
) -> Result<InboxItemRunReport> {
    let context = input.context;
    let item_index = input.item_index;
    let item = input.item;
    let repo = context.repo;
    let run_id = context.run_id;
    let action_policy = context.action_policy;
    let permission_mode = context.permission_mode;
    let config = context.config;
    revalidate_inbox_item_source(repo, item)
        .context("inbox source changed before item processing started")?;
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
        return Ok(InboxItemRunReport {
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
            next_action: if planned_only {
                "review the plan; this permission mode does not launch work".to_string()
            } else {
                "review the dry-run plan; no work was launched".to_string()
            },
        });
    }

    revalidate_inbox_item_source(repo, item)
        .context("inbox source changed immediately before local work started")?;
    let autopilot_result = autopilot::run_autopilot_plan_file(AutopilotRunOptions {
        repo: repo.to_path_buf(),
        plan_file: plan_path.clone(),
        run_id: autopilot_run_id.clone(),
        codex_bin: context.codex_bin.clone(),
        reviewer_command: None,
        allow_dirty_primary: false,
        max_child_dispatches: None,
        cancellation: None,
    });
    let (autopilot_success, autopilot_message) = match autopilot_result {
        Ok(report) => {
            let success = report.success;
            let message = report.next_action.clone();
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

    let github_report = github_action_for_item(
        repo,
        config,
        action_policy,
        permission_mode,
        item,
        autopilot_success,
        autopilot_message,
    );
    write_private_artifact_json(writer, &github_report_relative, &github_report)?;
    let success = autopilot_success && github_report.success;
    Ok(InboxItemRunReport {
        item_index,
        item_id: item.item_id.clone(),
        kind: item.kind,
        title: item.title.clone(),
        success,
        status: if success {
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
        next_action: if success {
            "review the generated autopilot and GitHub reports".to_string()
        } else {
            "inspect the item autopilot and GitHub reports before retrying".to_string()
        },
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
            let path_reasons = pr_path_reasons(pr, &failing_checks);
            let validation_expectation = pr_validation_expectation(&failing_checks);
            format!(
                "React to GitHub PR #{}.\nURL: {}\nHead: {}\nBase: {}\n\nChanged files:\n{}\n\nTarget paths and reasons:\n{}\n\nChecks:\n{}\n\nReview feedback:\n{}\n\nValidation expectation:\n{}\n\nRepair failing checks or requested changes in isolated autopilot work. Do not merge automatically.",
                pr.number,
                pr.url.as_deref().unwrap_or("unknown"),
                pr.head_ref.as_deref().unwrap_or("unknown"),
                pr.base_ref.as_deref().unwrap_or("unknown"),
                path_list(&pr.changed_files),
                path_reasons,
                if checks.is_empty() { "no failing check metadata" } else { &checks },
                if reviews.is_empty() { "no review summaries" } else { &reviews },
                validation_expectation
            )
        }
        _ => format!(
            "React to inbox item {}. Do not merge automatically.",
            item.item_id
        ),
    }
}

fn pr_path_reasons(pr: &GithubPrCandidate, failing_checks: &[String]) -> String {
    let check_reason = if failing_checks.is_empty() {
        "review feedback requested changes".to_string()
    } else {
        format!(
            "review feedback requested changes; failing checks: {}",
            failing_checks.join(", ")
        )
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

fn pr_validation_expectation(failing_checks: &[String]) -> String {
    if failing_checks.is_empty() {
        "preserve configured validation and confirm requested review changes are addressed"
            .to_string()
    } else {
        format!(
            "run or preserve configured validation and address failing check context: {}",
            failing_checks.join(", ")
        )
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
    let needs_reaction = raw.review_feedback.requested_changes
        || raw
            .checks
            .iter()
            .any(|check| check_failed(check.conclusion.as_deref(), check.status.as_deref()));
    let mut skip_reason = None;
    if !privacy.safe {
        skip_reason = Some("privacy_refused".to_string());
    } else if duplicate.duplicate {
        skip_reason = Some("duplicate".to_string());
    } else if !needs_reaction {
        skip_reason = Some("no_requested_changes_or_failing_checks".to_string());
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
            changed_files: normalize_or_default(raw.changed_files, config)?,
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
        changed_files: files_from_value(object.get("files"))?,
        checks: checks_from_value(object.get("statusCheckRollup"))?,
        review_feedback: review_feedback_from_value(value)?,
    })
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

fn non_runtime_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|path| !is_ignored_runtime_path(path))
        .cloned()
        .collect()
}

fn inbox_detail_paths(details: &[InboxLockRefusalDetail]) -> Vec<PathBuf> {
    details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn dirty_primary_paths(repo_path: &Path) -> Result<Vec<PathBuf>> {
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect primary worktree status")?;
    let mut paths = Vec::new();
    for entry in statuses.iter() {
        let path = PathBuf::from(
            entry
                .path()
                .context("primary worktree status path is not valid UTF-8")?,
        );
        if !is_ignored_runtime_path(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn load_config(repo: &Path) -> Result<LoadedConfig> {
    let root = SafeRoot::open_existing(repo).context("failed to bind inbox repository root")?;
    let (config, config_path) = if root.direct_child_exists(CONFIG_FILE)? {
        let contents = BoundedRegularReader::read_direct(&root, CONFIG_FILE, MAX_CONFIG_BYTES)
            .context("failed to read bounded no-follow inbox config maco-inbox.json")?;
        root.verify()
            .context("inbox repository root changed during config read")?;
        let contents = String::from_utf8(contents).context("inbox config is not valid UTF-8")?;
        (
            serde_json::from_str::<InboxConfig>(&contents)
                .context("failed to parse inbox config maco-inbox.json")?,
            Some(PathBuf::from(CONFIG_FILE)),
        )
    } else {
        (InboxConfig::default(), None)
    };
    Ok(LoadedConfig {
        config: validate_config(config)?,
        path: config_path,
    })
}

fn load_config_with_config_overrides(
    repo: &Path,
    overrides: InboxConfigOverrides,
) -> Result<LoadedConfig> {
    let mut loaded = load_config(repo)?;
    if let Some(max_items) = overrides.max_items {
        loaded.config.selection.max_items = max_items;
    }
    if let Some(action_policy) = overrides.action_policy {
        loaded.config.action_policy = action_policy;
    }
    if let Some(labels) = overrides.labels {
        loaded.config.selection.labels = labels;
    }
    if let Some(issues) = overrides.issues {
        loaded.config.selection.issues = issues;
    }
    if let Some(pull_requests) = overrides.pull_requests {
        loaded.config.selection.pull_requests = pull_requests;
    }
    loaded.config = validate_config(loaded.config)?;
    Ok(loaded)
}

fn validate_config(mut config: InboxConfig) -> Result<InboxConfig> {
    validate_schema_version("inbox config", config.version)?;
    validate_schema_version("inbox repository config", config.repository.version)?;
    validate_schema_version("inbox selection config", config.selection.version)?;
    validate_schema_version("inbox privacy config", config.privacy.version)?;
    validate_repository_config(&mut config.repository)?;
    validate_item_limit(config.selection.max_items, "inbox selection max_items")?;
    if !config.selection.issues && !config.selection.pull_requests {
        bail!("inbox selection must enable issues or pull_requests");
    }
    config.selection.labels = validate_labels(
        std::mem::take(&mut config.selection.labels),
        "inbox selection labels",
    )?;
    if config.action_policy == InboxActionPolicy::Github
        && config.permission_mode == Some(InboxPermissionMode::Fake)
    {
        bail!("inbox action_policy github conflicts with permission_mode fake");
    }
    if config.max_repair_attempts > MAX_REPAIR_ATTEMPTS {
        bail!(
            "inbox max_repair_attempts exceeds its {} attempt limit",
            MAX_REPAIR_ATTEMPTS
        );
    }
    validate_optional_timeout(config.timeout_seconds, "inbox timeout_seconds")?;
    if config.default_validation_commands.len() > MAX_VALIDATION_COMMANDS {
        bail!(
            "inbox default_validation_commands exceeds its {} command limit",
            MAX_VALIDATION_COMMANDS
        );
    }
    config.privacy.blocked_terms = validate_bounded_string_set(
        std::mem::take(&mut config.privacy.blocked_terms),
        "inbox privacy blocked_terms",
        MAX_PRIVACY_TERMS,
        MAX_PRIVACY_TERM_BYTES,
    )?;
    if config.privacy.max_body_chars == 0 || config.privacy.max_body_chars > MAX_BODY_LIMIT {
        bail!(
            "inbox privacy max_body_chars must be between 1 and {}",
            MAX_BODY_LIMIT
        );
    }
    if config.default_assigned_paths.len() > MAX_ASSIGNED_PATHS {
        bail!(
            "inbox default_assigned_paths exceeds its {} path limit",
            MAX_ASSIGNED_PATHS
        );
    }
    config.default_assigned_paths =
        normalize_or_default(std::mem::take(&mut config.default_assigned_paths), &config)?;
    for (index, command) in config.default_validation_commands.iter_mut().enumerate() {
        validate_schema_version(
            &format!("default validation command {}", index + 1),
            command.version,
        )?;
        command.command = command.command.trim().to_string();
        validate_bounded_text(
            &command.command,
            &format!("default validation command {} command", index + 1),
            MAX_VALIDATION_COMMAND_BYTES,
            false,
        )?;
        if let Some(name) = command.name.as_mut() {
            *name = name.trim().to_string();
            validate_bounded_text(
                name,
                &format!("default validation command {} name", index + 1),
                MAX_VALIDATION_NAME_BYTES,
                false,
            )?;
        }
        validate_optional_timeout(
            command.timeout_seconds,
            &format!("default validation command {} timeout_seconds", index + 1),
        )?;
        if command.timeout_seconds.is_none() {
            command.timeout_seconds = config.timeout_seconds;
        }
    }
    if let Some(codex_bin) = &config.codex_bin {
        validate_path_text(codex_bin, "inbox codex_bin", MAX_CODEX_PATH_BYTES)?;
    }
    validate_serialized_config_size(&config, "inbox config")?;
    Ok(config)
}

fn normalize_or_default(paths: Vec<PathBuf>, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let fallback = if config.default_assigned_paths.is_empty() {
        default_assigned_paths()
    } else {
        config.default_assigned_paths.clone()
    };
    let source = if paths.is_empty() { fallback } else { paths };
    if source.len() > MAX_ASSIGNED_PATHS {
        bail!(
            "inbox assigned paths exceed the {} path limit",
            MAX_ASSIGNED_PATHS
        );
    }
    let normalized = source
        .into_iter()
        .map(|path| -> Result<PathBuf> {
            validate_path_text(&path, "inbox assigned path", MAX_CONFIG_PATH_BYTES)?;
            Ok(normalize_repo_relative_path(&path)?)
        })
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(normalized.into_iter().collect())
}

fn assigned_paths_for_item(item: &InboxItem, config: &InboxConfig) -> Result<Vec<PathBuf>> {
    item.source_snapshot.validate()?;
    let (number, updated_at) = match (item.kind, &item.issue, &item.pull_request) {
        (InboxItemKind::Issue, Some(issue), None) => (issue.number, issue.updated_at.as_deref()),
        (InboxItemKind::PullRequest, None, Some(pull_request)) => {
            (pull_request.number, pull_request.updated_at.as_deref())
        }
        _ => bail!("inbox item kind does not match its issue/PR payload"),
    };
    if item.source_snapshot.kind() != item.kind
        || item.source_snapshot.source_key() != item.source_key
        || number != item.source_snapshot.number()
        || updated_at != Some(item.source_snapshot.updated_at())
    {
        bail!("inbox item source snapshot does not match the item identity");
    }
    match (&item.issue, &item.pull_request) {
        (Some(issue), _) => normalize_or_default(issue.assigned_paths.clone(), config),
        (_, Some(pr)) => normalize_or_default(pr.changed_files.clone(), config),
        _ => normalize_or_default(Vec::new(), config),
    }
}

fn selected_target_paths(items: &[InboxItem], config: &InboxConfig) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for item in items.iter().filter(|item| item.selected) {
        paths.extend(assigned_paths_for_item(item, config)?);
    }
    Ok(paths.into_iter().collect())
}

fn privacy_scan(body: &str, policy: &InboxPrivacyPolicy) -> PrivacyScanResult {
    let redacted = Redactor::new().redact(body);
    let reasons = privacy_reasons(body, &redacted, policy);
    let public_body = sanitize_redacted_public_text(body, &redacted.text);
    let summary = summarize_text(&public_body, policy.max_body_chars);
    PrivacyScanResult {
        safe: reasons.is_empty() || policy.allow_private_bodies,
        reasons,
        redactions: redacted.summary,
        body_summary: summary.text,
        body_truncated: summary.truncated,
    }
}

fn extend_privacy_reasons(
    privacy: &mut PrivacyScanResult,
    label: &str,
    text: &str,
    policy: &InboxPrivacyPolicy,
) {
    let redacted = Redactor::new().redact(text);
    let mut field_reasons = privacy_reasons(text, &redacted, policy)
        .into_iter()
        .map(|reason| format!("{label}_{reason}"))
        .collect::<Vec<_>>();
    if field_reasons.is_empty() {
        return;
    }
    privacy.redactions.merge(redacted.summary);
    privacy.reasons.append(&mut field_reasons);
    privacy.reasons.sort();
    privacy.reasons.dedup();
    privacy.safe = privacy.reasons.is_empty() || policy.allow_private_bodies;
}

fn privacy_reasons(
    text: &str,
    redacted: &crate::llm::RedactedText,
    policy: &InboxPrivacyPolicy,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if redacted.summary.total_replacements > 0 || contains_token_like_word(text) {
        reasons.push("secret_like_content_redacted".to_string());
    }
    if contains_private_key_material(text) {
        reasons.push("private_key_material".to_string());
    }
    if contains_local_absolute_path(text) {
        reasons.push("local_absolute_path".to_string());
    }
    let lower = text.to_ascii_lowercase();
    for term in &policy.blocked_terms {
        let term = term.trim();
        if !term.is_empty() && lower.contains(&term.to_ascii_lowercase()) {
            reasons.push(format!("blocked_term:{term}"));
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn duplicate_result(key: &str, duplicates: &BTreeMap<String, String>) -> DuplicateDetectionResult {
    let matched_run_id = duplicates.get(key).cloned();
    DuplicateDetectionResult {
        duplicate: matched_run_id.is_some(),
        key: key.to_string(),
        reason: matched_run_id
            .as_ref()
            .map(|run_id| format!("already selected by inbox run {run_id}")),
        matched_run_id,
    }
}

fn load_duplicate_keys(repo: &Path) -> Result<BTreeMap<String, String>> {
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
                    "finalized inbox run '{}' changed during duplicate scan",
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
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(key) = item["source_key"].as_str() {
                    duplicates
                        .entry(key.to_string())
                        .or_insert(run.run_id.clone());
                }
            }
        }
    }
    Ok(duplicates)
}

#[cfg(test)]
fn parse_gh_json_bytes(bytes: Vec<u8>, label: &str) -> Result<Value> {
    if bytes.len() > GH_OUTPUT_LIMIT {
        bail!("{label} exceeded its {GH_OUTPUT_LIMIT} byte JSON limit");
    }
    let text =
        String::from_utf8(bytes).with_context(|| format!("{label} returned non-UTF-8 JSON"))?;
    let bounded = summarize_text(&text, GH_OUTPUT_LIMIT);
    if bounded.truncated {
        bail!("{label} exceeded its {GH_OUTPUT_LIMIT} character JSON limit");
    }
    serde_json::from_str(&bounded.text).with_context(|| format!("{label} returned invalid JSON"))
}

fn artifact_status(reader: &ArtifactRunReader) -> InboxArtifactStatus {
    let mut item_plan_count = 0usize;
    let mut item_autopilot_report_count = 0usize;
    let mut item_github_report_count = 0usize;
    let contains = |path: &str| {
        reader
            .finalization()
            .files
            .iter()
            .any(|record| record.path == Path::new(path))
    };
    for record in &reader.finalization().files {
        let Some(name) = record.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("item-") && name.ends_with("-plan.json") {
            item_plan_count = item_plan_count.saturating_add(1);
        } else if name.starts_with("item-") && name.ends_with("-autopilot-report.json") {
            item_autopilot_report_count = item_autopilot_report_count.saturating_add(1);
        } else if name.starts_with("item-") && name.ends_with("-github-report.json") {
            item_github_report_count = item_github_report_count.saturating_add(1);
        }
    }
    InboxArtifactStatus {
        scan_report: contains("scan-report.json"),
        selected_items: contains("selected-items.json"),
        final_report: contains("final-report.json"),
        item_plan_count,
        item_autopilot_report_count,
        item_github_report_count,
    }
}

enum ArtifactRunState {
    Missing,
    Active(PathBuf),
    Finalized(Box<ArtifactRunReader>),
}

fn inbox_artifact_run_state(repo: &Path, run_id: &RunId) -> Result<ArtifactRunState> {
    let Some(run_dir) =
        verified_unfinalized_run_dir(repo, &[".maco", "inbox", "runs", run_id.as_str()])?
    else {
        return Ok(ArtifactRunState::Missing);
    };
    if !known_regular_file_exists(&run_dir, ARTIFACT_FINAL_MARKER)? {
        return Ok(ArtifactRunState::Active(run_dir));
    }
    let reader =
        ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, run_id).with_context(|| {
            format!(
                "inbox run '{}' has corrupt or unverifiable finalized artifacts",
                run_id.as_str()
            )
        })?;
    Ok(ArtifactRunState::Finalized(Box::new(reader)))
}

fn verified_unfinalized_run_dir(repo: &Path, components: &[&str]) -> Result<Option<PathBuf>> {
    let mut current = repo.to_path_buf();
    for component in components {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect artifact directory {}", current.display())
                })
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "artifact directory is not a direct non-link directory: {}",
                current.display()
            );
        }
    }
    Ok(Some(current))
}

fn known_regular_file_exists(run_dir: &Path, name: &str) -> Result<bool> {
    let path = run_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "artifact entry is not a direct regular file: {}",
                path.display()
            )
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect artifact file {}", path.display())),
    }
}

fn empty_artifact_status() -> InboxArtifactStatus {
    InboxArtifactStatus {
        scan_report: false,
        selected_items: false,
        final_report: false,
        item_plan_count: 0,
        item_autopilot_report_count: 0,
        item_github_report_count: 0,
    }
}

fn unfinalized_artifact_status(run_dir: &Path) -> Result<InboxArtifactStatus> {
    let status = InboxArtifactStatus {
        scan_report: known_regular_file_exists(run_dir, "scan-report.json")?,
        selected_items: known_regular_file_exists(run_dir, "selected-items.json")?,
        final_report: known_regular_file_exists(run_dir, "final-report.json")?,
        // Per-item names are not a bounded known set until the authenticated
        // manifest exists. Do not enumerate an unfinalized child-writable tree.
        item_plan_count: 0,
        item_autopilot_report_count: 0,
        item_github_report_count: 0,
    };
    if known_regular_file_exists(run_dir, ARTIFACT_FINAL_MARKER)? {
        bail!("artifact run finalized while active status was being inspected; retry status");
    }
    Ok(status)
}

fn run_artifacts(run_id: &RunId) -> InboxRunArtifacts {
    InboxRunArtifacts {
        run_dir: public_run_dir().join(run_id.as_str()),
        scan_report: public_item_path(run_id, "scan-report.json"),
        selected_items: public_item_path(run_id, "selected-items.json"),
        final_report: public_item_path(run_id, "final-report.json"),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish {}", path.display()))
}

fn write_private_artifact_json<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: impl AsRef<Path>,
    value: &T,
) -> Result<()> {
    writer.write_json(relative, value, ArtifactFileDisposition::PrivateEvidence)?;
    Ok(())
}

fn read_artifact_json(reader: &ArtifactRunReader, relative: impl AsRef<Path>) -> Result<Value> {
    let relative = relative.as_ref();
    let contents = reader.read(relative)?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse finalized artifact {}", relative.display()))
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn public_run_dir() -> PathBuf {
    PathBuf::from(".maco").join("inbox").join("runs")
}

fn public_repo_path() -> PathBuf {
    PathBuf::from(".")
}

fn public_item_path(run_id: &RunId, file_name: &str) -> PathBuf {
    public_run_dir().join(run_id.as_str()).join(file_name)
}

fn effective_permission_mode(
    config: &InboxConfig,
    github: bool,
    override_mode: Option<InboxPermissionMode>,
) -> InboxPermissionMode {
    if let Some(mode) = override_mode {
        mode
    } else if github {
        InboxPermissionMode::GithubFull
    } else if let Some(mode) = config.permission_mode {
        mode
    } else if config.action_policy == InboxActionPolicy::Github {
        InboxPermissionMode::GithubFull
    } else {
        InboxPermissionMode::Fake
    }
}

fn effective_action_policy(
    configured: InboxActionPolicy,
    permission_mode: InboxPermissionMode,
) -> InboxActionPolicy {
    if configured == InboxActionPolicy::DryRun {
        InboxActionPolicy::DryRun
    } else if permission_mode.uses_github_intake() {
        InboxActionPolicy::Github
    } else {
        InboxActionPolicy::Fake
    }
}

fn permission_mode_label(mode: InboxPermissionMode) -> &'static str {
    match mode {
        InboxPermissionMode::Fake => "fake",
        InboxPermissionMode::GithubRead => "github_read",
        InboxPermissionMode::GithubLocal => "github_local",
        InboxPermissionMode::GithubGit => "github_git",
        InboxPermissionMode::GithubPr => "github_pr",
        InboxPermissionMode::GithubFull => "github_full",
    }
}

fn is_ignored_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
}

fn validate_schema_version(label: &str, version: u32) -> Result<()> {
    if version != INBOX_SCHEMA_VERSION {
        bail!(
            "{label} version must be {}; got {version}",
            INBOX_SCHEMA_VERSION
        );
    }
    Ok(())
}

fn validate_count(count: usize, label: &str, limit: usize) -> Result<()> {
    if count > limit {
        bail!("{label} exceeds its {limit} item limit");
    }
    Ok(())
}

fn validate_item_limit(value: usize, label: &str) -> Result<()> {
    if value == 0 || value > MAX_SELECTION_ITEMS {
        bail!("{label} must be between 1 and {}", MAX_SELECTION_ITEMS);
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty()) || value.len() > max_bytes {
        bail!(
            "{label} must contain between {} and {max_bytes} bytes",
            usize::from(!allow_empty)
        );
    }
    if value.chars().any(char::is_control) {
        bail!("{label} must not contain control characters");
    }
    Ok(())
}

fn validate_multiline_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.len() > max_bytes {
        bail!("{label} exceeds its {max_bytes} byte limit");
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        bail!("{label} contains an unsupported control character");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    validate_bounded_text(value, label, max_bytes, false)?;
    let mut characters = value.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        bail!(
            "{label} must start with an ASCII letter or digit and contain only letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn validate_path_text(path: &Path, label: &str, max_bytes: usize) -> Result<()> {
    let value = path
        .to_str()
        .with_context(|| format!("{label} must be valid UTF-8"))?;
    validate_bounded_text(value, label, max_bytes, false)
}

fn validate_labels(values: Vec<String>, label: &str) -> Result<Vec<String>> {
    validate_bounded_string_set(values, label, MAX_LABELS, MAX_LABEL_BYTES)
}

fn validate_bounded_string_set(
    values: Vec<String>,
    label: &str,
    max_count: usize,
    max_bytes: usize,
) -> Result<Vec<String>> {
    validate_count(values.len(), label, max_count)?;
    let mut normalized = BTreeSet::new();
    for (index, value) in values.into_iter().enumerate() {
        let value = value.trim().to_string();
        validate_bounded_text(
            &value,
            &format!("{label} item {}", index + 1),
            max_bytes,
            false,
        )?;
        normalized.insert(value);
    }
    Ok(normalized.into_iter().collect())
}

fn validate_optional_timeout(value: Option<u64>, label: &str) -> Result<()> {
    if value.is_some_and(|seconds| seconds == 0 || seconds > MAX_TIMEOUT_SECONDS) {
        bail!(
            "{label} must be between 1 and {} seconds when set",
            MAX_TIMEOUT_SECONDS
        );
    }
    Ok(())
}

fn validate_poll_seconds(value: u64) -> Result<()> {
    if value == 0 || value > MAX_TIMEOUT_SECONDS {
        bail!("poll-seconds must be between 1 and {}", MAX_TIMEOUT_SECONDS);
    }
    Ok(())
}

fn validate_serialized_config_size<T: Serialize>(value: &T, label: &str) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).with_context(|| format!("failed to serialize {label}"))?;
    if bytes.len() > MAX_CONFIG_SERIALIZED_BYTES {
        bail!(
            "{label} exceeds its {} byte serialized limit",
            MAX_CONFIG_SERIALIZED_BYTES
        );
    }
    Ok(())
}

fn validate_repository_config(repository: &mut InboxRepositoryConfig) -> Result<()> {
    match (&mut repository.owner, &mut repository.name) {
        (Some(owner), Some(name)) => {
            *owner = owner.trim().to_ascii_lowercase();
            *name = name.trim().to_ascii_lowercase();
            validate_github_owner(owner)?;
            validate_github_repository_name(name)?;
        }
        (None, None) => {}
        _ => bail!("inbox repository owner and name must be configured together"),
    }
    if let Some(branch) = repository.default_branch.as_mut() {
        *branch = branch.trim().to_string();
        validate_git_branch(branch)?;
    }
    Ok(())
}

fn validate_github_owner(owner: &str) -> Result<()> {
    validate_bounded_text(owner, "GitHub repository owner", 39, false)?;
    if owner.starts_with('-')
        || owner.ends_with('-')
        || !owner
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        bail!("GitHub repository owner is not canonical");
    }
    Ok(())
}

fn validate_github_repository_name(name: &str) -> Result<()> {
    validate_bounded_text(name, "GitHub repository name", 100, false)?;
    if matches!(name, "." | "..")
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        bail!("GitHub repository name is not canonical");
    }
    Ok(())
}

fn validate_git_branch(branch: &str) -> Result<()> {
    validate_bounded_text(branch, "inbox default_branch", 255, false)?;
    if branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch
            .chars()
            .any(|character| matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
        || branch.split('/').any(|component| {
            component.is_empty() || component.starts_with('.') || component.ends_with(".lock")
        })
    {
        bail!("inbox default_branch is not a canonical Git ref name");
    }
    Ok(())
}

fn validate_repository_selector(selector: &str) -> Result<()> {
    if selector == "." {
        return Ok(());
    }
    validate_bounded_text(selector, "inbox repository selector", 256, false)?;
    let mut parts = selector.split('/');
    let owner = parts
        .next()
        .context("repository selector requires an owner")?;
    let name = parts
        .next()
        .context("repository selector requires a name")?;
    if parts.next().is_some() {
        bail!("inbox repository selector must contain exactly owner/name");
    }
    validate_github_owner(owner)?;
    validate_github_repository_name(name)
}

fn validate_git_oid(oid: &str, label: &str) -> Result<()> {
    if !matches!(oid.len(), 40 | 64)
        || !oid
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        bail!("{label} must be a canonical lowercase 40- or 64-hex Git OID");
    }
    Ok(())
}

fn validate_timestamp(timestamp: &str) -> Result<()> {
    validate_bounded_text(
        timestamp,
        "inbox source updatedAt",
        MAX_TIMESTAMP_BYTES,
        false,
    )?;
    let bytes = timestamp.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
    {
        bail!("inbox source updatedAt must be a canonical RFC3339 timestamp");
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    if !matches!(number(5..7), Some(1..=12))
        || !matches!(number(8..10), Some(1..=31))
        || !matches!(number(11..13), Some(0..=23))
        || !matches!(number(14..16), Some(0..=59))
        || !matches!(number(17..19), Some(0..=59))
        || !timestamp.ends_with('Z')
        || (bytes.len() > 20
            && (bytes.get(19) != Some(&b'.')
                || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
    {
        bail!("inbox source updatedAt must be a canonical UTC RFC3339 timestamp");
    }
    Ok(())
}

fn source_key(kind: InboxItemKind, number: u64) -> String {
    match kind {
        InboxItemKind::Issue => format!("github_issue:{number}"),
        InboxItemKind::PullRequest => format!("github_pr:{number}"),
    }
}

fn source_repository_binding_context(
    repo_path: &Path,
    config: &InboxConfig,
    require_remote_match: bool,
) -> Result<SourceRepositoryBindingContext> {
    let repo = Repository::open(repo_path).context("failed to bind inbox source repository")?;
    let common = SafeRoot::open_existing(repo.commondir())
        .context("failed to bind inbox source repository common directory")?;
    let identity = publication::external_source_repository_identity(
        common.identity().device,
        common.identity().file,
    );
    let origin_binding = match repo.find_remote("origin") {
        Ok(remote) => {
            let url = remote
                .url()
                .context("origin remote URL is not valid UTF-8")?;
            publication::canonical_github_source_repository(url).ok()
        }
        Err(error) if error.code() == git2::ErrorCode::NotFound => None,
        Err(error) => return Err(error).context("failed to inspect origin remote"),
    };
    let configured_selector = match (&config.repository.owner, &config.repository.name) {
        (Some(owner), Some(name)) => Some(format!("{owner}/{name}")),
        _ => None,
    };
    if require_remote_match {
        let (_, observed) = origin_binding
            .as_ref()
            .context("GitHub intake requires a canonical HTTPS origin remote")?;
        if let Some(configured) = &configured_selector {
            let observed_owner_name = observed
                .split_once('/')
                .and_then(|(_, remainder)| remainder.split_once('/'))
                .map(|(owner, name)| format!("{owner}/{name}"))
                .context("canonical GitHub origin selector omitted owner/name")?;
            if !configured.eq_ignore_ascii_case(&observed_owner_name) {
                bail!(
                    "configured GitHub repository does not match the execution repository origin"
                );
            }
        }
    }
    let (host, selector) = match origin_binding {
        Some(binding) => binding,
        None => (
            "fake".to_string(),
            configured_selector.unwrap_or_else(|| ".".to_string()),
        ),
    };
    if host == "fake" {
        validate_repository_selector(&selector)?;
    } else {
        publication::validate_github_source_repository_binding(&host, &selector)?;
    }
    common.verify()?;
    Ok(SourceRepositoryBindingContext {
        host,
        selector,
        identity,
    })
}

fn validate_candidate_repository_url(
    provider: InboxSourceProvider,
    url: Option<&str>,
    repository_selector: &str,
    kind: InboxItemKind,
    number: u64,
) -> Result<()> {
    if provider == InboxSourceProvider::Fake {
        return Ok(());
    }
    let url = url.context("GitHub candidate requires a canonical URL")?;
    let expected_kind = match kind {
        InboxItemKind::Issue => "issues",
        InboxItemKind::PullRequest => "pull",
    };
    let expected_url = format!("https://{repository_selector}/{expected_kind}/{number}");
    if url != expected_url {
        bail!("GitHub candidate URL does not match its exact host, repository, kind, and number");
    }
    Ok(())
}

fn canonical_or_lexical_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path).with_context(|| {
            format!(
                "failed to resolve workspace repository path {}",
                path.display()
            )
        });
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("workspace repository path escapes its filesystem root");
                }
            }
        }
    }
    Ok(normalized)
}

fn validate_cli_source_options(
    github: bool,
    permission_mode: Option<InboxPermissionMode>,
    max_items: Option<usize>,
    codex_bin: Option<&Path>,
) -> Result<()> {
    if github && permission_mode == Some(InboxPermissionMode::Fake) {
        bail!("--github conflicts with --permission fake");
    }
    if let Some(max_items) = max_items {
        validate_item_limit(max_items, "inbox --max-items")?;
    }
    if let Some(codex_bin) = codex_bin {
        validate_path_text(codex_bin, "inbox --codex-bin", MAX_CODEX_PATH_BYTES)?;
    }
    Ok(())
}

fn required_input_string(value: Option<&Value>, label: &str, max_bytes: usize) -> Result<String> {
    let value = value
        .and_then(Value::as_str)
        .with_context(|| format!("{label} must be a string"))?;
    validate_bounded_text(value, label, max_bytes, false)?;
    Ok(value.to_string())
}

fn optional_input_string(
    value: Option<&Value>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .with_context(|| format!("{label} must be a string or null"))?;
    validate_bounded_text(value, label, max_bytes, false)?;
    Ok(Some(value.to_string()))
}

fn optional_input_body(
    value: Option<&Value>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .with_context(|| format!("{label} must be a string or null"))?;
    validate_multiline_text(value, label, max_bytes)?;
    Ok(Some(value.to_string()))
}

fn optional_input_array<'a>(
    value: Option<&'a Value>,
    label: &str,
    max_count: usize,
) -> Result<&'a [Value]> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(&[]);
    };
    let values = value
        .as_array()
        .with_context(|| format!("{label} must be an array or null"))?;
    validate_count(values.len(), label, max_count)?;
    Ok(values)
}

fn optional_nested_login(value: Option<&Value>, label: &str) -> Result<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be an object or null"))?;
    optional_input_string(
        object.get("login"),
        &format!("{label} login"),
        MAX_GITHUB_LOGIN_BYTES,
    )
}

fn first_optional_input_string(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    label: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    for field in fields {
        if object.get(*field).is_some_and(|value| !value.is_null()) {
            return optional_input_string(object.get(*field), label, max_bytes);
        }
    }
    Ok(None)
}

fn first_required_input_string(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    first_optional_input_string(object, fields, label, max_bytes)?
        .with_context(|| format!("{label} is required"))
}

fn item_target(item: &InboxItem) -> String {
    match item.kind {
        InboxItemKind::Issue => item
            .issue
            .as_ref()
            .map(|issue| format!("issue #{}", issue.number))
            .unwrap_or_else(|| item.item_id.clone()),
        InboxItemKind::PullRequest => item
            .pull_request
            .as_ref()
            .map(|pr| format!("pr #{}", pr.number))
            .unwrap_or_else(|| item.item_id.clone()),
    }
}

fn item_number(item: &InboxItem) -> Option<u64> {
    item.issue
        .as_ref()
        .map(|issue| issue.number)
        .or_else(|| item.pull_request.as_ref().map(|pr| pr.number))
}

fn item_label(kind: InboxItemKind) -> &'static str {
    match kind {
        InboxItemKind::Issue => "issue",
        InboxItemKind::PullRequest => "pull request",
    }
}

fn path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "- no changed files".to_string();
    }
    paths
        .iter()
        .map(|path| format!("- {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_summary(name: &str, status: Option<&str>, conclusion: Option<&str>) -> String {
    if check_failed(conclusion, status) {
        format!("{name} is failing or incomplete; full logs omitted")
    } else {
        format!("{name} check metadata fetched; full logs omitted")
    }
}

fn check_failed(conclusion: Option<&str>, status: Option<&str>) -> bool {
    conclusion.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    }) || status.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "failure" | "failed" | "timed_out" | "cancelled" | "action_required"
        )
    })
}

#[derive(Debug, Clone)]
struct BoundedText {
    text: String,
    truncated: bool,
}

fn summarize_text(text: &str, limit: usize) -> BoundedText {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    BoundedText {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn sanitize_public_text(repo: &Path, text: &str, limit: usize) -> BoundedText {
    let mut sanitized = Redactor::new().redact(text).text;
    sanitized = sanitized.replace(&repo.display().to_string(), ".");
    if let Some(parent) = repo.parent() {
        sanitized = sanitized.replace(&parent.display().to_string(), "<repo-parent>");
    }
    sanitized = sanitize_redacted_public_text(text, &sanitized);
    summarize_text(&sanitized, limit)
}

fn sanitize_public_field(text: &str, limit: usize) -> String {
    let redacted = Redactor::new().redact(text);
    summarize_text(&sanitize_redacted_public_text(text, &redacted.text), limit).text
}

fn sanitize_public_fields(values: &[String], limit: usize) -> Vec<String> {
    values
        .iter()
        .map(|value| sanitize_public_field(value, limit))
        .collect()
}

fn sanitize_redacted_public_text(original: &str, redacted: &str) -> String {
    if contains_private_key_material(original) || contains_private_key_material(redacted) {
        return "<redacted:private-key-material>".to_string();
    }
    redact_token_like_words(&redact_local_absolute_paths(redacted))
}

fn contains_private_key_material(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("PRIVATE KEY") && (upper.contains("-----BEGIN") || upper.contains("BEGIN "))
}

fn contains_local_absolute_path(text: &str) -> bool {
    text.split_whitespace()
        .any(token_contains_local_absolute_path)
}

fn redact_local_absolute_paths(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut token = String::new();
    for character in text.chars() {
        if character.is_whitespace() {
            push_redacted_path_token(&mut output, &token);
            token.clear();
            output.push(character);
        } else {
            token.push(character);
        }
    }
    push_redacted_path_token(&mut output, &token);
    output
}

fn push_redacted_path_token(output: &mut String, token: &str) {
    if token_contains_local_absolute_path(token) {
        output.push_str("<redacted:local-path>");
    } else {
        output.push_str(token);
    }
}

fn token_contains_local_absolute_path(token: &str) -> bool {
    contains_windows_home_path(token) || contains_unix_absolute_path(token)
}

fn contains_windows_home_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("c:\\users\\") || lower.contains("c:/users/")
}

fn contains_unix_absolute_path(token: &str) -> bool {
    if token.starts_with("//") {
        return false;
    }
    for (index, character) in token.char_indices() {
        if character == '/' && is_unix_absolute_path_start(token, index) {
            return true;
        }
    }
    false
}

fn is_unix_absolute_path_start(token: &str, index: usize) -> bool {
    if token[index..].starts_with("//") || token_url_prefix_start(token, index).is_some() {
        return false;
    }
    let Some(next) = token[index..].chars().nth(1) else {
        return false;
    };
    if !is_unix_path_component_char(next) {
        return false;
    }
    let previous = token[..index].chars().next_back();
    !previous.is_some_and(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
    })
}

fn token_url_prefix_start(token: &str, index: usize) -> Option<usize> {
    let marker = token.find("://")?;
    (index > marker).then_some(marker)
}

fn is_unix_path_component_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}

fn redact_token_like_words(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            push_redacted_token(&mut output, &token);
            token.clear();
            output.push(character);
        }
    }
    push_redacted_token(&mut output, &token);
    output
}

fn contains_token_like_word(text: &str) -> bool {
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            if is_token_like_word(&token) {
                return true;
            }
            token.clear();
        }
    }
    is_token_like_word(&token)
}

fn push_redacted_token(output: &mut String, token: &str) {
    if is_token_like_word(token) {
        output.push_str("<redacted:token>");
    } else {
        output.push_str(token);
    }
}

fn is_token_like_word(token: &str) -> bool {
    token.len() >= 32
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && token.chars().any(|c| c.is_ascii_digit())
}

fn default_true() -> bool {
    true
}

fn default_inbox_schema_version() -> u32 {
    INBOX_SCHEMA_VERSION
}

fn default_max_items() -> usize {
    DEFAULT_MAX_ITEMS
}

fn default_workspace_permission_mode() -> InboxPermissionMode {
    InboxPermissionMode::GithubRead
}

fn default_max_repair_attempts() -> usize {
    1
}

fn default_assigned_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("README.md")]
}

fn default_body_limit() -> usize {
    DEFAULT_BODY_LIMIT
}

fn default_blocked_terms() -> Vec<String> {
    [
        "api key",
        "credential",
        "cve",
        "exploit",
        "password",
        "private key",
        "secret",
        "security",
        "ssn",
        "token",
        "vulnerability",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use serde_json::json;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn dirty_primary_paths_fails_closed_on_non_utf8_git_status_path() -> Result<()> {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = tempfile::tempdir()?;
        Repository::init(temp.path())?;
        fs::write(
            temp.path()
                .join(OsString::from_vec(vec![b'n', b'o', b'n', 0xff])),
            b"untracked",
        )?;

        let error = dirty_primary_paths(temp.path()).expect_err("non-UTF-8 status must fail");
        assert!(error
            .to_string()
            .contains("primary worktree status path is not valid UTF-8"));
        Ok(())
    }

    #[cfg(unix)]
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };

    #[test]
    fn effectful_inbox_library_entries_fail_closed_before_input_or_artifact_access() {
        let temp = TempDir::new().expect("tempdir");
        let missing_repo = temp.path().join("repo-must-not-be-opened");
        let missing_config = temp.path().join("config-must-not-be-read");
        let run_id = RunId::new("inbox-failclosed").expect("run id");
        let errors = [
            run_inbox(InboxRunOptions {
                repo: missing_repo.clone(),
                run_id: run_id.clone(),
                github: true,
                permission_mode: None,
                dry_run: false,
                max_items: None,
                codex_bin: Some(temp.path().join("worker-must-not-run")),
            })
            .expect_err("inbox run must fail closed"),
            watch_inbox(InboxWatchOptions {
                repo: missing_repo,
                poll_seconds: 1,
                once: false,
                github: true,
                permission_mode: None,
                dry_run: false,
                max_items: None,
                codex_bin: None,
            })
            .expect_err("inbox watch must fail closed"),
            run_workspace_inbox(InboxWorkspaceRunOptions {
                config: missing_config.clone(),
                run_id,
                dry_run: false,
                codex_bin: None,
            })
            .expect_err("workspace inbox run must fail closed"),
            watch_workspace_inbox(InboxWorkspaceWatchOptions {
                config: missing_config,
                poll_seconds: 1,
                once: false,
                dry_run: false,
                codex_bin: None,
            })
            .expect_err("workspace inbox watch must fail closed"),
        ];

        assert!(
            errors
                .iter()
                .all(|error| format!("{error:#}")
                    .contains("capability-bound supervisor input bridge"))
        );
        assert_eq!(fs::read_dir(temp.path()).expect("read temp").count(), 0);
    }

    #[test]
    fn config_schema_defaults_versions_and_rejects_unknown_fields_at_every_level() {
        let compatible: InboxConfig = serde_json::from_value(json!({
            "default_validation_commands": ["true", {"command": "cargo test"}]
        }))
        .expect("legacy-compatible config");
        let compatible = validate_config(compatible).expect("validate compatible config");
        assert_eq!(compatible.version, INBOX_SCHEMA_VERSION);
        assert_eq!(compatible.repository.version, INBOX_SCHEMA_VERSION);
        assert_eq!(compatible.selection.version, INBOX_SCHEMA_VERSION);
        assert_eq!(compatible.privacy.version, INBOX_SCHEMA_VERSION);
        assert!(compatible
            .default_validation_commands
            .iter()
            .all(|command| command.version == INBOX_SCHEMA_VERSION));

        for (label, value) in [
            ("top", json!({"unknown": true})),
            ("repository", json!({"repository": {"unknown": true}})),
            ("selection", json!({"selection": {"unknown": true}})),
            ("privacy", json!({"privacy": {"unknown": true}})),
            (
                "validation command",
                json!({"default_validation_commands": [{"command": "true", "unknown": true}]}),
            ),
        ] {
            assert!(
                serde_json::from_value::<InboxConfig>(value).is_err(),
                "{label} unknown field was accepted"
            );
        }

        for (label, value) in [
            (
                "workspace top",
                json!({"repositories": [{"id": "repo", "path": "."}], "unknown": true}),
            ),
            (
                "workspace repository",
                json!({"repositories": [{"id": "repo", "path": ".", "unknown": true}]}),
            ),
            (
                "workspace safety",
                json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"unknown": true}}),
            ),
        ] {
            assert!(
                serde_json::from_value::<InboxWorkspaceConfig>(value).is_err(),
                "{label} unknown field was accepted"
            );
        }
    }

    #[test]
    fn config_schema_rejects_unsupported_versions_at_every_level() {
        for value in [
            json!({"version": 2}),
            json!({"repository": {"version": 2}}),
            json!({"selection": {"version": 2}}),
            json!({"privacy": {"version": 2}}),
            json!({"default_validation_commands": [{"version": 2, "command": "true"}]}),
        ] {
            let config: InboxConfig = serde_json::from_value(value).expect("parse version fixture");
            assert!(validate_config(config).is_err());
        }

        for value in [
            json!({"version": 2, "repositories": [{"id": "repo", "path": "."}]}),
            json!({"repositories": [{"version": 2, "id": "repo", "path": "."}]}),
            json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"version": 2}}),
        ] {
            let config: InboxWorkspaceConfig =
                serde_json::from_value(value).expect("parse workspace version fixture");
            assert!(validate_workspace_config(config).is_err());
        }
    }

    #[test]
    fn repository_config_and_cli_overrides_enforce_bounded_canonical_values() {
        let oversized_commands = (0..MAX_VALIDATION_COMMANDS)
            .map(|_| json!({"command": "x".repeat(MAX_VALIDATION_COMMAND_BYTES)}))
            .collect::<Vec<_>>();
        for (label, value) in [
            (
                "owner without name",
                json!({"repository": {"owner": "acme"}}),
            ),
            (
                "invalid owner",
                json!({"repository": {"owner": "-acme", "name": "repo"}}),
            ),
            (
                "invalid branch",
                json!({"repository": {"default_branch": "refs/../main"}}),
            ),
            (
                "selection count",
                json!({"selection": {"max_items": MAX_SELECTION_ITEMS + 1}}),
            ),
            (
                "selection disabled",
                json!({"selection": {"issues": false, "pull_requests": false}}),
            ),
            (
                "action permission conflict",
                json!({"action_policy": "github", "permission_mode": "fake"}),
            ),
            (
                "label control",
                json!({"selection": {"labels": ["bad\nlabel"]}}),
            ),
            (
                "repair attempts",
                json!({"max_repair_attempts": MAX_REPAIR_ATTEMPTS + 1}),
            ),
            (
                "validation count",
                json!({"default_validation_commands": vec!["true"; MAX_VALIDATION_COMMANDS + 1]}),
            ),
            (
                "validation timeout",
                json!({"default_validation_commands": [{"command": "true", "timeout_seconds": MAX_TIMEOUT_SECONDS + 1}]}),
            ),
            (
                "assigned path count",
                json!({"default_assigned_paths": vec!["README.md"; MAX_ASSIGNED_PATHS + 1]}),
            ),
            (
                "absolute assigned path",
                json!({"default_assigned_paths": ["/tmp/outside"]}),
            ),
            (
                "privacy term count",
                json!({"privacy": {"blocked_terms": vec!["term"; MAX_PRIVACY_TERMS + 1]}}),
            ),
            (
                "privacy body limit",
                json!({"privacy": {"max_body_chars": MAX_BODY_LIMIT + 1}}),
            ),
            (
                "codex path",
                json!({"codex_bin": "x".repeat(MAX_CODEX_PATH_BYTES + 1)}),
            ),
            (
                "serialized total",
                json!({"default_validation_commands": oversized_commands}),
            ),
        ] {
            let config: InboxConfig = serde_json::from_value(value).expect("parse bound fixture");
            assert!(validate_config(config).is_err(), "{label} was accepted");
        }

        assert!(
            validate_cli_source_options(false, None, Some(MAX_SELECTION_ITEMS + 1), None).is_err()
        );
        assert!(
            validate_cli_source_options(true, Some(InboxPermissionMode::Fake), None, None).is_err()
        );
        assert!(validate_cli_source_options(
            false,
            None,
            None,
            Some(Path::new(&"x".repeat(MAX_CODEX_PATH_BYTES + 1)))
        )
        .is_err());
    }

    #[test]
    fn workspace_config_enforces_counts_ids_paths_labels_and_strict_safety() {
        for (label, value) in [
            ("empty repositories", json!({"repositories": []})),
            (
                "repository count",
                json!({"repositories": (0..=MAX_WORKSPACE_REPOSITORIES).map(|index| json!({"id": format!("repo-{index}"), "path": format!("repo-{index}")})).collect::<Vec<_>>() }),
            ),
            (
                "invalid id",
                json!({"repositories": [{"id": "../repo", "path": "."}]}),
            ),
            (
                "case-folded duplicate id",
                json!({"repositories": [{"id": "Repo", "path": "one"}, {"id": "repo", "path": "two"}]}),
            ),
            (
                "disabled selectors",
                json!({"repositories": [{"id": "repo", "path": ".", "include_issues": false, "include_pull_requests": false}]}),
            ),
            (
                "max items",
                json!({"default_max_items_per_repo": MAX_SELECTION_ITEMS + 1, "repositories": [{"id": "repo", "path": "."}]}),
            ),
            (
                "label count",
                json!({"repositories": [{"id": "repo", "path": ".", "labels": vec!["bug"; MAX_LABELS + 1]}]}),
            ),
            (
                "auto approval",
                json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"allow_auto_approval": true}}),
            ),
            (
                "unclean primary",
                json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"require_clean_primary": false}}),
            ),
        ] {
            let config: InboxWorkspaceConfig =
                serde_json::from_value(value).expect("parse workspace bound fixture");
            assert!(
                validate_workspace_config(config).is_err(),
                "{label} was accepted"
            );
        }

        let temp = TempDir::new().expect("tempdir");
        let config = validate_workspace_config(
            serde_json::from_value(json!({
                "repositories": [
                    {"id": "first", "path": "."},
                    {"id": "second", "path": "."}
                ]
            }))
            .expect("parse collision fixture"),
        )
        .expect("validate collision fixture shape");
        let loaded = LoadedWorkspaceConfig {
            config,
            config_dir: temp.path().to_path_buf(),
            public_config_path: PathBuf::from("workspace.json"),
        };
        assert!(workspace_repo_specs(&loaded).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn repository_and_workspace_configs_reject_links_special_files_oversize_and_non_utf8() {
        let (temp, repo) = temp_repo();
        let config = repo.join(CONFIG_FILE);
        let external = temp.path().join("external-config.json");
        fs::write(&external, b"{}\n").expect("external config");
        symlink(&external, &config).expect("config symlink");
        assert!(load_config(&repo).is_err());
        fs::remove_file(&config).expect("remove symlink");

        let fifo = CString::new(config.as_os_str().as_bytes()).expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(load_config(&repo).is_err());
        fs::remove_file(&config).expect("remove FIFO");

        fs::create_dir(&config).expect("config directory");
        assert!(load_config(&repo).is_err());
        fs::remove_dir(&config).expect("remove config directory");

        fs::write(&config, vec![b'x'; MAX_CONFIG_BYTES as usize + 1]).expect("oversized config");
        assert!(load_config(&repo).is_err());
        fs::write(&config, [0xff, 0xfe]).expect("non-UTF8 config");
        assert!(load_config(&repo).is_err());

        let workspace = temp.path().join("workspace.json");
        fs::remove_file(&config).expect("remove repo config");
        symlink(&external, &workspace).expect("workspace symlink");
        assert!(load_workspace_config(&workspace).is_err());
        fs::remove_file(&workspace).expect("remove workspace symlink");
        let fifo = CString::new(workspace.as_os_str().as_bytes()).expect("workspace FIFO path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(load_workspace_config(&workspace).is_err());
        fs::remove_file(&workspace).expect("remove workspace FIFO");
        fs::create_dir(&workspace).expect("workspace directory");
        assert!(load_workspace_config(&workspace).is_err());
        fs::remove_dir(&workspace).expect("remove workspace directory");
        fs::write(&workspace, vec![b'x'; MAX_CONFIG_BYTES as usize + 1])
            .expect("oversized workspace config");
        assert!(load_workspace_config(&workspace).is_err());
        fs::write(&workspace, [0xff, 0xfe]).expect("non-UTF8 workspace config");
        assert!(load_workspace_config(&workspace).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_config_binds_the_canonical_parent_before_resolving_repo_paths() {
        let temp = TempDir::new().expect("tempdir");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("real config directory");
        let alias = temp.path().join("alias");
        symlink(&real, &alias).expect("parent alias");
        let config = real.join("workspace.json");
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "repositories": [{"id": "repo", "path": "missing-repo"}]
            }))
            .expect("workspace JSON"),
        )
        .expect("workspace config");

        let loaded = load_workspace_config(&alias.join("workspace.json")).expect("load config");
        assert_eq!(
            loaded.config_dir,
            fs::canonicalize(&real).expect("canonical real")
        );
    }

    #[test]
    fn workspace_repository_projection_uses_config_relative_paths_and_enabled_flags() {
        let temp = TempDir::new().expect("tempdir");
        let config_dir = temp.path().join("config");
        let first = config_dir.join("first");
        let second = config_dir.join("second");
        fs::create_dir_all(&first).expect("first repository");
        fs::create_dir(&second).expect("second repository");
        let config = config_dir.join("workspace.json");
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "repositories": [
                    {"id": "first", "path": "first"},
                    {"id": "second", "path": "second", "enabled": false}
                ]
            }))
            .expect("workspace JSON"),
        )
        .expect("workspace config");

        let repositories =
            load_workspace_repositories(&config).expect("project workspace repositories");

        assert_eq!(
            repositories,
            vec![
                WorkspaceRepository {
                    id: "first".to_string(),
                    path: fs::canonicalize(first).expect("canonical first repository"),
                    enabled: true,
                },
                WorkspaceRepository {
                    id: "second".to_string(),
                    path: fs::canonicalize(second).expect("canonical second repository"),
                    enabled: false,
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_repository_projection_preserves_strict_no_follow_loading() {
        let temp = TempDir::new().expect("tempdir");
        let external = temp.path().join("external.json");
        fs::write(
            &external,
            br#"{"repositories":[{"id":"repo","path":".","unknown":true}]}"#,
        )
        .expect("strict schema fixture");
        assert!(load_workspace_repositories(&external).is_err());

        let linked = temp.path().join("workspace.json");
        symlink(&external, &linked).expect("workspace symlink");
        assert!(load_workspace_repositories(&linked).is_err());
    }

    #[test]
    fn source_snapshot_binding_is_deterministic_validated_and_identity_stable() {
        let identity = publication::stable_external_digest(b"repository-identity");
        let first = InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "github.example",
            "github.example/acme/repo",
            identity.clone(),
            42,
            "2026-07-08T00:00:00Z",
            "OPEN",
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(64),
            "4".repeat(64),
        )
        .expect("first binding");
        let second = InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "github.example",
            "github.example/acme/repo",
            identity,
            42,
            "2026-07-08T00:00:00Z",
            "OPEN",
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(64),
            "4".repeat(64),
        )
        .expect("second binding");
        assert_eq!(first, second);
        assert_eq!(first.source_key(), "github_pr:42");
        assert_eq!(first.digest(), first.deterministic_digest().unwrap());

        let encoded = serde_json::to_value(&first).expect("serialize binding");
        let decoded: InboxSourceSnapshotBinding =
            serde_json::from_value(encoded.clone()).expect("deserialize binding");
        assert_eq!(decoded, first);
        let mut tampered_identity = encoded.clone();
        tampered_identity["repository_identity"] = json!("f".repeat(64));
        assert!(serde_json::from_value::<InboxSourceSnapshotBinding>(tampered_identity).is_err());
        let mut tampered = encoded;
        tampered["updated_at"] = json!("not-a-timestamp");
        assert!(serde_json::from_value::<InboxSourceSnapshotBinding>(tampered).is_err());

        assert!(InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "github.example",
            "github.example/acme/repo",
            publication::stable_external_digest(b"repository-identity"),
            42,
            "2026-07-08T00:00:00Z",
            "OPEN",
            "not-an-oid".to_string(),
            "2".repeat(40),
            "3".repeat(64),
            "4".repeat(64),
        )
        .is_err());
        assert!(InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "other.example",
            "github.example/acme/repo",
            publication::stable_external_digest(b"repository-identity"),
            42,
            "2026-07-08T00:00:00Z",
            "OPEN",
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(64),
            "4".repeat(64),
        )
        .is_err());

        let config = InboxConfig::default();
        let context = SourceRepositoryBindingContext {
            host: "fake".to_string(),
            selector: ".".to_string(),
            identity: publication::stable_external_digest(b"fake-repository"),
        };
        let mut candidates = fake_issue_candidates(&config).into_iter();
        let first_item = issue_item(
            candidates.next().expect("first fake issue"),
            &config,
            &context,
            &BTreeMap::new(),
        )
        .expect("first fake item");
        let duplicate_item = issue_item(
            candidates.next().expect("duplicate fake issue"),
            &config,
            &context,
            &BTreeMap::new(),
        )
        .expect("duplicate fake item");
        assert_eq!(first_item.source_key, duplicate_item.source_key);
        assert_eq!(first_item.source_snapshot, duplicate_item.source_snapshot);
    }

    #[test]
    fn source_repository_binding_matches_configured_owner_name_and_is_locally_durable() {
        let (temp, repo_path) = temp_repo();
        let repo = Repository::open(&repo_path).expect("open repository");
        repo.remote("origin", "https://github.com/acme/inbox.git")
            .expect("create origin");
        let mut config = InboxConfig::default();
        config.repository.owner = Some("acme".to_string());
        config.repository.name = Some("inbox".to_string());
        let config = validate_config(config).expect("validate repository config");

        let first = source_repository_binding_context(&repo_path, &config, true)
            .expect("first repository binding");
        let second = source_repository_binding_context(&repo_path, &config, true)
            .expect("second repository binding");
        assert_eq!(first.host, "github.com");
        assert_eq!(first.selector, "github.com/acme/inbox");
        assert_eq!(first.identity, second.identity);
        assert_eq!(first.identity.len(), 64);
        assert!(first
            .identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));

        drop(repo);
        let moved_repo = temp.path().join("moved-repo");
        fs::rename(&repo_path, &moved_repo).expect("move repository");
        let moved = source_repository_binding_context(&moved_repo, &config, true)
            .expect("moved repository binding");
        assert_eq!(first.identity, moved.identity);
        InboxSourceSnapshotBinding::for_issue(
            InboxSourceProvider::Fake,
            moved.host.clone(),
            moved.selector.clone(),
            moved.identity.clone(),
            7,
            "2026-07-08T00:00:00Z",
            "OPEN",
            "3".repeat(64),
            "4".repeat(64),
        )
        .expect("fake intake snapshot bound to canonical local origin");

        let wrong_url = json!({
            "number": 7,
            "title": "wrong repository",
            "body": "body",
            "url": "https://github.com/acme/different/issues/7",
            "author": null,
            "updatedAt": "2026-07-08T00:00:00Z",
            "state": "OPEN",
            "labels": []
        });
        let raw =
            raw_issue_from_value(&moved_repo, &wrong_url, &config, &moved).expect("raw issue");
        assert!(issue_item(raw, &config, &moved, &BTreeMap::new()).is_err());

        let mut exact_url = wrong_url;
        exact_url["title"] = json!("exact repository");
        exact_url["url"] = json!("https://github.com/acme/inbox/issues/7");
        let raw =
            raw_issue_from_value(&moved_repo, &exact_url, &config, &moved).expect("raw issue");
        let exact_item =
            issue_item(raw, &config, &moved, &BTreeMap::new()).expect("exact bound issue item");
        let guard = exact_item
            .source_snapshot
            .external_source_guard()
            .expect("source guard conversion")
            .expect("GitHub source guard");
        let moved_repository = Repository::open(&moved_repo).expect("open moved repository");
        moved_repository
            .remote_set_url("origin", "https://other.example/acme/inbox.git")
            .expect("swap origin host");
        assert!(publication::revalidate_external_source(&moved_repo, &guard).is_err());

        let mut mismatch = config;
        mismatch.repository.name = Some("different".to_string());
        assert!(source_repository_binding_context(&moved_repo, &mismatch, true).is_err());
    }

    #[test]
    fn raw_github_candidates_fail_closed_on_malformed_identity_and_nested_values() {
        let source = test_source_repository_binding();
        let mut pr = valid_raw_pr_value();
        pr.as_object_mut().unwrap().remove("headRefOid");
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["updatedAt"] = json!("invalid");
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["files"] = json!([{"path": "/tmp/outside"}]);
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["labels"] = json!((0..=MAX_LABELS)
            .map(|index| json!({"name": format!("label-{index}")}))
            .collect::<Vec<_>>());
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["title"] = json!("x".repeat(MAX_GITHUB_TITLE_BYTES + 1));
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["author"] = json!({"login": "bad\nlogin"});
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["statusCheckRollup"] = json!(vec![json!({"name": "ci"}); MAX_GITHUB_CHECKS + 1]);
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        let mut pr = valid_raw_pr_value();
        pr["latestReviews"] = json!(vec![json!({"state": "APPROVED"}); MAX_GITHUB_REVIEWS + 1]);
        assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

        assert!(validate_count(
            MAX_GITHUB_ITEMS + 1,
            "gh issue list items",
            MAX_GITHUB_ITEMS
        )
        .is_err());

        let (_temp, repo) = temp_repo();
        let issue = json!({
            "number": 0,
            "title": "issue",
            "body": "body",
            "updatedAt": "2026-07-08T00:00:00Z",
            "state": "OPEN"
        });
        assert!(raw_issue_from_value(&repo, &issue, &InboxConfig::default(), &source).is_err());
    }

    #[test]
    fn real_publication_mode_fails_closed_before_intake_or_artifacts() {
        let (_temp, repo) = temp_repo();
        let error = run_inbox(InboxRunOptions {
            repo: repo.clone(),
            run_id: RunId::new("reviewer-refusal").expect("run id"),
            github: false,
            permission_mode: Some(InboxPermissionMode::GithubGit),
            dry_run: false,
            max_items: Some(1),
            codex_bin: None,
        })
        .expect_err("real publication must fail closed before effectful intake");
        let error = format!("{error:#}");
        assert!(error.contains("capability-bound supervisor input bridge"));
        assert!(!repo.join(".maco/inbox/runs/reviewer-refusal").exists());
    }

    #[test]
    fn assigned_paths_for_issue_falls_back_to_config_default() {
        let config = InboxConfig::default();
        let item = make_issue_item(1, "No candidate paths", Vec::new());

        let paths = assigned_paths_for_item(&item, &config).expect("assigned paths");

        assert_eq!(paths, vec![PathBuf::from("README.md")]);
    }

    #[test]
    fn summarize_text_bounds_body_summary_by_chars() {
        let bounded = summarize_text("abcdef", 3);

        assert_eq!(bounded.text, "abc");
        assert!(bounded.truncated);

        let exact = summarize_text("abc", 3);

        assert_eq!(exact.text, "abc");
        assert!(!exact.truncated);
    }

    #[test]
    fn github_json_parser_rejects_oversized_truncated_and_non_utf8_source() {
        assert!(parse_gh_json_bytes(vec![b' '; GH_OUTPUT_LIMIT + 1], "gh test").is_err());
        assert!(parse_gh_json_bytes(vec![0xff, 0xfe], "gh test").is_err());
        assert_eq!(
            parse_gh_json_bytes(b"[]".to_vec(), "gh test").expect("bounded JSON"),
            json!([])
        );
    }

    #[test]
    fn privacy_scan_redacts_token_like_values_and_refuses_body() {
        let token = "abc123456789012345678901234567890xyz";
        let policy = InboxPrivacyPolicy {
            max_body_chars: 512,
            ..InboxPrivacyPolicy::default()
        };

        let scan = privacy_scan(&format!("observed value {token}"), &policy);

        assert!(!scan.safe);
        assert!(scan
            .reasons
            .contains(&"secret_like_content_redacted".to_string()));
        assert!(scan.body_summary.contains("<redacted:token>"));
        assert!(!scan.body_summary.contains(token));
    }

    #[test]
    fn private_key_material_is_replaced_with_refusal_marker() {
        let body = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";

        let scan = privacy_scan(body, &InboxPrivacyPolicy::default());

        assert!(!scan.safe);
        assert!(scan.reasons.contains(&"private_key_material".to_string()));
        assert_eq!(scan.body_summary, "<redacted:private-key-material>");
    }

    #[test]
    fn local_absolute_paths_are_detected_and_redacted() {
        let body = r"Paths: /mnt/d/home/project, /home/example/repo, C:\Users\Example\secret.txt";

        let scan = privacy_scan(body, &InboxPrivacyPolicy::default());

        assert!(!scan.safe);
        assert!(scan.reasons.contains(&"local_absolute_path".to_string()));
        assert_eq!(
            scan.body_summary.matches("<redacted:local-path>").count(),
            3
        );
        assert!(!scan.body_summary.contains("/mnt/d/home"));
        assert!(!scan.body_summary.contains("/home/example"));
        assert!(!scan.body_summary.contains(r"C:\Users"));
    }

    #[test]
    fn blocked_terms_in_titles_extend_privacy_reasons() {
        let mut privacy = privacy_scan("safe body", &InboxPrivacyPolicy::default());

        extend_privacy_reasons(
            &mut privacy,
            "title",
            "Regression exposes api key handling",
            &InboxPrivacyPolicy::default(),
        );

        assert!(!privacy.safe);
        assert!(privacy
            .reasons
            .contains(&"title_blocked_term:api key".to_string()));
    }

    #[test]
    fn sanitize_public_text_rewrites_repo_paths_without_leaking_absolutes() {
        let repo = Path::new("/mnt/d/home/project/repo");

        let sanitized = sanitize_public_text(
            repo,
            "repo path /mnt/d/home/project/repo/src/inbox.rs parent /mnt/d/home/project",
            512,
        );

        assert_eq!(
            sanitized.text,
            "repo path ./src/inbox.rs parent <repo-parent>"
        );
        assert!(!sanitized.text.contains("/mnt/d/home/project"));
    }

    #[test]
    fn permission_mode_parse_normalizes_hyphen_aliases() {
        assert_eq!(
            InboxPermissionMode::parse("github-read").expect("github-read"),
            InboxPermissionMode::GithubRead
        );
        assert_eq!(
            InboxPermissionMode::parse("github_read").expect("github_read"),
            InboxPermissionMode::GithubRead
        );
        assert_eq!(
            InboxPermissionMode::parse("github-full").expect("github-full"),
            InboxPermissionMode::GithubFull
        );
    }

    #[test]
    fn permission_mode_parse_accepts_legacy_github_alias_and_rejects_unknown() {
        assert_eq!(
            InboxPermissionMode::parse("github").expect("github alias"),
            InboxPermissionMode::GithubFull
        );

        let error = InboxPermissionMode::parse("github-write").expect_err("unknown mode");

        assert!(error.contains("expected one of"));
    }

    #[test]
    fn permission_mode_deserializes_hyphen_aliases() {
        let mode: InboxPermissionMode =
            serde_json::from_str(r#""github-local""#).expect("deserialize alias");

        assert_eq!(mode, InboxPermissionMode::GithubLocal);
    }

    #[test]
    fn legacy_github_flag_and_action_policy_promote_to_full_permission() {
        let config = InboxConfig::default();

        assert_eq!(
            effective_permission_mode(&config, true, None),
            InboxPermissionMode::GithubFull
        );

        let config = InboxConfig {
            action_policy: InboxActionPolicy::Github,
            ..InboxConfig::default()
        };

        assert_eq!(
            effective_permission_mode(&config, false, None),
            InboxPermissionMode::GithubFull
        );
    }

    #[test]
    fn effective_action_policy_preserves_dry_run_and_maps_github_intake() {
        assert_eq!(
            effective_action_policy(InboxActionPolicy::DryRun, InboxPermissionMode::GithubFull),
            InboxActionPolicy::DryRun
        );
        assert_eq!(
            effective_action_policy(InboxActionPolicy::Fake, InboxPermissionMode::GithubRead),
            InboxActionPolicy::Github
        );
        assert_eq!(
            effective_action_policy(InboxActionPolicy::Github, InboxPermissionMode::Fake),
            InboxActionPolicy::Fake
        );
    }

    #[test]
    fn apply_scan_decisions_enforces_max_items() {
        let mut items = vec![
            make_issue_item(1, "first", vec![PathBuf::from("README.md")]),
            make_issue_item(2, "second", vec![PathBuf::from("src/lib.rs")]),
            make_issue_item(3, "third", vec![PathBuf::from("docs/guide.md")]),
        ];

        apply_scan_decisions(&mut items, 2);

        assert!(items[0].selected);
        assert!(items[1].selected);
        assert!(!items[2].selected);
        assert_eq!(items[2].skip_reason.as_deref(), Some("selection_limit"));
    }

    #[test]
    fn apply_scan_decisions_marks_duplicates_within_current_scan() {
        let mut duplicate = make_issue_item(1, "duplicate", vec![PathBuf::from("README.md")]);
        duplicate.item_id = "issue-1-copy".to_string();
        let mut items = vec![
            make_issue_item(1, "first", vec![PathBuf::from("README.md")]),
            duplicate,
        ];

        apply_scan_decisions(&mut items, 4);

        assert!(items[0].selected);
        assert!(!items[1].selected);
        assert!(items[1].duplicate.duplicate);
        assert_eq!(items[1].skip_reason.as_deref(), Some("duplicate"));
        assert_eq!(
            items[1].duplicate.reason.as_deref(),
            Some("duplicate inbox candidate in current scan")
        );
    }

    #[test]
    fn label_overrides_are_trimmed_sorted_and_used_by_fake_candidates() {
        let (temp, repo) = temp_repo();
        let loaded = load_config_with_config_overrides(
            &repo,
            InboxConfigOverrides {
                labels: Some(vec![
                    "needs-work".to_string(),
                    " bug ".to_string(),
                    "needs-work".to_string(),
                ]),
                ..InboxConfigOverrides::default()
            },
        )
        .expect("load config");

        assert_eq!(
            loaded.config.selection.labels,
            vec!["bug".to_string(), "needs-work".to_string()]
        );
        assert_eq!(
            fake_issue_candidates(&loaded.config)[0].labels,
            loaded.config.selection.labels
        );
        drop(temp);
    }

    #[test]
    fn selected_target_paths_include_only_selected_items() {
        let config = InboxConfig::default();
        let mut skipped = make_issue_item(2, "skipped", vec![PathBuf::from("src/lib.rs")]);
        skipped.selected = false;
        let items = vec![
            make_issue_item(1, "selected", vec![PathBuf::from("README.md")]),
            skipped,
        ];

        let paths = selected_target_paths(&items, &config).expect("target paths");

        assert_eq!(paths, vec![PathBuf::from("README.md")]);
    }

    #[test]
    fn preflight_ignores_dirty_runtime_artifacts() {
        let (_temp, repo) = temp_repo();
        fs::create_dir_all(repo.join(".maco/inbox/runs/run-1")).expect("create .maco");
        fs::write(
            repo.join(".maco/inbox/runs/run-1/final-report.json"),
            "{}\n",
        )
        .expect("write .maco artifact");
        fs::create_dir_all(repo.join(".maco-cache")).expect("create cache");
        fs::write(repo.join(".maco-cache/state.json"), "{}\n").expect("write cache artifact");

        let refusals =
            preflight_refusals(&repo, &[PathBuf::from("src/inbox.rs")]).expect("preflight");

        assert!(refusals.is_empty());
    }

    #[test]
    fn preflight_refuses_only_overlapping_sync_claims() {
        let (_temp, repo) = temp_repo();
        SyncStore::open(&repo)
            .expect("open store")
            .claim_paths("agent-a", ["docs"])
            .expect("claim docs");

        let unrelated =
            preflight_refusals(&repo, &[PathBuf::from("src/inbox.rs")]).expect("preflight");

        assert!(unrelated.is_empty());

        let overlapping =
            preflight_refusals(&repo, &[PathBuf::from("docs/guide.md")]).expect("preflight");

        assert_eq!(overlapping.len(), 1);
        assert_eq!(overlapping[0].kind, "active_sync_claims");
        assert_eq!(overlapping[0].paths, vec![PathBuf::from("docs")]);
    }

    #[test]
    fn preflight_ignores_runtime_artifact_sync_claims() {
        let (_temp, repo) = temp_repo();
        SyncStore::open(&repo)
            .expect("open store")
            .claim_paths("agent-a", [".maco/inbox/runs/run-1"])
            .expect("claim runtime path");

        let refusals = preflight_refusals(
            &repo,
            &[PathBuf::from(".maco/inbox/runs/run-1/final-report.json")],
        )
        .expect("preflight");

        assert!(refusals.is_empty());
    }

    #[test]
    fn scan_report_public_json_uses_placeholder_repo_and_omits_absolute_paths() {
        let (temp, repo) = temp_repo();

        let report = scan_inbox(InboxScanOptions {
            repo: repo.clone(),
            github: false,
            permission_mode: None,
            max_items: Some(1),
            action_policy_override: None,
        })
        .expect("scan inbox");
        let public_json = serde_json::to_string(&report).expect("serialize report");

        assert_eq!(report.repo, PathBuf::from("."));
        let snapshot = &report.items[0].source_snapshot;
        snapshot.validate().expect("public snapshot binding");
        assert_eq!(snapshot.repository_selector(), ".");
        assert_eq!(snapshot.repository_identity().len(), 64);
        assert!(!public_json.contains(repo.to_str().expect("utf8 repo path")));
        assert!(!public_json.contains(temp.path().to_str().expect("utf8 temp path")));
    }

    #[test]
    fn issue_task_body_and_title_include_public_issue_context() {
        let config = InboxConfig::default();
        let mut item = make_issue_item(7, "Repair inbox summaries", vec![PathBuf::from("src")]);
        let issue = item.issue.as_mut().expect("issue");
        issue.url = Some("https://github.example/repo/issues/7".to_string());
        issue.body_summary = "Summary with <redacted:token>".to_string();

        let plan =
            autopilot_plan_for_item(&item, &config, InboxPermissionMode::GithubPr).expect("plan");

        assert_eq!(plan.task.title, "Inbox issue: Repair inbox summaries");
        assert!(plan
            .task
            .body
            .contains("React to GitHub issue #7.\nURL: https://github.example/repo/issues/7"));
        assert!(plan.task.body.contains("Summary with <redacted:token>"));
        assert_eq!(plan.assigned_paths, vec![PathBuf::from("src")]);
        assert_eq!(plan.forge_mode, AutopilotForgeMode::Github);
    }

    #[test]
    fn pr_task_body_includes_paths_checks_reviews_and_validation_expectation() {
        let item = make_pr_item(
            42,
            "Fix failing inbox CI",
            vec![PathBuf::from("src/inbox.rs")],
        );

        let body = task_body_for_item(&item);

        assert!(body.contains("React to GitHub PR #42."));
        assert!(body.contains("Changed files:\n- src/inbox.rs"));
        assert!(body.contains("- ci status=completed conclusion=failure summary=ci failed"));
        assert!(body.contains("requested change summary"));
        assert!(body.contains("address failing check context: ci"));
    }

    #[test]
    fn raw_pr_candidate_parsing_deduplicates_labels_files_and_failed_checks() {
        let value = json!({
            "number": 9,
            "title": "PR title",
            "body": "body",
            "url": "https://github.example/acme/repo/pull/9",
            "updatedAt": "2026-07-08T00:00:00Z",
            "state": "OPEN",
            "author": {"login": "author"},
            "headRefName": "feature",
            "baseRefName": "main",
            "headRefOid": "1111111111111111111111111111111111111111",
            "baseRefOid": "2222222222222222222222222222222222222222",
            "isDraft": false,
            "labels": [{"name": "z"}, {"name": "a"}, {"name": "a"}],
            "files": [{"path": "src/../src/inbox.rs"}, {"path": "src/inbox.rs"}],
            "statusCheckRollup": [
                {"name": "ci", "status": "completed", "conclusion": "failure", "detailsUrl": "fake://ci"}
            ],
            "reviewDecision": "CHANGES_REQUESTED",
            "latestReviews": [
                {"state": "CHANGES_REQUESTED", "author": {"login": "reviewer"}, "body": "please adjust"}
            ]
        });

        let raw = raw_pr_from_value(
            &value,
            &InboxConfig::default(),
            &test_source_repository_binding(),
        )
        .expect("raw pr");

        assert_eq!(raw.labels, vec!["a".to_string(), "z".to_string()]);
        assert_eq!(raw.changed_files, vec![PathBuf::from("src/inbox.rs")]);
        assert!(raw.review_feedback.requested_changes);
        assert!(check_failed(
            raw.checks[0].conclusion.as_deref(),
            raw.checks[0].status.as_deref()
        ));
    }

    fn temp_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main").expect("init repo");
        (temp, repo)
    }

    fn test_source_repository_binding() -> SourceRepositoryBindingContext {
        SourceRepositoryBindingContext {
            host: "github.example".to_string(),
            selector: "github.example/acme/repo".to_string(),
            identity: publication::stable_external_digest(b"inbox-test-source-repository"),
        }
    }

    fn make_issue_item(number: u64, title: &str, assigned_paths: Vec<PathBuf>) -> InboxItem {
        let source_key = format!("github_issue:{number}");
        InboxItem {
            item_id: format!("issue-{number}"),
            source_key: source_key.clone(),
            source_snapshot: test_source_snapshot(InboxItemKind::Issue, number),
            kind: InboxItemKind::Issue,
            title: title.to_string(),
            url: None,
            issue: Some(GithubIssueCandidate {
                number,
                title: title.to_string(),
                url: None,
                author: None,
                labels: Vec::new(),
                updated_at: Some("1970-01-01T00:00:00Z".to_string()),
                body_summary: String::new(),
                body_truncated: false,
                assigned_paths,
                path_proposal: planning::TaskPathProposalDiagnostics::default(),
            }),
            pull_request: None,
            privacy: safe_privacy(),
            duplicate: duplicate_result(&source_key, &BTreeMap::new()),
            selected: true,
            skip_reason: None,
        }
    }

    fn make_pr_item(number: u64, title: &str, changed_files: Vec<PathBuf>) -> InboxItem {
        let source_key = format!("github_pr:{number}");
        InboxItem {
            item_id: format!("pr-{number}"),
            source_key: source_key.clone(),
            source_snapshot: test_source_snapshot(InboxItemKind::PullRequest, number),
            kind: InboxItemKind::PullRequest,
            title: title.to_string(),
            url: Some(format!("https://github.example/repo/pull/{number}")),
            issue: None,
            pull_request: Some(GithubPrCandidate {
                number,
                title: title.to_string(),
                url: Some(format!("https://github.example/repo/pull/{number}")),
                author: Some("author".to_string()),
                labels: vec!["needs-work".to_string()],
                updated_at: Some("2026-07-08T00:00:00Z".to_string()),
                head_ref: Some("feature/inbox".to_string()),
                base_ref: Some("main".to_string()),
                changed_files,
                checks: vec![GithubCheckSummary {
                    name: "ci".to_string(),
                    status: Some("completed".to_string()),
                    conclusion: Some("failure".to_string()),
                    details_url: None,
                    summary: "ci failed".to_string(),
                }],
                review_feedback: GithubReviewFeedbackSummary {
                    review_decision: Some("CHANGES_REQUESTED".to_string()),
                    requested_changes: true,
                    unresolved_thread_count: Some(1),
                    reviewer_logins: vec!["reviewer".to_string()],
                    summaries: vec!["requested change summary".to_string()],
                },
                body_summary: "PR body summary".to_string(),
                body_truncated: false,
            }),
            privacy: safe_privacy(),
            duplicate: duplicate_result(&source_key, &BTreeMap::new()),
            selected: true,
            skip_reason: None,
        }
    }

    fn test_source_snapshot(kind: InboxItemKind, number: u64) -> InboxSourceSnapshotBinding {
        match kind {
            InboxItemKind::Issue => InboxSourceSnapshotBinding::for_issue(
                InboxSourceProvider::Fake,
                "fake",
                ".",
                publication::stable_external_digest(b"inbox-test-repository"),
                number,
                "1970-01-01T00:00:00Z",
                "OPEN",
                "3".repeat(64),
                "4".repeat(64),
            ),
            InboxItemKind::PullRequest => InboxSourceSnapshotBinding::for_pull_request(
                InboxSourceProvider::Fake,
                "fake",
                ".",
                publication::stable_external_digest(b"inbox-test-repository"),
                number,
                "1970-01-01T00:00:00Z",
                "OPEN",
                "1111111111111111111111111111111111111111".to_string(),
                "2222222222222222222222222222222222222222".to_string(),
                "3".repeat(64),
                "4".repeat(64),
            ),
        }
        .expect("test source snapshot")
    }

    fn valid_raw_pr_value() -> Value {
        json!({
            "number": 42,
            "title": "Bounded PR",
            "body": "Please repair the failing check.",
            "url": "https://github.example/acme/repo/pull/42",
            "author": {"login": "reviewer"},
            "labels": [{"name": "bug"}],
            "updatedAt": "2026-07-08T00:00:00Z",
            "state": "OPEN",
            "headRefName": "feature/inbox",
            "baseRefName": "main",
            "headRefOid": "1111111111111111111111111111111111111111",
            "baseRefOid": "2222222222222222222222222222222222222222",
            "isDraft": false,
            "files": [{"path": "src/inbox.rs"}],
            "reviewDecision": "CHANGES_REQUESTED",
            "latestReviews": [],
            "statusCheckRollup": [{
                "name": "ci",
                "status": "completed",
                "conclusion": "failure",
                "detailsUrl": "https://github.example/acme/repo/actions/1"
            }]
        })
    }

    fn safe_privacy() -> PrivacyScanResult {
        PrivacyScanResult {
            safe: true,
            reasons: Vec::new(),
            redactions: RedactionSummary::default(),
            body_summary: String::new(),
            body_truncated: false,
        }
    }
}
