use crate::agent_lifecycle::{AgentLaunchMetadata, MACO_RUN_ID_ENV, MACO_TASK_ID_ENV};
use crate::artifacts::state_auth::sha256_hex;
use crate::gate_denial::{ExternalSideEffectState, GateDenial};
use crate::llm::provider::Usage;
use crate::machine_global::{
    DestructiveTargetInput, GateOutcome, MachineGlobalRetentionBinding, MachineGlobalStore,
    RetentionOperation, RetentionOperationId,
};
use crate::pre_action_review::{
    ActionDescriptor, ApprovalReviewRequest, BlastRadius, CommandClass, CommandInvocation,
    DecisionSource, PathAccess, PathAccessMode, PermissionRequest, PreActionReviewer,
    RedactedClassifierRequest, ReviewContext, ReviewMetricSnapshot, ReviewOutcome,
};
use crate::process_runner::{
    read_bounded_regular_file_nofollow, run_process_cancellable, run_process_interactive,
    CapturedBytes, ContainmentBackend, EnvironmentMode, ExternalCodexProfile,
    InteractiveProcessOutput, ProcessCancellation, ProcessOutput, ProcessRunError, ProcessSpec,
    ProcessTreeEvidence, SideEffectConfinementEvidence, SideEffectConfinementProfile,
    SideEffectConfinementProfileKind, StdinMode, StreamCapture, StrictOfflineWorkspaceProfile,
    WorkspaceAccess,
};
use crate::protected_path::{DeclaredPathCoordinate, ProtectedPathSpec};
use crate::runtime_adapter::{
    AdapterId, LaunchContext, RuntimeAdapterConfig, RuntimeId, SideEffectConfinement, TypedRuntime,
    TypedRuntimeContract, WritableLaunchTarget,
};
use crate::safe_state::{unsigned_to_u32, ReservedDirectory};
use crate::secure_output::{ReservedOutputFile, SecureOutputRoot};
use crate::worktree::normalize_agent_id;
use anyhow::{bail, Context, Result};
use git2::Oid;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "codex_app_server.rs"]
pub(crate) mod codex_app_server;
#[allow(dead_code, unused_imports)]
pub(crate) mod executor;

pub use crate::protected_path::SandboxDenialRetryability;

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_TEE_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_WORKER_JOURNAL_ARTIFACT_BYTES: usize = 1024 * 1024;
const CODEX_MODEL_CATALOG_MAX_BYTES: usize = 8 * 1024 * 1024;
const CODEX_MODEL_CATALOG_MAX_MODELS: usize = 512;
const CODEX_MODEL_SLUG_MAX_BYTES: usize = 256;
const MIN_CREDENTIAL_BYTES: usize = 16;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_REDACTION_PATTERNS: usize = 32;
const MAX_CREDENTIAL_REDACTION_PATTERN_BYTES: usize = 128 * 1024;
const CREDENTIAL_REDACTION: &[u8] = b"[REDACTED]";
const CODEX_MINIMUM_VERSION: (u64, u64, u64) = (0, 138, 0);
const CODEX_DUPLEX_AUDITED_VERSION: (u64, u64, u64) = (0, 144, 4);
const TRUSTED_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";
const OUTER_SYSTEMD_POLICY_ID: &str = "maco_external_codex_outer_systemd_v1";
const INNER_CODEX_POLICY_ID: &str = "maco_external_codex_inner_v1";
#[cfg(target_os = "linux")]
pub(crate) const CODEX_WRITABLE_ROOT_PROTECTED_MOUNT_TARGETS: &[&str] =
    &[".git", ".agents", ".codex"];
const WORKTREE_DECLARED_ROOT_ID: &str = "worktree";
const PERMANENT_CONTROL_ROOTS: &[&str] = &[".maco", ".maco-cache", ".codex"];
const POLICY_CONTROL_ROOTS: &[&str] = &[".agents"];
const POLICY_CONTROL_FILES: &[&str] = &[
    ".gitignore",
    ".gitattributes",
    ".ignore",
    ".rgignore",
    ".dockerignore",
    ".cursorignore",
    ".cursorindexingignore",
    ".codexignore",
    "AGENTS.md",
    "CLAUDE.md",
];
const MAX_WORKTREE_CONTROL_EXCEPTIONS: usize = 128;
const MAX_SANDBOX_DENIAL_EVIDENCE: usize = 128;
const MAX_SANDBOX_DENIAL_PATH_BYTES: usize = 4 * 1024;
const MAX_CODEX_JSONL_EVENT_BYTES: usize = 256 * 1024;
const MAX_CODEX_EVENT_TEXT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_REQUIREMENTS: usize = 32;
const PRE_ACTION_JOURNAL_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
static OUTPUT_STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) trait PreActionJournalSink {
    fn append(&mut self, record: &PreActionJournalRecord) -> Result<()>;
}

pub(crate) struct ExternalPreActionReviewRuntime<'a> {
    pub(crate) context: &'a ReviewContext,
    pub(crate) journal: &'a mut dyn PreActionJournalSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PreActionJournalPhase {
    ReviewDecision,
    TurnTerminal,
    ProcessTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PreActionJournalRationale {
    DeterministicPolicyAllow,
    DeterministicPolicyDeny,
    ClassifierAllow,
    ClassifierFailClosed,
    HumanInterventionRequired,
    LatencyBudgetExceeded,
    DuplexFallbackRequired,
    TerminalEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreActionJournalRecord {
    pub(crate) version: u32,
    pub(crate) run_id: String,
    pub(crate) review_session_id: String,
    pub(crate) phase: PreActionJournalPhase,
    pub(crate) thread_id: Option<String>,
    pub(crate) turn_id: Option<String>,
    pub(crate) item_id: Option<String>,
    pub(crate) request: Option<RedactedClassifierRequest>,
    pub(crate) decision_source: Option<DecisionSource>,
    pub(crate) decision_latency_ms: Option<u64>,
    pub(crate) rationale: PreActionJournalRationale,
    pub(crate) allowed: Option<bool>,
    pub(crate) denial: Option<GateDenial>,
    pub(crate) turn_status: Option<codex_app_server::TurnTerminalStatus>,
    pub(crate) item_outcomes: Vec<codex_app_server::ItemOutcome>,
    pub(crate) process_exit_code: Option<i32>,
    pub(crate) process_tree: Option<ProcessTreeEvidence>,
    pub(crate) side_effects: Option<SideEffectConfinementEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexRuntimeModelCatalog {
    slugs: BTreeSet<String>,
}

impl CodexRuntimeModelCatalog {
    pub(crate) fn from_slugs(slugs: impl IntoIterator<Item = impl Into<String>>) -> Result<Self> {
        let slugs = slugs.into_iter().map(Into::into).collect::<Vec<_>>();
        if slugs.is_empty() {
            bail!("Codex runtime model catalog must contain at least one model");
        }
        if slugs.len() > CODEX_MODEL_CATALOG_MAX_MODELS {
            bail!(
                "Codex runtime model catalog contains {} models, exceeding the {} model limit",
                slugs.len(),
                CODEX_MODEL_CATALOG_MAX_MODELS
            );
        }
        let mut validated = BTreeSet::new();
        for slug in slugs {
            validate_codex_model_slug(&slug)?;
            if !validated.insert(slug.clone()) {
                bail!("Codex runtime model catalog contains duplicate slug '{slug}'");
            }
        }
        Ok(Self { slugs: validated })
    }

    pub(crate) fn contains(&self, slug: &str) -> bool {
        self.slugs.contains(slug)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentCommand {
    pub invocation: ExternalAgentInvocation,
    pub program: PathBuf,
    pub cwd: PathBuf,
    pub prompt: PathBuf,
    pub json_log: PathBuf,
    pub output_last_message: PathBuf,
    pub output_schema: Option<PathBuf>,
    /// Exact bounded regular files exposed read-only without exposing their parent directories.
    pub read_only_input_files: Vec<PathBuf>,
    /// Typed precreated worker journals bound to the original incoming report root.
    pub worker_journal_artifacts: Vec<WorkerJournalArtifactSpec>,
    pub timeout: Duration,
    pub workspace_access: WorkspaceAccess,
    pub hidden_roots: Vec<PathBuf>,
    /// Optional model for the primary Codex process. Absence deliberately leaves model selection
    /// to the same runtime defaults used before this field existed.
    pub model: Option<String>,
    /// Optional Codex model-provider id. When present it is passed as strict runtime configuration
    /// and never silently replaced with the runtime default.
    pub model_provider: Option<String>,
    /// Optional reasoning effort for the primary Codex process.
    pub reasoning_effort: Option<String>,
    /// Optional lifecycle identity for the long-running provider process. `registry_repo` is the
    /// supervisor repository whose `.maco/agents` state operators inspect, which can differ from
    /// `cwd` when the provider runs inside a linked assignment worktree.
    pub agent_lifecycle: Option<ExternalAgentLifecycleIdentity>,
    /// Exact normalized workspace-relative exceptions to the default read-only policy controls.
    /// Linked-worktree Git metadata and MACO/Codex runtime roots are never writable exceptions.
    pub worktree_control_exceptions: Vec<PathBuf>,
    /// Bounded, typed environment capabilities that must be verified before the target is
    /// released. Every executable variant maps to a MACO-owned fixed version probe; assignments
    /// cannot provide commands or arguments.
    pub environment_requirements: Vec<EnvironmentRequirement>,
    /// Explicit binding for recoverable cleanup of the private machine-global output staging
    /// directory. Absence keeps the legacy path as an attributed cooperative bypass.
    pub machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    pub runtime_adapter: Option<RuntimeAdapterConfig>,
    /// Isolated child worktree vs primary checkout. Default constructors use a
    /// managed child worktree; primary-target launch stays fail-closed.
    pub writable_launch_target: WritableLaunchTarget,
    /// Opaque supervisor-selected launch identity. Only the MACO assignment binder can create
    /// this evidence; writable Grok admission rechecks it against the live command so a later
    /// model, effort, executable, cwd, invocation, or adapter-config change fails closed.
    writable_runtime_selection: Option<WritableRuntimeSelectionEvidence>,
    /// Opaque MACO-owned proof that the selected command, held claims, disposable worktree, and
    /// verified native confinement were authenticated together immediately before launch.
    worktree_writable_confinement: Option<WorktreeWritableConfinementProof>,
}

pub(crate) const WRITABLE_GROK_TERMINAL_WORKER_REQUIRED: &str =
    "writable_grok_terminal_worker_required";
pub(crate) const WRITABLE_GROK_SELECTION_EVIDENCE_MISSING: &str =
    "writable_grok_selection_evidence_missing";
pub(crate) const WRITABLE_GROK_SELECTION_EVIDENCE_STALE: &str =
    "writable_grok_selection_evidence_stale";
pub(crate) const WRITABLE_GROK_EXACT_MODEL_REQUIRED: &str = "writable_grok_exact_model_required";
pub(crate) const WRITABLE_GROK_XHIGH_EFFORT_REQUIRED: &str = "writable_grok_xhigh_effort_required";
pub(crate) const WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED: &str =
    "writable_grok_adapter_configuration_unverified";
pub(crate) const WRITABLE_GROK_CONFINEMENT_PROOF_MISSING: &str =
    "writable_grok_confinement_proof_missing";
pub(crate) const WRITABLE_GROK_CONFINEMENT_PROOF_STALE: &str =
    "writable_grok_confinement_proof_stale";
pub(crate) const WRITABLE_GROK_CONFINEMENT_UNVERIFIED: &str =
    "writable_grok_confinement_unverified";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableRuntimeSelectionEvidence {
    assignment_id: String,
    runtime: RuntimeId,
    invocation: ExternalAgentInvocation,
    program: PathBuf,
    cwd: PathBuf,
    model: Option<String>,
    reasoning_effort: Option<String>,
    adapter_config: Option<RuntimeAdapterConfig>,
}

impl WritableRuntimeSelectionEvidence {
    fn from_command(
        assignment_id: impl Into<String>,
        runtime: RuntimeId,
        command: &ExternalAgentCommand,
    ) -> Self {
        Self {
            assignment_id: assignment_id.into(),
            runtime,
            invocation: command.invocation,
            program: command.program.clone(),
            cwd: command.cwd.clone(),
            model: command.model.clone(),
            reasoning_effort: command.reasoning_effort.clone(),
            adapter_config: command.runtime_adapter.clone(),
        }
    }

    fn matches_command(&self, command: &ExternalAgentCommand, runtime: RuntimeId) -> bool {
        self.runtime == runtime
            && self.invocation == command.invocation
            && self.program == command.program
            && self.cwd == command.cwd
            && self.model == command.model
            && self.reasoning_effort == command.reasoning_effort
            && self.adapter_config == command.runtime_adapter
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeWritableConfinementProof {
    admission: WorktreeWritableAdmission,
    selected_launch: Option<WritableRuntimeSelectionEvidence>,
    command: WorktreeConfinementSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeConfinementSnapshot {
    prompt: PathBuf,
    json_log: PathBuf,
    output_last_message: PathBuf,
    output_schema: Option<PathBuf>,
    read_only_input_files: Vec<PathBuf>,
    worker_journal_artifacts: Vec<WorkerJournalArtifactSpec>,
    workspace_access: WorkspaceAccess,
    hidden_roots: Vec<PathBuf>,
    worktree_control_exceptions: Vec<PathBuf>,
    writable_launch_target: WritableLaunchTarget,
}

impl WorktreeConfinementSnapshot {
    fn from_command(command: &ExternalAgentCommand) -> Self {
        Self {
            prompt: command.prompt.clone(),
            json_log: command.json_log.clone(),
            output_last_message: command.output_last_message.clone(),
            output_schema: command.output_schema.clone(),
            read_only_input_files: command.read_only_input_files.clone(),
            worker_journal_artifacts: command.worker_journal_artifacts.clone(),
            workspace_access: command.workspace_access,
            hidden_roots: command.hidden_roots.clone(),
            worktree_control_exceptions: command.worktree_control_exceptions.clone(),
            writable_launch_target: command.writable_launch_target,
        }
    }

    fn matches_command(&self, command: &ExternalAgentCommand) -> bool {
        self == &Self::from_command(command)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerJournalArtifactSpec {
    pub worker_id: String,
    pub incoming_root: PathBuf,
    pub path: PathBuf,
}

pub type ExternalMachineGlobalRetentionBinding = MachineGlobalRetentionBinding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentLifecycleIdentity {
    pub registry_repo: PathBuf,
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAgentInvocation {
    CodexSupervisor,
    CodexConsultant,
    ClaudeConsultant,
    Grok,
    Cursor,
    ClaudeCode,
    GeminiCli,
}

impl ExternalAgentInvocation {
    pub const fn is_adapter_subprocess(self) -> bool {
        matches!(
            self,
            Self::Grok | Self::Cursor | Self::ClaudeCode | Self::GeminiCli
        )
    }

    pub const fn adapter_id(self) -> Option<AdapterId> {
        match self {
            Self::CodexSupervisor | Self::CodexConsultant => Some(AdapterId::Codex),
            Self::ClaudeConsultant | Self::ClaudeCode => Some(AdapterId::ClaudeCode),
            Self::Grok => Some(AdapterId::Grok),
            Self::Cursor => Some(AdapterId::Cursor),
            Self::GeminiCli => Some(AdapterId::GeminiCli),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProgramTrust {
    TrustedSystemCodex,
    ExplicitCustom,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CodexPermissionEvidence {
    pub codex_version: String,
    pub minimum_version: String,
    pub permission_profile: String,
    pub workspace_access: WorkspaceAccess,
    pub network_enabled: bool,
    pub argv_digest: String,
    pub executable_identity: String,
}

pub const WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedWorktreeAdmissionKind {
    ManagedDisposable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWorktreeAdmission {
    pub kind: ManagedWorktreeAdmissionKind,
    pub worktree_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldPathClaimsAdmissionState {
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeldPathClaimsAdmission {
    pub state: HeldPathClaimsAdmissionState,
    pub token: u64,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSandboxAdmission {
    pub runtime: RuntimeId,
    pub workspace_access: WorkspaceAccess,
    pub side_effect_confinement: SideEffectConfinement,
}

/// Parent-derived evidence that all three managed-worktree writable conditions held together.
/// Primary-worktree execution uses the separate universal callback gate and is never represented
/// by this record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeWritableAdmission {
    pub version: u32,
    pub assignment_id: String,
    pub attempt: usize,
    pub target: WritableLaunchTarget,
    pub worktree: ManagedWorktreeAdmission,
    pub claims: HeldPathClaimsAdmission,
    pub native_sandbox: NativeSandboxAdmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl EnvironmentVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for EnvironmentVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVersionConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_inclusive: Option<EnvironmentVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_exclusive: Option<EnvironmentVersion>,
}

impl EnvironmentVersionConstraint {
    pub const fn at_least(minimum: EnvironmentVersion) -> Self {
        Self {
            minimum_inclusive: Some(minimum),
            maximum_exclusive: None,
        }
    }

    pub const fn bounded(
        minimum: EnvironmentVersion,
        maximum_exclusive: EnvironmentVersion,
    ) -> Self {
        Self {
            minimum_inclusive: Some(minimum),
            maximum_exclusive: Some(maximum_exclusive),
        }
    }

    fn validate(self) -> Result<()> {
        if self.minimum_inclusive.is_none() && self.maximum_exclusive.is_none() {
            bail!("environment version constraint must have at least one bound");
        }
        if matches!(
            (self.minimum_inclusive, self.maximum_exclusive),
            (Some(minimum), Some(maximum)) if minimum >= maximum
        ) {
            bail!("environment version constraint minimum must be below its exclusive maximum");
        }
        Ok(())
    }

    const fn accepts(self, version: EnvironmentVersion) -> bool {
        let meets_minimum = match self.minimum_inclusive {
            Some(minimum) => {
                version.major > minimum.major
                    || (version.major == minimum.major
                        && (version.minor > minimum.minor
                            || (version.minor == minimum.minor && version.patch >= minimum.patch)))
            }
            None => true,
        };
        let below_maximum = match self.maximum_exclusive {
            Some(maximum) => {
                version.major < maximum.major
                    || (version.major == maximum.major
                        && (version.minor < maximum.minor
                            || (version.minor == maximum.minor && version.patch < maximum.patch)))
            }
            None => true,
        };
        meets_minimum && below_maximum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentExecutable {
    Bash,
    Cargo,
    Cmake,
    Codex,
    Git,
    Nix,
    Node,
    Npm,
    Python3,
    Rustc,
}

impl EnvironmentExecutable {
    const fn program_name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Cargo => "cargo",
            Self::Cmake => "cmake",
            Self::Codex => "codex",
            Self::Git => "git",
            Self::Nix => "nix",
            Self::Node => "node",
            Self::Npm => "npm",
            Self::Python3 => "python3",
            Self::Rustc => "rustc",
        }
    }

    const fn version_arguments(self) -> &'static [&'static str] {
        match self {
            Self::Git => &["version"],
            Self::Nix => &["--version"],
            Self::Bash
            | Self::Cargo
            | Self::Cmake
            | Self::Codex
            | Self::Node
            | Self::Npm
            | Self::Python3
            | Self::Rustc => &["--version"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentCredential {
    CodexAccessToken,
    CodexApiKey,
    OpenAiApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentConfiguration {
    CodexAuthFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentNetworkAccess {
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentSandboxCapability {
    VerifiedExternalCodex,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentRequirement {
    Executable {
        executable: EnvironmentExecutable,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<EnvironmentVersionConstraint>,
    },
    Credential {
        credential: EnvironmentCredential,
    },
    Configuration {
        configuration: EnvironmentConfiguration,
    },
    Network {
        access: EnvironmentNetworkAccess,
    },
    Sandbox {
        capability: EnvironmentSandboxCapability,
    },
}

impl EnvironmentRequirement {
    pub const fn executable(
        executable: EnvironmentExecutable,
        version: Option<EnvironmentVersionConstraint>,
    ) -> Self {
        Self::Executable {
            executable,
            version,
        }
    }

    pub const fn credential(credential: EnvironmentCredential) -> Self {
        Self::Credential { credential }
    }

    pub const fn configuration(configuration: EnvironmentConfiguration) -> Self {
        Self::Configuration { configuration }
    }

    pub const fn network(access: EnvironmentNetworkAccess) -> Self {
        Self::Network { access }
    }

    pub const fn sandbox(capability: EnvironmentSandboxCapability) -> Self {
        Self::Sandbox { capability }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentPreflightStatus {
    Satisfied,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnvironmentPreflightObservation {
    ExecutableVersion {
        executable: EnvironmentExecutable,
        version: EnvironmentVersion,
    },
    CredentialPresent {
        credential: EnvironmentCredential,
    },
    ConfigurationPresent {
        configuration: EnvironmentConfiguration,
    },
    Network {
        enabled: bool,
    },
    Sandbox {
        profile: SideEffectConfinementProfileKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPreflightResult {
    pub requirement: EnvironmentRequirement,
    pub status: EnvironmentPreflightStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<EnvironmentPreflightObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentFailureCategory {
    MissingExecutable,
    VersionMismatch,
    MissingCredential,
    NetworkForbidden,
    SandboxUnavailable,
    ProbeFailed,
    RuntimeModelCatalogUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentRemediationScope {
    ProjectLocal,
    PersistentNixosHostSoftware,
    CredentialConfiguration,
    CapabilityPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRemediation {
    pub scope: EnvironmentRemediationScope,
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFailure {
    pub category: EnvironmentFailureCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement: Option<EnvironmentRequirement>,
    pub summary: String,
    pub remediation: Vec<EnvironmentRemediation>,
}

impl EnvironmentFailure {
    pub(crate) fn sandbox_unavailable(summary: String) -> Self {
        environment_failure(
            EnvironmentFailureCategory::SandboxUnavailable,
            None,
            summary,
        )
    }

    pub(crate) fn probe_failed(summary: String) -> Self {
        environment_failure(EnvironmentFailureCategory::ProbeFailed, None, summary)
    }

    pub(crate) fn runtime_model_catalog(summary: String) -> Self {
        environment_failure(
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable,
            None,
            summary,
        )
    }
}

impl std::fmt::Display for EnvironmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.summary)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialBoundary {
    OuterSystemd,
    InnerCodex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDeniedOperation {
    EstablishBoundary,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxDenialEvidence {
    pub boundary: SandboxDenialBoundary,
    pub policy_id: String,
    pub operation: SandboxDeniedOperation,
    /// A safe workspace-relative path. Absolute host paths and untrusted free-form paths are never
    /// copied into this field.
    pub path: Option<PathBuf>,
    pub retryability: SandboxDenialRetryability,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxDenialEvidenceWireRef<'a> {
    boundary: SandboxDenialBoundary,
    policy_id: &'a str,
    operation: SandboxDeniedOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: &'a Option<PathBuf>,
    retryability: SandboxDenialRetryability,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxDenialEvidenceWireOwned {
    boundary: SandboxDenialBoundary,
    policy_id: String,
    operation: SandboxDeniedOperation,
    #[serde(default)]
    path: Option<PathBuf>,
    retryability: SandboxDenialRetryability,
}

impl Serialize for SandboxDenialEvidence {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        validate_sandbox_denial_evidence(self).map_err(serde::ser::Error::custom)?;
        SandboxDenialEvidenceWireRef {
            boundary: self.boundary,
            policy_id: &self.policy_id,
            operation: self.operation,
            path: &self.path,
            retryability: self.retryability,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SandboxDenialEvidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SandboxDenialEvidenceWireOwned::deserialize(deserializer)?;
        let evidence = Self {
            boundary: wire.boundary,
            policy_id: wire.policy_id,
            operation: wire.operation,
            path: wire.path,
            retryability: wire.retryability,
        };
        validate_sandbox_denial_evidence(&evidence).map_err(serde::de::Error::custom)?;
        Ok(evidence)
    }
}

fn validate_sandbox_denial_evidence(
    evidence: &SandboxDenialEvidence,
) -> std::result::Result<(), &'static str> {
    match evidence.boundary {
        SandboxDenialBoundary::OuterSystemd => {
            if evidence.policy_id != OUTER_SYSTEMD_POLICY_ID
                || evidence.operation != SandboxDeniedOperation::EstablishBoundary
                || evidence.path.is_some()
                || evidence.retryability != SandboxDenialRetryability::NotRetryable
            {
                return Err("invalid outer sandbox-denial policy evidence");
            }
        }
        SandboxDenialBoundary::InnerCodex => {
            if evidence.policy_id != INNER_CODEX_POLICY_ID
                || evidence.operation != SandboxDeniedOperation::Write
            {
                return Err("invalid inner sandbox-denial policy evidence");
            }
            let path = evidence
                .path
                .as_deref()
                .ok_or("inner sandbox-denial evidence requires a protected path")?;
            let expected_retryability = validate_sandbox_denial_path(path)?;
            if evidence.retryability != expected_retryability {
                return Err("sandbox-denial retryability does not match protected path policy");
            }
        }
    }
    Ok(())
}

fn validate_sandbox_denial_path(
    path: &Path,
) -> std::result::Result<SandboxDenialRetryability, &'static str> {
    let text = path
        .as_os_str()
        .to_str()
        .ok_or("sandbox-denial path must be valid UTF-8")?;
    if text.is_empty()
        || text.len() > MAX_SANDBOX_DENIAL_PATH_BYTES
        || path.is_absolute()
        || text
            .chars()
            .any(|character| character.is_control() || matches!(character, '\\' | ':'))
    {
        return Err("sandbox-denial path is not a safe workspace-relative path");
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err("sandbox-denial path must already be normalized");
            }
        }
    }
    if normalized.as_os_str().is_empty() || normalized.as_os_str() != path.as_os_str() {
        return Err("sandbox-denial path must already be normalized");
    }

    if path == Path::new(".git")
        || PERMANENT_CONTROL_ROOTS
            .iter()
            .any(|root| path.starts_with(root))
    {
        return Ok(SandboxDenialRetryability::NotRetryable);
    }
    if POLICY_CONTROL_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
        || POLICY_CONTROL_FILES
            .iter()
            .any(|file| path == Path::new(file))
    {
        return Ok(SandboxDenialRetryability::RequiresDeclaredException);
    }
    Err("sandbox-denial path is outside the protected control set")
}

fn canonicalize_sandbox_denials(
    mut evidence: Vec<SandboxDenialEvidence>,
) -> std::result::Result<Vec<SandboxDenialEvidence>, &'static str> {
    if evidence.len() > MAX_SANDBOX_DENIAL_EVIDENCE {
        return Err("sandbox-denial evidence exceeds the bounded entry count");
    }
    for item in &evidence {
        validate_sandbox_denial_evidence(item)?;
    }
    evidence.sort();
    if evidence.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("sandbox-denial evidence contains duplicate entries");
    }
    Ok(evidence)
}

impl ExternalAgentCommand {
    pub fn codex(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexSupervisor,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            read_only_input_files: Vec::new(),
            worker_journal_artifacts: Vec::new(),
            timeout,
            workspace_access: WorkspaceAccess::ReadWrite,
            hidden_roots: Vec::new(),
            model: None,
            model_provider: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
            environment_requirements: Vec::new(),
            machine_global_retention: None,
            runtime_adapter: None,
            writable_launch_target: WritableLaunchTarget::ManagedChildWorktree,
            writable_runtime_selection: None,
            worktree_writable_confinement: None,
        }
    }

    pub fn codex_read_only_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            read_only_input_files: Vec::new(),
            worker_journal_artifacts: Vec::new(),
            timeout,
            workspace_access: WorkspaceAccess::ReadOnly,
            hidden_roots: Vec::new(),
            model: None,
            model_provider: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
            environment_requirements: Vec::new(),
            machine_global_retention: None,
            runtime_adapter: None,
            writable_launch_target: WritableLaunchTarget::ManagedChildWorktree,
            writable_runtime_selection: None,
            worktree_writable_confinement: None,
        }
    }

    pub fn claude_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::ClaudeConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            read_only_input_files: Vec::new(),
            worker_journal_artifacts: Vec::new(),
            timeout,
            workspace_access: WorkspaceAccess::ReadOnly,
            hidden_roots: Vec::new(),
            model: None,
            model_provider: None,
            reasoning_effort: None,
            agent_lifecycle: None,
            worktree_control_exceptions: Vec::new(),
            environment_requirements: Vec::new(),
            machine_global_retention: None,
            runtime_adapter: None,
            writable_launch_target: WritableLaunchTarget::ManagedChildWorktree,
            writable_runtime_selection: None,
            worktree_writable_confinement: None,
        }
    }

    pub fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.hidden_roots.push(root.into());
        self
    }

    pub fn with_read_only_input_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only_input_files.push(path.into());
        self
    }

    pub fn with_worker_journal_artifact(
        mut self,
        worker_id: impl Into<String>,
        incoming_root: impl Into<PathBuf>,
        path: impl Into<PathBuf>,
    ) -> Self {
        self.worker_journal_artifacts
            .push(WorkerJournalArtifactSpec {
                worker_id: worker_id.into(),
                incoming_root: incoming_root.into(),
                path: path.into(),
            });
        self
    }

    pub fn with_runtime_adapter(
        mut self,
        runtime: RuntimeId,
        mut config: RuntimeAdapterConfig,
    ) -> Self {
        if runtime.is_adapter_subprocess() {
            config.binary = Some(self.program.clone());
            self.invocation = match runtime {
                RuntimeId::Grok => ExternalAgentInvocation::Grok,
                RuntimeId::Cursor => ExternalAgentInvocation::Cursor,
                RuntimeId::ClaudeCode => ExternalAgentInvocation::ClaudeCode,
                RuntimeId::GeminiCli => ExternalAgentInvocation::GeminiCli,
                RuntimeId::Codex | RuntimeId::Fake => {
                    return self;
                }
            };
            self.runtime_adapter = Some(config);
        }
        self
    }

    pub fn with_workspace_access(mut self, access: WorkspaceAccess) -> Self {
        self.workspace_access = access;
        self
    }

    pub fn with_model_selection(
        mut self,
        model: Option<String>,
        reasoning_effort: Option<String>,
    ) -> Self {
        self.model = model;
        self.reasoning_effort = reasoning_effort;
        self
    }

    /// Bind the supervisor-resolved identity used for writable Grok admission.
    ///
    /// This is deliberately crate-private and snapshots the already rendered command rather than
    /// accepting provider-controlled evidence. Both writable consumers compare the snapshot with
    /// the live command and independently re-prove the immutable adapter contract.
    pub(crate) fn with_writable_runtime_selection(
        mut self,
        assignment_id: impl Into<String>,
        runtime: RuntimeId,
        non_delegating_terminal_worker: bool,
    ) -> Result<Self> {
        if runtime != RuntimeId::Grok || !non_delegating_terminal_worker {
            bail!(
                "{WRITABLE_GROK_TERMINAL_WORKER_REQUIRED}: writable Grok requires an explicitly bound non-delegating terminal Worker"
            );
        }
        if self.invocation != ExternalAgentInvocation::Grok {
            bail!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_STALE}: selected Grok runtime does not match the executable invocation"
            );
        }
        self.writable_runtime_selection = Some(WritableRuntimeSelectionEvidence::from_command(
            assignment_id,
            runtime,
            &self,
        ));
        self.worktree_writable_confinement = None;
        Ok(self)
    }

    /// Attach the parent-authenticated managed-worktree proof to the exact selected launch.
    /// A later command mutation cannot reuse it because verification compares both snapshots.
    pub(crate) fn with_worktree_writable_confinement(
        mut self,
        admission: WorktreeWritableAdmission,
    ) -> Self {
        self.worktree_writable_confinement = Some(WorktreeWritableConfinementProof {
            admission,
            selected_launch: self.writable_runtime_selection.clone(),
            command: WorktreeConfinementSnapshot::from_command(&self),
        });
        self
    }

    fn current_grok_writable_contract(&self) -> Result<TypedRuntimeContract> {
        if self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree {
            bail!(
                "writable_grok_managed_worktree_required: writable Grok is restricted to a managed child worktree"
            );
        }
        if self.model.as_deref() != Some(TypedRuntime::Grok46Xhigh.model()) {
            bail!(
                "{WRITABLE_GROK_EXACT_MODEL_REQUIRED}: writable Grok requires exact model '{}'",
                TypedRuntime::Grok46Xhigh.model()
            );
        }
        if self.reasoning_effort.as_deref() != Some(TypedRuntime::Grok46Xhigh.reasoning_effort()) {
            bail!(
                "{WRITABLE_GROK_XHIGH_EFFORT_REQUIRED}: writable Grok requires exact reasoning effort '{}'",
                TypedRuntime::Grok46Xhigh.reasoning_effort()
            );
        }
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_MISSING}: writable Grok has no supervisor-selected launch evidence"
            )
        })?;
        if !selected.matches_command(self, RuntimeId::Grok) {
            bail!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_STALE}: writable Grok launch no longer matches its supervisor-selected evidence"
            );
        }
        let config = self.runtime_adapter.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Grok has no adapter configuration"
            )
        })?;
        if self.invocation != ExternalAgentInvocation::Grok
            || config.binary_path() != self.program.as_path()
        {
            bail!(
                "{WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Grok adapter executable is not bound to the selected program"
            );
        }
        config
            .typed_runtime_contract(
                AdapterId::Grok,
                &LaunchContext {
                    prompt: &self.prompt,
                    model: self.model.as_deref(),
                    effort: self.reasoning_effort.as_deref(),
                    cwd: &self.cwd,
                    output: &self.output_last_message,
                },
            )
            .with_context(|| {
                format!(
                    "{WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Grok adapter contract is not the immutable bounded 4.6/xhigh contract"
                )
            })
    }

    /// Concrete capabilities used by the supervisor while creating MACO-owned confinement
    /// evidence. Static capabilities remain authoritative for every non-Grok runtime.
    pub(crate) fn selected_writable_capabilities(
        &self,
        runtime: RuntimeId,
        expected_assignment_id: Option<&str>,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        if runtime != RuntimeId::Grok {
            return Ok(runtime.capabilities());
        }
        let contract = self.current_grok_writable_contract()?;
        if expected_assignment_id.is_some_and(|expected| {
            self.writable_runtime_selection
                .as_ref()
                .is_none_or(|selected| selected.assignment_id != expected)
        }) {
            bail!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_STALE}: writable Grok selection evidence belongs to a different assignment"
            );
        }
        Ok(contract.capabilities())
    }

    /// Concrete capabilities used at the external process boundary. Writable Grok must carry the
    /// exact MACO-owned proof produced after worktree and claim reauthentication.
    fn verified_writable_capabilities(
        &self,
        runtime: RuntimeId,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        let capabilities = self.selected_writable_capabilities(runtime, None)?;
        if runtime != RuntimeId::Grok {
            return Ok(capabilities);
        }
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_MISSING}: writable Grok selection evidence disappeared before confinement verification"
            )
        })?;
        let proof = self.worktree_writable_confinement.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_CONFINEMENT_PROOF_MISSING}: writable Grok has no MACO-owned managed-worktree confinement proof"
            )
        })?;
        if proof.selected_launch.as_ref() != Some(selected) || !proof.command.matches_command(self)
        {
            bail!(
                "{WRITABLE_GROK_CONFINEMENT_PROOF_STALE}: writable Grok confinement proof does not bind the current selected launch"
            );
        }
        let admission = &proof.admission;
        if admission.version != WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION
            || admission.assignment_id != selected.assignment_id
            || admission.target != WritableLaunchTarget::ManagedChildWorktree
            || admission.worktree.kind != ManagedWorktreeAdmissionKind::ManagedDisposable
            || admission.worktree.worktree_id != selected.assignment_id
            || admission.claims.state != HeldPathClaimsAdmissionState::Held
            || admission.native_sandbox.runtime != RuntimeId::Grok
            || admission.native_sandbox.workspace_access != WorkspaceAccess::ReadWrite
            || admission.native_sandbox.side_effect_confinement != SideEffectConfinement::Verified
            || self.workspace_access != WorkspaceAccess::ReadWrite
        {
            bail!(
                "{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: writable Grok confinement proof does not authenticate the current bounded managed-worktree launch"
            );
        }
        Ok(capabilities)
    }

    pub fn with_model_provider(mut self, model_provider: Option<String>) -> Self {
        self.model_provider = model_provider;
        self
    }

    pub fn with_agent_lifecycle(
        mut self,
        registry_repo: impl Into<PathBuf>,
        role: impl Into<String>,
        run_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        self.agent_lifecycle = Some(ExternalAgentLifecycleIdentity {
            registry_repo: registry_repo.into(),
            role: role.into(),
            run_id: run_id.into(),
            task_id: task_id.into(),
            parent: None,
        });
        self
    }

    pub fn with_agent_parent(mut self, parent: impl Into<String>) -> Self {
        if let Some(identity) = &mut self.agent_lifecycle {
            identity.parent = Some(parent.into());
        }
        self
    }

    pub fn with_worktree_control_exception(mut self, relative: impl Into<PathBuf>) -> Self {
        self.worktree_control_exceptions.push(relative.into());
        self
    }

    pub fn with_environment_requirement(mut self, requirement: EnvironmentRequirement) -> Self {
        self.environment_requirements.push(requirement);
        self
    }

    pub fn with_environment_requirements(
        mut self,
        requirements: impl IntoIterator<Item = EnvironmentRequirement>,
    ) -> Self {
        self.environment_requirements.extend(requirements);
        self
    }

    pub fn with_machine_global_retention(
        mut self,
        binding: ExternalMachineGlobalRetentionBinding,
    ) -> Self {
        self.machine_global_retention = Some(binding);
        self
    }

    pub fn with_writable_launch_target(mut self, target: WritableLaunchTarget) -> Self {
        self.writable_launch_target = target;
        self
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalAgentRun {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    /// Present only after the shared runner starts and closes the owned execution boundary.
    pub process_tree: Option<ProcessTreeEvidence>,
    pub side_effects: Option<SideEffectConfinementEvidence>,
    pub publishable: bool,
    pub program_trust: ExternalProgramTrust,
    pub codex_permissions: Option<CodexPermissionEvidence>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub error: Option<String>,
    /// Descriptor-captured final output. This is deliberately excluded from the public report
    /// surface so callers cannot confuse a tainted pathname with the held capability.
    pub(crate) output_last_message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGlobalBypassAttribution {
    pub actor: String,
    pub operation: String,
    pub process_attribution: String,
    pub reason: String,
}

impl std::fmt::Debug for ExternalAgentRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held_output = self
            .output_last_message
            .as_ref()
            .map(|contents| RedactedByteCount(contents.len()));
        formatter
            .debug_struct("ExternalAgentRun")
            .field("command", &self.command)
            .field("cwd", &self.cwd)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("exit_code", &self.exit_code)
            .field("duration_ms", &self.duration_ms)
            .field("timed_out", &self.timed_out)
            .field("process_tree", &self.process_tree)
            .field("side_effects", &self.side_effects)
            .field("publishable", &self.publishable)
            .field("program_trust", &self.program_trust)
            .field("codex_permissions", &self.codex_permissions)
            .field(
                "environment_preflight_results",
                &self.environment_preflight_results(),
            )
            .field("environment_failures", &self.environment_failures())
            .field(
                "environment_preflight_process_started",
                &self
                    .stdout
                    .run_metadata
                    .environment_preflight_process_started,
            )
            .field("sandbox_denials", &self.sandbox_denials())
            .field("worker_journal_artifacts", &self.worker_journal_artifacts())
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("error", &self.error)
            .field("output_last_message", &held_output)
            .finish()
    }
}

struct RedactedByteCount(usize);

impl std::fmt::Debug for RedactedByteCount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "<redacted:{} bytes>", self.0)
    }
}

impl ExternalAgentRun {
    pub fn environment_preflight_results(&self) -> &[EnvironmentPreflightResult] {
        &self.stdout.run_metadata.environment_preflight_results
    }

    pub fn environment_failures(&self) -> &[EnvironmentFailure] {
        &self.stdout.run_metadata.environment_failures
    }

    pub fn environment_blocked(&self) -> bool {
        !self.environment_failures().is_empty()
    }

    /// Returns whether an environment refusal is safe to treat as terminal without a separate
    /// containment failure.
    ///
    /// A static refusal may happen before any probe process starts. Once a probe starts, the
    /// trusted runner must retain proof that both its owned process tree and side effects were
    /// contained. Missing or unverified evidence therefore remains fail-closed.
    pub(crate) fn environment_preflight_quiescence_verified(&self) -> bool {
        self.environment_blocked() && self.scratch_quiescence_verified()
    }

    pub fn sandbox_denials(&self) -> &[SandboxDenialEvidence] {
        &self.stdout.run_metadata.sandbox_denials
    }

    pub fn gate_denials(&self) -> &[GateDenial] {
        &self.stdout.run_metadata.gate_denials
    }

    pub(crate) fn worker_journal_artifacts(&self) -> &[WorkerJournalArtifactCapture] {
        &self.stdout.run_metadata.worker_journal_artifacts
    }

    pub(crate) fn replace_worker_journal_artifacts(
        &mut self,
        captures: Vec<WorkerJournalArtifactCapture>,
    ) {
        self.stdout.run_metadata.worker_journal_artifacts = captures;
    }

    pub fn machine_global_bypasses(&self) -> &[MachineGlobalBypassAttribution] {
        &self.stdout.run_metadata.machine_global_bypasses
    }

    pub fn machine_global_retention_operation_id(&self) -> Option<RetentionOperationId> {
        self.stdout
            .run_metadata
            .machine_global_retention_operation_id
    }

    pub fn pre_action_review_metrics(&self) -> Option<&ReviewMetricSnapshot> {
        self.stdout.run_metadata.pre_action_review_metrics.as_ref()
    }

    /// Returns a typed external-effect observation attached by the trusted host runner.
    ///
    /// This held metadata is not decoded from child output and is deliberately excluded from the
    /// serialized run wire format.
    pub(crate) fn external_side_effect_state(&self) -> Option<ExternalSideEffectState> {
        self.stdout.run_metadata.external_side_effect_state
    }

    /// Attaches a host-observed external-effect state before the parent controller consumes the
    /// run. Child reports and serialized run values cannot set or preserve this held metadata.
    ///
    /// This crate-private seam is available to trusted host integrations; the current external
    /// runner leaves it empty unless such an integration supplies an observation.
    #[allow(dead_code)]
    pub(crate) fn with_external_side_effect_state(
        mut self,
        state: ExternalSideEffectState,
    ) -> Self {
        self.stdout.run_metadata.external_side_effect_state = Some(state);
        self
    }

    pub fn safely_executed(&self) -> bool {
        self.exit_code == Some(0)
            && !self.timed_out
            && self.error.is_none()
            && self
                .process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && self
                .side_effects
                .is_some_and(SideEffectConfinementEvidence::is_verified)
            && self.codex_permissions.is_some()
    }

    pub fn succeeded(&self) -> bool {
        self.safely_executed() && self.publishable
    }

    pub(crate) fn simulation_succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.error.is_none() && !self.publishable
    }

    pub(crate) fn output_last_message(&self) -> Option<&[u8]> {
        self.output_last_message.as_deref()
    }

    /// Exact bounded prefix captured from the owned stdout pipe. The bytes are
    /// private held evidence and are deliberately excluded from serialization.
    pub(crate) fn stdout_bytes(&self) -> &[u8] {
        &self.stdout.bytes
    }

    /// Scratch output may be discarded only when the main target was never
    /// released and no preflight probe started, or every launched process is
    /// proven empty with verified side-effect confinement.
    pub(crate) fn scratch_quiescence_verified(&self) -> bool {
        if self.stdout.target_launch_attempted {
            return self
                .process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
                && self
                    .side_effects
                    .is_some_and(SideEffectConfinementEvidence::is_verified);
        }
        if self
            .stdout
            .run_metadata
            .environment_preflight_process_started
        {
            return self
                .stdout
                .run_metadata
                .environment_preflight_quiescence_verified
                || (self
                    .process_tree
                    .is_some_and(ProcessTreeEvidence::is_verified_empty)
                    && self
                        .side_effects
                        .is_some_and(SideEffectConfinementEvidence::is_verified));
        }
        true
    }
}

#[derive(Serialize)]
struct ExternalAgentRunWireRef<'a> {
    command: &'a [String],
    cwd: &'a Path,
    timeout_seconds: u64,
    exit_code: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_tree: &'a Option<ProcessTreeEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    side_effects: &'a Option<SideEffectConfinementEvidence>,
    publishable: bool,
    program_trust: ExternalProgramTrust,
    #[serde(skip_serializing_if = "Option::is_none")]
    codex_permissions: &'a Option<CodexPermissionEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    environment_preflight_results: &'a Vec<EnvironmentPreflightResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    environment_failures: &'a Vec<EnvironmentFailure>,
    environment_preflight_process_started: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sandbox_denials: Vec<SandboxDenialEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    gate_denials: &'a Vec<GateDenial>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    machine_global_bypasses: &'a Vec<MachineGlobalBypassAttribution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_global_retention_operation_id: &'a Option<RetentionOperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_action_review_metrics: &'a Option<ReviewMetricSnapshot>,
    stdout: &'a CapturedOutput,
    stderr: &'a CapturedOutput,
    error: &'a Option<String>,
}

#[derive(Deserialize)]
struct ExternalAgentRunWireOwned {
    command: Vec<String>,
    cwd: PathBuf,
    timeout_seconds: u64,
    exit_code: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
    #[serde(default)]
    process_tree: Option<ProcessTreeEvidence>,
    #[serde(default)]
    side_effects: Option<SideEffectConfinementEvidence>,
    publishable: bool,
    program_trust: ExternalProgramTrust,
    #[serde(default)]
    codex_permissions: Option<CodexPermissionEvidence>,
    #[serde(default)]
    environment_preflight_results: Vec<EnvironmentPreflightResult>,
    #[serde(default)]
    environment_failures: Vec<EnvironmentFailure>,
    #[serde(default = "default_environment_preflight_process_started")]
    environment_preflight_process_started: bool,
    #[serde(default)]
    sandbox_denials: Vec<SandboxDenialEvidence>,
    #[serde(default)]
    gate_denials: Vec<GateDenial>,
    #[serde(default)]
    machine_global_bypasses: Vec<MachineGlobalBypassAttribution>,
    #[serde(default)]
    machine_global_retention_operation_id: Option<RetentionOperationId>,
    #[serde(default)]
    pre_action_review_metrics: Option<ReviewMetricSnapshot>,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    error: Option<String>,
}

impl Serialize for ExternalAgentRun {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let sandbox_denials = canonicalize_sandbox_denials(self.sandbox_denials().to_vec())
            .map_err(serde::ser::Error::custom)?;
        ExternalAgentRunWireRef {
            command: &self.command,
            cwd: &self.cwd,
            timeout_seconds: self.timeout_seconds,
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            timed_out: self.timed_out,
            process_tree: &self.process_tree,
            side_effects: &self.side_effects,
            publishable: self.publishable,
            program_trust: self.program_trust,
            codex_permissions: &self.codex_permissions,
            environment_preflight_results: &self.stdout.run_metadata.environment_preflight_results,
            environment_failures: &self.stdout.run_metadata.environment_failures,
            environment_preflight_process_started: self
                .stdout
                .run_metadata
                .environment_preflight_process_started,
            sandbox_denials,
            gate_denials: &self.stdout.run_metadata.gate_denials,
            machine_global_bypasses: &self.stdout.run_metadata.machine_global_bypasses,
            machine_global_retention_operation_id: &self
                .stdout
                .run_metadata
                .machine_global_retention_operation_id,
            pre_action_review_metrics: &self.stdout.run_metadata.pre_action_review_metrics,
            stdout: &self.stdout,
            stderr: &self.stderr,
            error: &self.error,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExternalAgentRun {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ExternalAgentRunWireOwned::deserialize(deserializer)?;
        let sandbox_denials =
            canonicalize_sandbox_denials(wire.sandbox_denials).map_err(serde::de::Error::custom)?;
        let mut stdout = wire.stdout;
        stdout.run_metadata.environment_preflight_results = wire.environment_preflight_results;
        stdout.run_metadata.environment_failures = wire.environment_failures;
        stdout.run_metadata.environment_preflight_process_started =
            wire.environment_preflight_process_started;
        stdout.run_metadata.sandbox_denials = sandbox_denials;
        stdout.run_metadata.gate_denials = wire.gate_denials;
        stdout.run_metadata.machine_global_bypasses = wire.machine_global_bypasses;
        stdout.run_metadata.machine_global_retention_operation_id =
            wire.machine_global_retention_operation_id;
        stdout.run_metadata.pre_action_review_metrics = wire.pre_action_review_metrics;
        Ok(Self {
            command: wire.command,
            cwd: wire.cwd,
            timeout_seconds: wire.timeout_seconds,
            exit_code: wire.exit_code,
            duration_ms: wire.duration_ms,
            timed_out: wire.timed_out,
            process_tree: wire.process_tree,
            side_effects: wire.side_effects,
            publishable: wire.publishable,
            program_trust: wire.program_trust,
            codex_permissions: wire.codex_permissions,
            stdout,
            stderr: wire.stderr,
            error: wire.error,
            output_last_message: None,
        })
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ExternalAgentRunMetadata {
    environment_preflight_results: Vec<EnvironmentPreflightResult>,
    environment_failures: Vec<EnvironmentFailure>,
    environment_preflight_process_started: bool,
    /// Held proof for scratch cleanup after a probe-only run. This is never serialized: a
    /// restored report cannot confer cleanup authority, and a target launch must earn fresh
    /// process-tree and side-effect evidence on the shared run fields.
    environment_preflight_quiescence_verified: bool,
    sandbox_denials: Vec<SandboxDenialEvidence>,
    gate_denials: Vec<GateDenial>,
    machine_global_bypasses: Vec<MachineGlobalBypassAttribution>,
    machine_global_retention_operation_id: Option<RetentionOperationId>,
    pre_action_review_metrics: Option<ReviewMetricSnapshot>,
    external_side_effect_state: Option<ExternalSideEffectState>,
    worker_journal_artifacts: Vec<WorkerJournalArtifactCapture>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WorkerJournalArtifactCapture {
    pub(crate) worker_id: String,
    pub(crate) path: PathBuf,
    pub(crate) status: WorkerJournalArtifactCaptureStatus,
}

impl std::fmt::Debug for WorkerJournalArtifactCapture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerJournalArtifactCapture")
            .field("worker_id", &self.worker_id)
            .field("path", &self.path)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum WorkerJournalArtifactCaptureStatus {
    Loaded(Vec<u8>),
    Invalid(String),
}

impl std::fmt::Debug for WorkerJournalArtifactCaptureStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loaded(bytes) => formatter
                .debug_tuple("Loaded")
                .field(&RedactedByteCount(bytes.len()))
                .finish(),
            Self::Invalid(error) => formatter.debug_tuple("Invalid").field(error).finish(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapturedOutput {
    pub text: String,
    pub truncated: bool,
    #[serde(skip, default)]
    bytes: Vec<u8>,
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "default_target_launch_attempted"
    )]
    target_launch_attempted: bool,
    /// Private held metadata for the enclosing run. It is serialized only by
    /// `ExternalAgentRun` as the top-level `sandbox_denials` wire field.
    #[serde(skip, default)]
    run_metadata: ExternalAgentRunMetadata,
}

impl std::fmt::Debug for CapturedOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "CapturedOutput {{ text: {:?}, truncated: {:?}, bytes: <redacted:{} bytes> }}",
            self.text,
            self.truncated,
            self.bytes.len()
        )
    }
}

fn default_target_launch_attempted() -> bool {
    true
}

fn default_environment_preflight_process_started() -> bool {
    // Older serialized environment-blocked runs did not distinguish a static refusal from a
    // launched probe whose evidence was lost. Treat absence as launched so they cannot bypass
    // containment without retained evidence.
    true
}

pub fn run_external_agent(spec: &ExternalAgentCommand) -> ExternalAgentRun {
    run_external_agent_cancellable(spec, &ProcessCancellation::new())
}

pub fn run_external_agent_cancellable(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
) -> ExternalAgentRun {
    run_external_agent_runtime(spec, ExternalExecutionRuntime::Verified, cancellation, None)
}

pub(crate) fn run_external_agent_cancellable_reviewed(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    forward_local_external_agent_run(
        &run_external_agent_cancellable_reviewed_local,
        spec,
        cancellation,
        review_runtime,
    )
}

fn forward_local_external_agent_run<Runner>(
    runner: &Runner,
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun
where
    Runner: for<'review> Fn(
            &ExternalAgentCommand,
            &ProcessCancellation,
            Option<ExternalPreActionReviewRuntime<'review>>,
        ) -> ExternalAgentRun
        + Send
        + Sync
        + ?Sized,
{
    executor::LocalExecutor.forward_existing_run(runner, spec, cancellation, review_runtime)
}

fn run_external_agent_cancellable_reviewed_local(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    run_external_agent_runtime(
        spec,
        ExternalExecutionRuntime::Verified,
        cancellation,
        review_runtime,
    )
}

#[cfg(test)]
pub(crate) fn run_external_agent_nonpublishable_simulation(
    spec: &ExternalAgentCommand,
) -> ExternalAgentRun {
    run_external_agent_nonpublishable_simulation_cancellable(spec, &ProcessCancellation::new())
}

#[cfg(test)]
fn run_external_agent_nonpublishable_simulation_cancellable(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
) -> ExternalAgentRun {
    run_external_agent_runtime(
        spec,
        ExternalExecutionRuntime::NonpublishableSimulation,
        cancellation,
        None,
    )
}

fn run_external_agent_runtime(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
    cancellation: &ProcessCancellation,
    mut review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    let started = Instant::now();
    if cancellation.is_cancelled() {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            "external agent was cancelled before executable preflight".to_string(),
        );
    }
    if spec.workspace_access == WorkspaceAccess::ReadWrite {
        if let Some(adapter) = spec.invocation.adapter_id() {
            let capabilities = if adapter == AdapterId::Grok
                && spec.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree
            {
                match spec.verified_writable_capabilities(RuntimeId::Grok) {
                    Ok(capabilities) => capabilities,
                    Err(error) => {
                        return failed_external_environment_run(
                            spec,
                            started,
                            command_display(&spec.program, &[]),
                            false,
                            EnvironmentFailureCategory::SandboxUnavailable,
                            Some(EnvironmentRequirement::sandbox(
                                EnvironmentSandboxCapability::VerifiedExternalCodex,
                            )),
                            format!("writable grok failed closed before launch: {error:#}"),
                        );
                    }
                }
            } else {
                adapter.capabilities()
            };
            if let Some(capability) =
                capabilities.writable_launch_refusal(spec.writable_launch_target)
            {
                return failed_external_environment_run(
                    spec,
                    started,
                    command_display(&spec.program, &[]),
                    false,
                    EnvironmentFailureCategory::SandboxUnavailable,
                    Some(EnvironmentRequirement::sandbox(
                        EnvironmentSandboxCapability::VerifiedExternalCodex,
                    )),
                    format!(
                        "writable {} failed closed before launch: {capability}",
                        adapter.as_str()
                    ),
                );
            }
        }
    }
    // Hosted duplex review is optional defense-in-depth. Isolated worktree
    // children launch with native permission/sandbox mode; they are not
    // blocked on a parent All-callback or a missing reviewer.
    let duplex_review_required = should_use_duplex_review(spec, runtime, review_runtime.is_some());
    if spec.workspace_access == WorkspaceAccess::ReadWrite
        && spec.writable_launch_target == WritableLaunchTarget::PrimaryWorktree
    {
        if let Err(error) = validate_universal_pre_action_coverage(spec.writable_launch_target) {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalCodex,
                )),
                error.to_string(),
            );
        }
    }
    let program_trust = external_program_trust(spec);
    let resolved_program = match resolve_external_program(&spec.program, &spec.cwd) {
        Ok(program) => program,
        Err(error) => {
            let mut report = failed_external_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                format!(
                    "failed to resolve external agent executable {}: {error}",
                    spec.program.display()
                ),
            );
            if spec.program == Path::new("codex") {
                let requirement = codex_environment_requirement();
                let category = if trusted_codex_fixed_candidate_exists() {
                    EnvironmentFailureCategory::ProbeFailed
                } else {
                    EnvironmentFailureCategory::MissingExecutable
                };
                report
                    .stdout
                    .run_metadata
                    .environment_preflight_results
                    .push(EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    });
                report
                    .stdout
                    .run_metadata
                    .environment_failures
                    .push(environment_failure(
                        category,
                        Some(requirement),
                        format!("trusted Codex executable preflight failed: {error}"),
                    ));
            } else {
                let summary = format!("explicit executable preflight failed: {error}");
                report
                    .stdout
                    .run_metadata
                    .environment_failures
                    .push(environment_failure(
                        EnvironmentFailureCategory::ProbeFailed,
                        None,
                        summary,
                    ));
            }
            return report;
        }
    };
    let program_identity = match external_program_identity(&resolved_program) {
        Ok(identity) => identity,
        Err(error) => {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&resolved_program, &[]),
                false,
                EnvironmentFailureCategory::ProbeFailed,
                None,
                format!("failed to capture external executable identity: {error}"),
            );
        }
    };
    if spec.workspace_access == WorkspaceAccess::ReadOnly
        && !spec.worktree_control_exceptions.is_empty()
    {
        return failed_external_run(
            spec,
            started,
            command_display(&resolved_program, &[]),
            false,
            "read-only external agents may not declare writable control exceptions".to_string(),
        );
    }
    let protected_controls = match protected_worktree_controls(spec) {
        Ok(controls) => controls,
        Err(error) => {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&resolved_program, &[]),
                false,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalCodex,
                )),
                format!("failed to validate protected worktree controls: {error}"),
            );
        }
    };
    let mut output_staging =
        match ExternalOutputStaging::create(&spec.cwd, spec.machine_global_retention.clone()) {
            Ok(staging) => staging,
            Err(error) => {
                return failed_external_run(
                    spec,
                    started,
                    command_display(&resolved_program, &[]),
                    false,
                    format!("failed to prepare private external-agent output staging: {error}"),
                );
            }
        };
    let mut target_spec = spec.clone();
    target_spec.output_last_message = match output_staging.path() {
        Ok(path) => path.to_path_buf(),
        Err(error) => {
            return failed_external_run(
                spec,
                started,
                command_display(&resolved_program, &[]),
                false,
                format!("private external-agent output staging became unavailable: {error:#}"),
            );
        }
    };
    let mut target_controls = protected_controls.clone();
    target_controls.writable_artifact_root = Some(output_staging.root_path().to_path_buf());
    // Duplex argv stays empty until the contained version probe matches the audited
    // app-server protocol. This remains a mandatory latent release gate even if
    // universal pre-action coverage becomes available in a future Codex protocol.
    let mut argv = if duplex_review_required {
        Vec::new()
    } else {
        match command_argv_with_controls(&target_spec, &target_controls) {
            Ok(argv) => argv,
            Err(error) => {
                return failed_external_run(
                    spec,
                    started,
                    command_display(&resolved_program, &[]),
                    false,
                    format!("runtime adapter launch configuration is invalid: {error:#}"),
                );
            }
        }
    };
    let mut bound_argv_digest = if duplex_review_required {
        None
    } else {
        match argv_digest(&argv) {
            Ok(digest) => Some(digest),
            Err(error) => {
                return failed_external_run(
                    spec,
                    started,
                    command_display(&resolved_program, &argv),
                    false,
                    format!("failed to bind external-agent permission evidence to argv: {error}"),
                );
            }
        }
    };

    let mut report = ExternalAgentRun {
        command: command_display(&resolved_program, &argv),
        cwd: spec.cwd.clone(),
        timeout_seconds: spec.timeout.as_secs(),
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust,
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
        output_last_message: None,
    };

    let mut codex_version = None;
    let mut preflight_process_evidence = EnvironmentPreflightProcessEvidence::default();
    let agent_lifecycle = match &spec.agent_lifecycle {
        Some(identity) => match AgentLaunchMetadata::new(
            &identity.registry_repo,
            &identity.role,
            &identity.run_id,
            &identity.task_id,
        )
        .and_then(|metadata| match &identity.parent {
            Some(parent) => metadata.with_parent(parent.clone()),
            None => Ok(metadata),
        }) {
            Ok(metadata) => Some(metadata),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("failed to prepare external-agent lifecycle identity: {error:#}"),
                );
                return report;
            }
        },
        None => None,
    };

    if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::ExplicitCustom
        && matches!(
            spec.invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        )
    {
        let requirement = codex_environment_requirement();
        let remaining = spec.timeout.saturating_sub(started.elapsed());
        match preflight_custom_codex_version(
            &resolved_program,
            &spec.cwd,
            remaining,
            cancellation,
            agent_lifecycle.as_ref(),
            &mut preflight_process_evidence,
        ) {
            Ok(probe) => {
                codex_version = Some((
                    probe.version.major,
                    probe.version.minor,
                    probe.version.patch,
                ));
                retain_environment_preflight_process_evidence(
                    &mut report,
                    &preflight_process_evidence,
                );
                report
                    .stdout
                    .run_metadata
                    .environment_preflight_results
                    .push(EnvironmentPreflightResult {
                        requirement,
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::ExecutableVersion {
                            executable: EnvironmentExecutable::Codex,
                            version: probe.version,
                        }),
                    });
            }
            Err(failure) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.timed_out = failure.timed_out;
                retain_environment_preflight_process_evidence(
                    &mut report,
                    &preflight_process_evidence,
                );
                report.error = Some(failure.failure.summary.clone());
                report
                    .stdout
                    .run_metadata
                    .environment_preflight_results
                    .push(EnvironmentPreflightResult {
                        requirement,
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    });
                report
                    .stdout
                    .run_metadata
                    .environment_failures
                    .push(*failure.failure);
                return report;
            }
        }
    }

    if cancellation.is_cancelled() {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "external agent was cancelled before target setup".to_string(),
        );
        return report;
    }

    if spec.invocation == ExternalAgentInvocation::ClaudeConsultant {
        report.duration_ms = duration_millis(started.elapsed());
        let capability = AdapterId::ClaudeCode
            .capabilities()
            .read_only_inner_contract_refusal()
            .unwrap_or("read_only_inner_contract unmet");
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
            format!(
                "external Claude runtime is refused because no enforceable inner read-only permission contract is available ({capability})"
            ),
        );
        return report;
    }

    // An explicit executable is useful only as a bounded, strict-offline version diagnostic.
    // Never give it repository-write authority, provider network access, ambient API keys, or a
    // copied Codex auth file. Nonpublishable evidence is not a substitute for preventing the
    // side effect in the first place.
    if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::ExplicitCustom
        && !spec.invocation.is_adapter_subprocess()
    {
        report.duration_ms = duration_millis(started.elapsed());
        // The held preflight bit proves only that the version diagnostic became quiescent for
        // scratch cleanup. Do not let its process evidence look like target containment evidence.
        report.process_tree = None;
        report.side_effects = None;
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
            "explicit custom executables are limited to a strict-offline version diagnostic; the external target was not started"
                .to_string(),
        );
        return report;
    }

    if let Err(error) = ensure_existing_output_parent(&spec.json_log)
        .and_then(|_| ensure_existing_output_parent(&spec.output_last_message))
        .and_then(|_| match &spec.output_schema {
            Some(path) => ensure_safe_read_target(path),
            None => Ok(()),
        })
        .and_then(|_| {
            spec.read_only_input_files
                .iter()
                .try_for_each(|path| ensure_safe_read_target(path))
        })
        .and_then(|_| ensure_safe_read_target(&spec.prompt))
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(&mut report, error.to_string());
        return report;
    }

    let mut output_reservation = match reserve_external_output(&spec.output_last_message) {
        Ok(reservation) => reservation,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("failed to reserve external-agent output: {error}"),
            );
            return report;
        }
    };

    let prompt = match read_bounded_regular_file_nofollow(&spec.prompt, MAX_PROMPT_BYTES) {
        Ok(prompt) => prompt,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!(
                    "failed to read prompt file {}: {error}",
                    spec.prompt.display()
                ),
            );
            return report;
        }
    };
    let duplex_prompt = if duplex_review_required {
        match String::from_utf8(prompt.clone()) {
            Ok(prompt) => Some(prompt),
            Err(_) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "writable Codex app-server prompt is not valid UTF-8".to_string(),
                );
                return report;
            }
        }
    } else {
        None
    };

    let codex_auth = if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::TrustedSystemCodex
    {
        match ValidatedCodexAuth::load() {
            Ok(auth) => auth,
            Err(error) => {
                let auth_failure = sanitized_codex_auth_validation_summary(&error);
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!(
                    "failed to validate Codex auth source: {auth_failure}"
                ));
                let requirement =
                    EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile);
                report
                    .stdout
                    .run_metadata
                    .environment_preflight_results
                    .push(EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    });
                report
                    .stdout
                    .run_metadata
                    .environment_failures
                    .push(environment_failure(
                        EnvironmentFailureCategory::ProbeFailed,
                        Some(requirement),
                        format!("Codex credential/config presence probe failed: {auth_failure}"),
                    ));
                return report;
            }
        }
    } else {
        None
    };

    let side_effect_profile = if runtime == ExternalExecutionRuntime::Verified
        && (program_trust == ExternalProgramTrust::TrustedSystemCodex
            || spec.invocation.is_adapter_subprocess())
    {
        match external_side_effect_profile(
            &target_spec,
            &resolved_program,
            program_trust,
            &target_controls,
        ) {
            Ok(profile) => Some(profile),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!("failed to prepare external-agent sandbox: {error}"));
                let requirement = EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalCodex,
                );
                report
                    .stdout
                    .run_metadata
                    .environment_preflight_results
                    .push(EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    });
                report
                    .stdout
                    .run_metadata
                    .environment_failures
                    .push(environment_failure(
                        EnvironmentFailureCategory::SandboxUnavailable,
                        Some(requirement),
                        format!("failed to prepare the fixed ExternalCodex sandbox: {error}"),
                    ));
                return report;
            }
        }
    } else {
        None
    };
    let mut external_environment = allowed_env(spec.invocation, program_trust);
    if let Some(config) = &target_spec.runtime_adapter {
        for key in &config.env_passthrough {
            if let Ok(value) = env::var(key) {
                external_environment.insert(key.clone(), value);
            }
        }
    }
    if let Some(metadata) = &agent_lifecycle {
        external_environment.insert(MACO_RUN_ID_ENV.to_string(), metadata.run_id().to_string());
        external_environment.insert(MACO_TASK_ID_ENV.to_string(), metadata.task_id().to_string());
    }
    if let Some(git) = &target_controls.managed_git {
        let git_environment = match managed_git_environment(git) {
            Ok(environment) => environment,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("failed to bind managed child private Git environment: {error:#}"),
                );
                return report;
            }
        };
        external_environment.extend(git_environment);
        external_environment.insert(
            "GIT_WORK_TREE".to_string(),
            target_spec.cwd.display().to_string(),
        );
    }
    let credential_redactor =
        match CredentialRedactor::from_runtime(&external_environment, codex_auth.as_ref()) {
            Ok(redactor) => redactor,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("failed to prepare bounded credential redaction: {error:#}"),
                );
                return report;
            }
        };
    if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::TrustedSystemCodex
        && matches!(
            spec.invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        )
    {
        let Some(preflight_profile) = side_effect_profile.as_ref() else {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalCodex,
                )),
                "verified environment preflight did not receive the target side-effect profile"
                    .to_string(),
            );
            return report;
        };
        let remaining = spec.timeout.saturating_sub(started.elapsed());
        let mut preflight = run_environment_preflight(
            &target_spec,
            &resolved_program,
            remaining,
            cancellation,
            &external_environment,
            preflight_profile,
            codex_auth.as_ref(),
            agent_lifecycle.as_ref(),
        );
        for failure in &mut preflight.failures {
            failure.summary = credential_redactor.redact_string(&failure.summary);
        }
        codex_version = preflight
            .codex_version
            .map(|version| (version.major, version.minor, version.patch));
        report.timed_out = preflight.timed_out;
        report.stdout.run_metadata.environment_preflight_results = preflight.results;
        report.stdout.run_metadata.environment_failures = preflight.failures;
        retain_environment_preflight_process_evidence(&mut report, &preflight.process_evidence);
        if report.environment_blocked() {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(environment_blocked_message(report.environment_failures()));
            return report;
        }
    }
    if duplex_review_required {
        let Some(version) =
            codex_version.map(|(major, minor, patch)| EnvironmentVersion::new(major, minor, patch))
        else {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::ProbeFailed,
                Some(codex_environment_requirement()),
                "writable Codex app-server version was unavailable after mandatory preflight"
                    .to_string(),
            );
            return report;
        };
        if let Err(error) = validate_duplex_app_server_version(version) {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::VersionMismatch,
                Some(codex_environment_requirement()),
                error.to_string(),
            );
            return report;
        }
        argv = codex_app_server_argv(&target_spec, &target_controls);
        report.command = command_display(&resolved_program, &argv);
        bound_argv_digest = match argv_digest(&argv) {
            Ok(digest) => Some(digest),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("failed to bind external-agent permission evidence to argv: {error}"),
                );
                return report;
            }
        };
    }
    let Some(argv_digest) = bound_argv_digest else {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "external-agent argv was not bound before target release".to_string(),
        );
        return report;
    };
    if let Err(error) =
        validate_external_program_identity(&resolved_program, spec.program == Path::new("codex"))
            .and_then(|()| {
                let current = external_program_identity(&resolved_program)?;
                if current == program_identity {
                    Ok(())
                } else {
                    bail!("external executable identity changed after version preflight")
                }
            })
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::ProbeFailed,
            Some(codex_environment_requirement()),
            format!("external executable changed before target release: {error}"),
        );
        return report;
    }
    if let Some(auth) = &codex_auth {
        if let Err(error) = auth.verify_source_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::ProbeFailed,
                Some(EnvironmentRequirement::configuration(
                    EnvironmentConfiguration::CodexAuthFile,
                )),
                format!("Codex auth source changed before unit setup: {error}"),
            );
            return report;
        }
    }
    let mut json_log_reservation = match reserve_external_output(&spec.json_log) {
        Ok(reservation) => reservation,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("failed to reserve external-agent JSON log: {error}"),
            );
            return report;
        }
    };

    let timeout = spec.timeout.saturating_sub(started.elapsed());
    let process_spec = ProcessSpec::direct(
        "external agent",
        &resolved_program,
        argv.clone(),
        &target_spec.cwd,
        OUTPUT_TEE_LIMIT_BYTES,
    )
    .with_stdin(external_agent_stdin_mode(
        &target_spec,
        duplex_review_required,
        prompt,
    ))
    .with_stdin_limit(MAX_PROMPT_BYTES)
    .with_timeout(Some(timeout))
    .with_stdout(StreamCapture::bounded(OUTPUT_TEE_LIMIT_BYTES));
    let process_spec = match runtime {
        ExternalExecutionRuntime::Verified => {
            let Some(side_effect_profile) = side_effect_profile else {
                report.duration_ms = duration_millis(started.elapsed());
                record_environment_failure(
                    &mut report,
                    EnvironmentFailureCategory::SandboxUnavailable,
                    Some(EnvironmentRequirement::sandbox(
                        EnvironmentSandboxCapability::VerifiedExternalCodex,
                    )),
                    "verified external-agent runtime did not prepare a side-effect profile"
                        .to_string(),
                );
                return report;
            };
            with_external_runtime_context(
                process_spec,
                external_environment,
                side_effect_profile,
                target_spec.invocation,
                codex_auth.as_ref(),
                agent_lifecycle.as_ref(),
            )
        }
        #[cfg(test)]
        ExternalExecutionRuntime::NonpublishableSimulation => {
            let process_spec = process_spec
                .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort);
            match &agent_lifecycle {
                Some(metadata) => process_spec.with_agent_lifecycle(metadata.clone()),
                None => process_spec,
            }
        }
    };

    if cancellation.is_cancelled() {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "external agent was cancelled before target start".to_string(),
        );
        return report;
    }

    // Preflight evidence describes only the bounded probes. Once the main target is released it
    // must earn fresh process-tree and side-effect evidence of its own; otherwise a target wait
    // or cancellation failure could appear quiescent because an earlier probe was clean.
    report.process_tree = None;
    report.side_effects = None;
    report.stdout.target_launch_attempted = true;
    let completed_context = CompletedTargetContext {
        runtime,
        codex_version,
        spec: &target_spec,
        protected_controls: &target_controls,
        argv_digest: &argv_digest,
        program_identity: &program_identity,
    };
    let mut retained_gate_denials = Vec::new();
    let mut retained_review_metrics = None;
    let process_result = if duplex_review_required {
        let Some(prompt) = duplex_prompt else {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "writable Codex duplex prompt was unavailable".to_string(),
            );
            return report;
        };
        let Some(review_runtime) = review_runtime.as_mut() else {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalCodex,
                )),
                "writable Codex duplex review runtime was unavailable".to_string(),
            );
            return report;
        };
        let attempt =
            run_duplex_app_server_process(process_spec, cancellation, spec, prompt, review_runtime);
        retained_gate_denials = attempt.gate_denials;
        retained_review_metrics = Some(attempt.metrics);
        match attempt.process {
            Ok(interactive) => {
                let protocol = interactive.interaction;
                let mut final_message_error = None;
                if let Ok(outcome) = &protocol {
                    if let Some(final_message) = &outcome.final_message {
                        let final_message =
                            credential_redactor.redact_bytes(final_message.as_bytes());
                        let staged = output_staging.reservation_mut().and_then(|reservation| {
                            reservation.write_bytes_atomic(&final_message, OUTPUT_TEE_LIMIT_BYTES)
                        });
                        if let Err(error) = staged {
                            final_message_error = Some(format!(
                                "failed to stage app-server final message: {error:#}"
                            ));
                        }
                    }
                }
                match output_staging.reservation_mut() {
                    Ok(staged_output) => record_completed_target(
                        &mut report,
                        interactive.process,
                        staged_output,
                        &mut output_reservation,
                        &mut json_log_reservation,
                        &credential_redactor,
                        completed_context,
                    ),
                    Err(error) => {
                        report.error = append_external_error(
                            report.error.take(),
                            Some(format!(
                                "private external-agent output staging became unavailable: {error:#}"
                            )),
                        );
                        report.publishable = false;
                    }
                }
                if let Some(error) = final_message_error {
                    report.error = append_external_error(report.error.take(), Some(error));
                    report.publishable = false;
                }
                if let Err(error) = protocol {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(credential_redactor.redact_string(&format!(
                            "duplex app-server protocol failed closed: {error}"
                        ))),
                    );
                    report.publishable = false;
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    } else {
        run_process_cancellable(process_spec, cancellation).map(|output| {
            match output_staging.reservation_mut() {
                Ok(staged_output) => record_completed_target(
                    &mut report,
                    output,
                    staged_output,
                    &mut output_reservation,
                    &mut json_log_reservation,
                    &credential_redactor,
                    completed_context,
                ),
                Err(error) => {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(format!(
                            "private external-agent output staging became unavailable: {error:#}"
                        )),
                    );
                    report.publishable = false;
                }
            }
        })
    };
    match process_result {
        Ok(()) => {}
        Err(error) => {
            report.timed_out = matches!(&error, ProcessRunError::SetupTimeout { .. });
            let preparation_failure = target_process_environment_failure(&error);
            if let Some((category, requirement)) = preparation_failure {
                if process_run_error_definitely_before_process_start(&error) {
                    report.stdout.target_launch_attempted = false;
                }
                record_environment_failure(
                    &mut report,
                    category,
                    requirement,
                    credential_redactor.redact_string(&error.to_string()),
                );
            }
            let mut sandbox_denials = Vec::new();
            if let Some(denial) = sandbox_denial_from_process_error(&error) {
                sandbox_denials.push(denial);
            }
            if let Some(evidence) = error.cancellation_evidence() {
                sandbox_denials.extend(sandbox_denials_from_codex_jsonl(
                    &protected_controls,
                    evidence.stdout.as_bytes(),
                ));
                report.process_tree = Some(evidence.process_tree);
                report.side_effects = Some(evidence.side_effects);
                if let Err(log_error) = write_redacted_json_log(
                    &mut json_log_reservation,
                    evidence.stdout.as_bytes(),
                    &credential_redactor,
                ) {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(format!(
                            "failed to persist redacted JSON log: {log_error:#}"
                        )),
                    );
                }
                replace_report_stdout(
                    &mut report,
                    summarize_redacted_output(&evidence.stdout, &credential_redactor),
                );
                report.stdout.target_launch_attempted = true;
                report.stderr = summarize_redacted_output(&evidence.stderr, &credential_redactor);
            }
            deduplicate_sandbox_denials(&mut sandbox_denials);
            report.stdout.run_metadata.sandbox_denials = sandbox_denials;
            report.error = append_external_error(
                report.error.take(),
                Some(credential_redactor.redact_string(&error.to_string())),
            );
            let staged_output = output_staging.reservation().and_then(|staged_output| {
                capture_redacted_staged_output(
                    staged_output,
                    &mut output_reservation,
                    &credential_redactor,
                )
            });
            match staged_output {
                Ok(bytes) => report.output_last_message = Some(bytes),
                Err(output_error) => {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(format!(
                            "external-agent output reservation could not be safely captured: {output_error:#}"
                        )),
                    );
                }
            }
        }
    }
    let worker_journal_artifacts =
        capture_worker_journal_artifacts(&protected_controls, report.scratch_quiescence_verified());
    report.replace_worker_journal_artifacts(worker_journal_artifacts);
    match output_staging.cleanup() {
        Ok(ExternalOutputCleanup::Quarantined(operation)) => {
            if let Err(error) = persist_machine_global_retention_receipt(&spec.json_log, &operation)
            {
                report.error = append_external_error(
                    report.error.take(),
                    Some(format!(
                        "machine-global output staging was quarantined as operation {} but its private purge receipt could not be persisted: {error:#}",
                        operation.id.get()
                    )),
                );
                report.publishable = false;
            } else {
                report
                    .stdout
                    .run_metadata
                    .machine_global_retention_operation_id = Some(operation.id);
            }
        }
        Ok(ExternalOutputCleanup::Denied(denial)) => {
            retained_gate_denials.push(denial);
            report.error = append_external_error(
                report.error.take(),
                Some("machine-global gate denied private output-staging cleanup".to_string()),
            );
            report.publishable = false;
        }
        Ok(ExternalOutputCleanup::Bypassed(attribution)) => {
            report
                .stdout
                .run_metadata
                .machine_global_bypasses
                .push(attribution);
        }
        Err(error) => {
            report.error = append_external_error(
                report.error.take(),
                Some(format!(
                    "failed to clean private external-agent output staging: {error:#}"
                )),
            );
            report.publishable = false;
        }
    }
    report.stdout.run_metadata.gate_denials = retained_gate_denials;
    report.stdout.run_metadata.pre_action_review_metrics = retained_review_metrics;
    report.duration_ms = duration_millis(started.elapsed());
    report
}

fn should_use_duplex_review(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
    hosted_reviewer_available: bool,
) -> bool {
    runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::CodexSupervisor
        && spec.workspace_access == WorkspaceAccess::ReadWrite
        // Managed worktree children always use Codex's native workspace-write sandbox. Merely
        // receiving an optional hosted reviewer must not reroute them into app-server duplex.
        && spec.writable_launch_target == WritableLaunchTarget::PrimaryWorktree
        && hosted_reviewer_available
}

fn validate_universal_pre_action_coverage(target: WritableLaunchTarget) -> Result<()> {
    // Isolated worktree children use native permission/sandbox mode. The Codex
    // app-server still has no force-review-every-action callback; that gap is
    // no longer a worktree-launch blocker. Primary-writable release still
    // requires a hosted All-callback.
    match target {
        WritableLaunchTarget::ManagedChildWorktree => Ok(()),
        WritableLaunchTarget::PrimaryWorktree => bail!(
            "writable primary Codex failed closed before launch: blocking_pre_action_callback != All"
        ),
    }
}

fn validate_duplex_app_server_version(version: EnvironmentVersion) -> Result<()> {
    let audited = EnvironmentVersion::new(
        CODEX_DUPLEX_AUDITED_VERSION.0,
        CODEX_DUPLEX_AUDITED_VERSION.1,
        CODEX_DUPLEX_AUDITED_VERSION.2,
    );
    if version != audited {
        bail!(
            "Codex {version} does not match the audited writable app-server protocol version {audited}"
        );
    }
    Ok(())
}

struct DuplexApprovalReviewer<'a> {
    context: &'a ReviewContext,
    review_session_id: &'a str,
    journal: &'a mut dyn PreActionJournalSink,
    reviewer: PreActionReviewer,
    observed_denials: Vec<GateDenial>,
    workspace: &'a Path,
}

impl codex_app_server::ApprovalReviewer for DuplexApprovalReviewer<'_> {
    fn review(
        &mut self,
        request: codex_app_server::ApprovalRequest,
    ) -> std::result::Result<codex_app_server::ApprovalReview, String> {
        let decision_started = Instant::now();
        let review_request = approval_review_request_from_app_server(&request, self.workspace)
            .map_err(|error| format!("invalid approval manifest: {error:#}"))?;
        let redacted = self
            .reviewer
            .redacted_classifier_request(self.context, &review_request);
        // Production deliberately supplies no classifier here. Incomplete command/file manifests
        // therefore fail closed instead of letting a classifier guess claim or sensitive-path
        // coverage.
        let outcome = self
            .reviewer
            .review(self.context, &review_request, None)
            .map_err(|error| format!("pre-action policy failed: {error}"))?;
        let (source, allowed, denial, rationale, response) = match outcome {
            ReviewOutcome::Allowed { source } => {
                let rationale = match source {
                    DecisionSource::Classifier => PreActionJournalRationale::ClassifierAllow,
                    DecisionSource::DeterministicAllow => {
                        PreActionJournalRationale::DeterministicPolicyAllow
                    }
                    DecisionSource::DeterministicDeny | DecisionSource::LatencyBudget => {
                        return Err(
                            "pre-action policy returned an invalid allow source".to_string()
                        );
                    }
                };
                (
                    source,
                    true,
                    None,
                    rationale,
                    codex_app_server::ApprovalReview::accept(),
                )
            }
            ReviewOutcome::Denied { source, denial } => {
                let rationale = match source {
                    DecisionSource::Classifier => PreActionJournalRationale::ClassifierFailClosed,
                    DecisionSource::DeterministicDeny => {
                        PreActionJournalRationale::DeterministicPolicyDeny
                    }
                    DecisionSource::LatencyBudget => {
                        PreActionJournalRationale::LatencyBudgetExceeded
                    }
                    DecisionSource::DeterministicAllow => {
                        return Err(
                            "pre-action policy returned an invalid denial source".to_string()
                        );
                    }
                };
                (
                    source,
                    false,
                    Some(denial.clone()),
                    rationale,
                    codex_app_server::ApprovalReview::decline(denial),
                )
            }
            ReviewOutcome::HumanInterventionRequired { source, denial } => (
                source,
                false,
                Some(denial.clone()),
                PreActionJournalRationale::HumanInterventionRequired,
                codex_app_server::ApprovalReview::cancel(Some(denial)),
            ),
        };
        let record = PreActionJournalRecord {
            version: PRE_ACTION_JOURNAL_VERSION,
            run_id: self.context.run_id().to_string(),
            review_session_id: self.review_session_id.to_string(),
            phase: PreActionJournalPhase::ReviewDecision,
            thread_id: Some(request.thread_id),
            turn_id: Some(request.turn_id),
            item_id: Some(request.item_id),
            request: Some(redacted),
            decision_source: Some(source),
            decision_latency_ms: Some(duration_millis(decision_started.elapsed())),
            rationale,
            allowed: Some(allowed),
            denial,
            turn_status: None,
            item_outcomes: Vec::new(),
            process_exit_code: None,
            process_tree: None,
            side_effects: None,
        };
        if let Some(denial) = &record.denial {
            self.observed_denials.push(denial.clone());
        }
        self.journal
            .append(&record)
            .map_err(|error| format!("strict pre-action journal append failed: {error:#}"))?;
        Ok(response)
    }
}

fn approval_review_request_from_app_server(
    request: &codex_app_server::ApprovalRequest,
    workspace: &Path,
) -> Result<ApprovalReviewRequest> {
    let action = match request.kind {
        codex_app_server::ApprovalKind::CommandExecution => {
            command_action_from_app_server(request, workspace)?
        }
        codex_app_server::ApprovalKind::FileChange => {
            file_action_from_app_server(request, workspace)?
        }
        codex_app_server::ApprovalKind::PermissionExpansion => ActionDescriptor::command(
            CommandInvocation::new("codex-permission-request", std::iter::empty::<&str>())?,
            CommandClass::ExternalSideEffect,
            BlastRadius::External,
            std::iter::empty::<PathAccess>(),
            false,
        )?,
    };
    let permissions = if request.ceiling_expansion_requested {
        PermissionRequest::within_ceiling().with_outside_workspace_access()
    } else {
        PermissionRequest::within_ceiling()
    };
    let mut correlation = Vec::new();
    correlation.extend_from_slice(request.thread_id.as_bytes());
    correlation.push(0);
    correlation.extend_from_slice(request.turn_id.as_bytes());
    correlation.push(0);
    correlation.extend_from_slice(request.item_id.as_bytes());
    let digest = sha256_hex(&correlation);
    ApprovalReviewRequest::new(
        format!("request-{digest}"),
        format!("correction-{digest}"),
        action,
        permissions,
    )
    .map_err(Into::into)
}

fn command_action_from_app_server(
    request: &codex_app_server::ApprovalRequest,
    workspace: &Path,
) -> Result<ActionDescriptor> {
    let invocation = CommandInvocation::new("codex-command", std::iter::empty::<&str>())?;
    let mut accesses = Vec::new();
    if let Some(actions) = request
        .item
        .get("commandActions")
        .and_then(serde_json::Value::as_array)
    {
        for action in actions {
            let action_type = action.get("type").and_then(serde_json::Value::as_str);
            if !matches!(action_type, Some("read" | "listFiles" | "search")) {
                continue;
            }
            let Some(path) = action.get("path").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if let Some(access) = review_path_access(workspace, path, PathAccessMode::Read) {
                accesses.push(access);
            }
        }
    }
    // Upstream documents commandActions as best-effort. Even a syntactically complete list is
    // never authoritative enough for a deterministic allow.
    ActionDescriptor::command(
        invocation,
        CommandClass::Unknown,
        BlastRadius::WorkspaceWide,
        accesses,
        false,
    )
    .map_err(Into::into)
}

fn file_action_from_app_server(
    request: &codex_app_server::ApprovalRequest,
    workspace: &Path,
) -> Result<ActionDescriptor> {
    let mut accesses = Vec::new();
    let mut destructive = false;
    let mut complete = true;
    let changes = request
        .item
        .get("changes")
        .and_then(serde_json::Value::as_array);
    let Some(changes) = changes else {
        return ActionDescriptor::file_change_with_manifest([], false, false).map_err(Into::into);
    };
    if changes.is_empty() {
        complete = false;
    }
    for change in changes {
        let Some(path) = change.get("path").and_then(serde_json::Value::as_str) else {
            complete = false;
            continue;
        };
        let kind = change
            .pointer("/kind/type")
            .and_then(serde_json::Value::as_str);
        let delete = kind == Some("delete");
        if !matches!(kind, Some("add" | "delete" | "update")) {
            complete = false;
            continue;
        }
        destructive |= delete;
        let mode = if delete {
            PathAccessMode::Delete
        } else {
            PathAccessMode::Write
        };
        match review_path_access(workspace, path, mode) {
            Some(access) => accesses.push(access),
            None => complete = false,
        }
        if let Some(move_path) = change
            .pointer("/kind/move_path")
            .and_then(serde_json::Value::as_str)
        {
            destructive = true;
            match review_path_access(workspace, move_path, PathAccessMode::Delete) {
                Some(access) => accesses.push(access),
                None => complete = false,
            }
        }
    }
    ActionDescriptor::file_change_with_manifest(accesses, destructive, complete).map_err(Into::into)
}

fn review_path_access(workspace: &Path, path: &str, mode: PathAccessMode) -> Option<PathAccess> {
    let path = Path::new(path);
    let relative = if path.is_absolute() {
        path.strip_prefix(workspace).ok()?
    } else {
        path
    };
    PathAccess::new(relative, mode).ok()
}

struct DuplexProcessAttempt {
    process: std::result::Result<
        InteractiveProcessOutput<codex_app_server::AppServerOutcome>,
        ProcessRunError,
    >,
    metrics: ReviewMetricSnapshot,
    gate_denials: Vec<GateDenial>,
}

fn run_duplex_app_server_process(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    runtime: &mut ExternalPreActionReviewRuntime<'_>,
) -> DuplexProcessAttempt {
    let review_session_id = duplex_review_session_id(runtime.context, spec);
    let mut reviewer = DuplexApprovalReviewer {
        context: runtime.context,
        review_session_id: &review_session_id,
        journal: runtime.journal,
        reviewer: PreActionReviewer::default(),
        observed_denials: Vec::new(),
        workspace: &spec.cwd,
    };
    let turn = codex_app_server::AppServerTurn {
        cwd: spec.cwd.to_string_lossy().into_owned(),
        permission_profile: "maco_external_codex".to_string(),
        prompt,
        model: spec.model.clone(),
    };
    let mut process = run_process_interactive(process_spec, cancellation, |session| {
        let mut transport = codex_app_server::ContainedJsonLineTransport::new(session);
        let outcome = codex_app_server::run_app_server_turn(
            &mut transport,
            &turn,
            codex_app_server::AppServerLimits {
                turn_timeout: spec.timeout,
                ..codex_app_server::AppServerLimits::default()
            },
            &mut reviewer,
            || cancellation.is_cancelled(),
        )
        .map_err(|error| error.to_string())?;
        let fallback_denial = duplex_fallback_denial(runtime.context, &review_session_id, &outcome)
            .map_err(|error| format!("failed to construct duplex fallback refusal: {error:#}"))?;
        reviewer
            .journal
            .append(&terminal_turn_journal_record(
                runtime.context.run_id(),
                &review_session_id,
                &outcome,
                fallback_denial.as_ref(),
            ))
            .map_err(|error| format!("strict turn-terminal journal append failed: {error:#}"))?;
        if let Some(denial) = fallback_denial {
            reviewer.observed_denials.push(denial);
            return Err(
                "child refused because mandatory duplex pre-action fallback was required"
                    .to_string(),
            );
        }
        Ok(outcome)
    });
    if let Ok(result) = &mut process {
        let terminal_outcome = result.interaction.as_ref().ok();
        if let Err(error) = reviewer.journal.append(&terminal_process_journal_record(
            runtime.context.run_id(),
            &review_session_id,
            terminal_outcome,
            &result.process,
        )) {
            result.interaction = Err(format!(
                "strict process-terminal journal append failed: {error:#}"
            ));
        }
    }
    let metrics = reviewer.reviewer.metrics();
    DuplexProcessAttempt {
        process,
        metrics,
        gate_denials: reviewer.observed_denials,
    }
}

fn duplex_review_session_id(context: &ReviewContext, spec: &ExternalAgentCommand) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(context.run_id().as_bytes());
    material.push(0);
    material.extend_from_slice(context.owner().as_bytes());
    material.push(0);
    material.extend_from_slice(spec.prompt.as_os_str().as_encoded_bytes());
    format!("review-{}", sha256_hex(&material))
}

fn duplex_fallback_denial(
    context: &ReviewContext,
    review_session_id: &str,
    outcome: &codex_app_server::AppServerOutcome,
) -> Result<Option<GateDenial>> {
    if !outcome.duplex_fallback_required {
        return Ok(None);
    }
    let paths = context.claims().iter().map(|claim| claim.path());
    GateDenial::from_approval_review(
        format!("{review_session_id}-fallback"),
        context.owner(),
        crate::gate_denial::ApprovalReviewDenial::DuplexFallbackRequired,
        paths,
    )
    .map(Some)
    .map_err(Into::into)
}

fn terminal_turn_journal_record(
    run_id: &str,
    review_session_id: &str,
    outcome: &codex_app_server::AppServerOutcome,
    fallback_denial: Option<&GateDenial>,
) -> PreActionJournalRecord {
    PreActionJournalRecord {
        version: PRE_ACTION_JOURNAL_VERSION,
        run_id: run_id.to_string(),
        review_session_id: review_session_id.to_string(),
        phase: PreActionJournalPhase::TurnTerminal,
        thread_id: Some(outcome.thread_id.clone()),
        turn_id: Some(outcome.turn_id.clone()),
        item_id: None,
        request: None,
        decision_source: None,
        decision_latency_ms: None,
        rationale: if fallback_denial.is_some() {
            PreActionJournalRationale::DuplexFallbackRequired
        } else {
            PreActionJournalRationale::TerminalEvidence
        },
        allowed: fallback_denial.map(|_| false),
        denial: fallback_denial.cloned(),
        turn_status: Some(outcome.status),
        item_outcomes: outcome.item_outcomes.clone(),
        process_exit_code: None,
        process_tree: None,
        side_effects: None,
    }
}

fn terminal_process_journal_record(
    run_id: &str,
    review_session_id: &str,
    outcome: Option<&codex_app_server::AppServerOutcome>,
    process: &ProcessOutput,
) -> PreActionJournalRecord {
    PreActionJournalRecord {
        version: PRE_ACTION_JOURNAL_VERSION,
        run_id: run_id.to_string(),
        review_session_id: review_session_id.to_string(),
        phase: PreActionJournalPhase::ProcessTerminal,
        thread_id: outcome.map(|value| value.thread_id.clone()),
        turn_id: outcome.map(|value| value.turn_id.clone()),
        item_id: None,
        request: None,
        decision_source: None,
        decision_latency_ms: None,
        rationale: PreActionJournalRationale::TerminalEvidence,
        allowed: None,
        denial: None,
        turn_status: outcome.map(|value| value.status),
        item_outcomes: outcome
            .map(|value| value.item_outcomes.clone())
            .unwrap_or_default(),
        process_exit_code: process.status.and_then(|status| status.code()),
        process_tree: Some(process.process_tree),
        side_effects: Some(process.side_effects),
    }
}

struct CompletedTargetContext<'a> {
    runtime: ExternalExecutionRuntime,
    codex_version: Option<(u64, u64, u64)>,
    spec: &'a ExternalAgentCommand,
    protected_controls: &'a ProtectedWorktreeControls,
    argv_digest: &'a str,
    program_identity: &'a ExternalProgramIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeAdapterCapturedOutput {
    ExistingStagedOutput,
    Captured(Vec<u8>),
    Unavailable,
}

fn runtime_adapter_captured_output(
    spec: &ExternalAgentCommand,
    stdout: &[u8],
    stderr: &[u8],
    target_completed_successfully: bool,
) -> Result<RuntimeAdapterCapturedOutput> {
    if spec.invocation == ExternalAgentInvocation::Grok {
        if !target_completed_successfully {
            return Ok(RuntimeAdapterCapturedOutput::Unavailable);
        }
        let stream = crate::runtime_adapter::grok::parse_grok_event_stream(stdout)
            .context("Grok runtime output failed bounded streaming-json validation")?;
        if !stream.completed() {
            // Grok error text can contain provider-owned diagnostics. The raw stream is retained
            // only through the existing redacted JSON-log path; public failure evidence names the
            // typed terminal condition without reflecting child-controlled text.
            bail!("Grok runtime returned a terminal streaming-json error event");
        }
        return Ok(RuntimeAdapterCapturedOutput::Captured(
            stream.response_text().as_bytes().to_vec(),
        ));
    }

    let Some(config) = &spec.runtime_adapter else {
        return Ok(RuntimeAdapterCapturedOutput::ExistingStagedOutput);
    };
    Ok(match config.output_capture {
        crate::runtime_adapter::OutputCaptureMode::OutputFile => {
            RuntimeAdapterCapturedOutput::ExistingStagedOutput
        }
        crate::runtime_adapter::OutputCaptureMode::Stdout => {
            RuntimeAdapterCapturedOutput::Captured(stdout.to_vec())
        }
        crate::runtime_adapter::OutputCaptureMode::StdoutAndStderr => {
            RuntimeAdapterCapturedOutput::Captured(stdout.iter().chain(stderr).copied().collect())
        }
    })
}

fn record_completed_target(
    report: &mut ExternalAgentRun,
    output: ProcessOutput,
    staged_output: &mut ReservedOutputFile,
    output_reservation: &mut ReservedOutputFile,
    json_log_reservation: &mut ReservedOutputFile,
    credential_redactor: &CredentialRedactor,
    context: CompletedTargetContext<'_>,
) {
    let safety_verified = output.safety_evidence_verified();
    let target_completed_successfully = !output.timed_out
        && output.status.is_some_and(|status| status.success())
        && output.process_error.is_none()
        && output.stdin_error.is_none();
    let mut sandbox_denials =
        sandbox_denials_from_codex_jsonl(context.protected_controls, output.stdout.as_bytes());
    deduplicate_sandbox_denials(&mut sandbox_denials);
    report.exit_code = output.status.and_then(|status| status.code());
    report.timed_out = output.timed_out;
    report.process_tree = Some(output.process_tree);
    report.side_effects = Some(output.side_effects);
    // Permission evidence describes the verified launch boundary, not the target's exit status.
    // Supervisors consume it as containment evidence even when the assignment itself fails.
    if context.runtime == ExternalExecutionRuntime::Verified
        && report.program_trust == ExternalProgramTrust::TrustedSystemCodex
        && safety_verified
    {
        report.codex_permissions = context.codex_version.map(|version| {
            codex_permission_evidence(
                version,
                context.spec,
                context.argv_digest,
                context.program_identity,
            )
        });
    }
    if let Err(error) = write_redacted_json_log(
        json_log_reservation,
        output.stdout.as_bytes(),
        credential_redactor,
    ) {
        report.error = append_external_error(
            report.error.take(),
            Some(format!("failed to persist redacted JSON log: {error:#}")),
        );
    }
    replace_report_stdout(
        report,
        summarize_redacted_output(&output.stdout, credential_redactor),
    );
    report.stdout.target_launch_attempted = true;
    report.stdout.run_metadata.sandbox_denials = sandbox_denials;
    report.stderr = summarize_redacted_output(&output.stderr, credential_redactor);
    report.error = append_external_error(
        report.error.take(),
        append_external_error(output.stdin_error, output.process_error)
            .map(|error| credential_redactor.redact_string(&error)),
    );
    if output.timed_out {
        report.error = append_external_error(
            report.error.take(),
            Some(format!(
                "external agent timed out after {} seconds",
                context.spec.timeout.as_secs()
            )),
        );
    } else if !output.status.is_some_and(|status| status.success()) {
        let status_error = match output.status.and_then(|status| status.code()) {
            Some(code) => format!("external agent exited with status {code}"),
            None => "external agent terminated without an exit code".to_string(),
        };
        report.error = append_external_error(report.error.take(), Some(status_error));
    }
    let staged_output_available = match runtime_adapter_captured_output(
        context.spec,
        output.stdout.as_bytes(),
        output.stderr.as_bytes(),
        target_completed_successfully,
    ) {
        Ok(RuntimeAdapterCapturedOutput::ExistingStagedOutput) => true,
        Ok(RuntimeAdapterCapturedOutput::Captured(captured)) => {
            match staged_output.write_bytes_atomic(&captured, OUTPUT_TEE_LIMIT_BYTES) {
                Ok(()) => true,
                Err(error) => {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(format!("failed to stage runtime adapter output: {error:#}")),
                    );
                    false
                }
            }
        }
        Ok(RuntimeAdapterCapturedOutput::Unavailable) => false,
        Err(error) => {
            report.error = append_external_error(
                report.error.take(),
                Some(credential_redactor.redact_string(&format!(
                    "runtime adapter output validation failed: {error:#}"
                ))),
            );
            false
        }
    };
    if staged_output_available {
        match capture_redacted_staged_output(staged_output, output_reservation, credential_redactor)
        {
            Ok(bytes) => report.output_last_message = Some(bytes),
            Err(error) => {
                report.error = append_external_error(
                    report.error.take(),
                    Some(format!(
                        "external-agent output reservation changed: {error}"
                    )),
                );
            }
        }
    }
    if let Some(git) = &context.protected_controls.managed_git {
        if let Err(error) = verify_managed_git_boundary_after_launch(git) {
            report.error = append_external_error(
                report.error.take(),
                Some(format!(
                    "managed child private Git boundary changed during launch: {error:#}"
                )),
            );
        }
    }
    let adapter_runtime = context.spec.invocation.is_adapter_subprocess();
    report.publishable = context.runtime == ExternalExecutionRuntime::Verified
        && safety_verified
        && (adapter_runtime
            || (report.program_trust == ExternalProgramTrust::TrustedSystemCodex
                && report.codex_permissions.is_some()))
        && report.exit_code == Some(0)
        && !report.timed_out
        && report.error.is_none();
}

fn capture_redacted_staged_output(
    staging: &ReservedOutputFile,
    destination: &mut ReservedOutputFile,
    credential_redactor: &CredentialRedactor,
) -> Result<Vec<u8>> {
    let bytes = match staging.read_bounded(OUTPUT_TEE_LIMIT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            destination
                .write_bytes_atomic(CREDENTIAL_REDACTION, OUTPUT_TEE_LIMIT_BYTES)
                .context("failed to replace unreadable external output with a redaction marker")?;
            return Err(error);
        }
    };
    let redacted = credential_redactor.redact_bytes(&bytes);
    destination
        .write_bytes_atomic(&redacted, OUTPUT_TEE_LIMIT_BYTES)
        .context("failed to persist redacted external-agent output")?;
    Ok(redacted)
}

fn deduplicate_sandbox_denials(evidence: &mut Vec<SandboxDenialEvidence>) {
    evidence.sort();
    evidence.dedup();
}

fn failed_external_run(
    spec: &ExternalAgentCommand,
    started: Instant,
    command: Vec<String>,
    timed_out: bool,
    error: String,
) -> ExternalAgentRun {
    ExternalAgentRun {
        command,
        cwd: spec.cwd.clone(),
        timeout_seconds: spec.timeout.as_secs(),
        exit_code: None,
        duration_ms: duration_millis(started.elapsed()),
        timed_out,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: external_program_trust(spec),
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: Some(error),
        output_last_message: None,
    }
}

fn failed_external_environment_run(
    spec: &ExternalAgentCommand,
    started: Instant,
    command: Vec<String>,
    timed_out: bool,
    category: EnvironmentFailureCategory,
    requirement: Option<EnvironmentRequirement>,
    error: String,
) -> ExternalAgentRun {
    let mut report = failed_external_run(spec, started, command, timed_out, error.clone());
    record_environment_failure(&mut report, category, requirement, error);
    report
}

fn reserve_external_output(path: &Path) -> Result<ReservedOutputFile> {
    let parent = required_parent(path)?;
    let name = path
        .file_name()
        .with_context(|| format!("external output must have a file name: {}", path.display()))?;
    let root = SecureOutputRoot::open_or_create(parent)?;
    root.reserve(name)
}

fn persist_machine_global_retention_receipt(
    json_log_path: &Path,
    operation: &RetentionOperation,
) -> Result<()> {
    let parent = required_parent(json_log_path)?;
    let root = SecureOutputRoot::open_or_create(parent)?;
    let name = OsString::from(format!(
        "machine-global-retention-{}.private.json",
        operation.id.get()
    ));
    let mut receipt = root.reserve(&name)?;
    let mut bytes = serde_json::to_vec_pretty(operation)
        .context("failed to serialize private machine-global retention receipt")?;
    bytes.push(b'\n');
    receipt
        .write_bytes_atomic(&bytes, OUTPUT_TEE_LIMIT_BYTES)
        .context("failed to persist private machine-global retention receipt")
}

struct ExternalOutputStaging {
    root_path: PathBuf,
    reservation: Option<ReservedOutputFile>,
    machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    bound_store: Option<MachineGlobalStore>,
    bound_root_reservation: Option<ReservedDirectory>,
    cleanup_completed: bool,
}

enum ExternalOutputCleanup {
    Quarantined(RetentionOperation),
    Denied(GateDenial),
    Bypassed(MachineGlobalBypassAttribution),
}

impl ExternalOutputStaging {
    fn create(
        writable_workspace: &Path,
        machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            if let Some(binding) = machine_global_retention {
                return Self::create_bound(writable_workspace, binding);
            }
            let runtime_root = crate::process_runner::trusted_linux_runtime_root()
                .context("owner-private runtime root is unavailable for output staging")?;
            Self::create_under_with_retention(&runtime_root, writable_workspace, None)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (writable_workspace, machine_global_retention);
            bail!("private external-agent output staging requires the strict Linux runtime")
        }
    }

    #[cfg(target_os = "linux")]
    fn create_bound(
        writable_workspace: &Path,
        binding: ExternalMachineGlobalRetentionBinding,
    ) -> Result<Self> {
        let store = MachineGlobalStore::open_config(&binding.config)
            .context("failed to open machine-global config before output staging")?;
        let root_reservation = store
            .reserve_random_direct_child_directory(
                &binding.root_id,
                OsStr::new("maco-external-output-"),
            )
            .context("failed to reserve output staging under the reviewed machine-global root")?;
        let root_path = root_reservation.path().to_path_buf();
        let prepared = (|| -> Result<ReservedOutputFile> {
            let root = SecureOutputRoot::open_private(&root_path)?;
            root.reject_inside(writable_workspace)?;
            root.reserve(OsStr::new("last-message.raw"))
        })();
        match prepared {
            Ok(reservation) => Ok(Self {
                root_path,
                reservation: Some(reservation),
                machine_global_retention: Some(binding),
                bound_store: Some(store),
                bound_root_reservation: Some(root_reservation),
                cleanup_completed: false,
            }),
            Err(error) => {
                store
                    .remove_empty_reserved_direct_child_directory(
                        &binding.root_id,
                        root_reservation,
                    )
                    .context("failed to roll back empty reviewed-root output staging")?;
                Err(error)
            }
        }
    }

    #[cfg(all(target_os = "linux", test))]
    fn create_under(runtime_root: &Path, writable_workspace: &Path) -> Result<Self> {
        Self::create_under_with_retention(runtime_root, writable_workspace, None)
    }

    #[cfg(target_os = "linux")]
    fn create_under_with_retention(
        runtime_root: &Path,
        writable_workspace: &Path,
        machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    ) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;

        if let Some(binding) = machine_global_retention {
            return Self::create_bound(writable_workspace, binding);
        }

        let mut root_path = None;
        for _ in 0..16 {
            let sequence = OUTPUT_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = runtime_root.join(format!(
                ".maco-external-output-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => {
                    root_path = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create private output staging {}",
                            candidate.display()
                        )
                    });
                }
            }
        }
        let root_path =
            root_path.context("private output staging name collision limit was exhausted")?;
        let prepared = (|| -> Result<ReservedOutputFile> {
            let root = SecureOutputRoot::open_private(&root_path)?;
            root.reject_inside(writable_workspace)?;
            root.reserve(OsStr::new("last-message.raw"))
        })();
        match prepared {
            Ok(reservation) => Ok(Self {
                root_path,
                reservation: Some(reservation),
                machine_global_retention: None,
                bound_store: None,
                bound_root_reservation: None,
                cleanup_completed: false,
            }),
            Err(error) => {
                tracing::warn!(
                    actor = "maco-external-agent",
                    operation = "delete_empty_output_staging_setup_rollback",
                    process_attribution = "not_process_observable",
                    reason = "output reservation creation failed before staging accepted data",
                    "machine-global cleanup bypass"
                );
                let _ = fs::remove_dir(&root_path);
                Err(error)
            }
        }
    }

    fn root_path(&self) -> &Path {
        &self.root_path
    }

    fn path(&self) -> Result<&Path> {
        self.reservation
            .as_ref()
            .map(ReservedOutputFile::path)
            .context("private output staging reservation was already cleaned")
    }

    fn reservation(&self) -> Result<&ReservedOutputFile> {
        self.reservation
            .as_ref()
            .context("private output staging reservation was already cleaned")
    }

    fn reservation_mut(&mut self) -> Result<&mut ReservedOutputFile> {
        self.reservation
            .as_mut()
            .context("private output staging reservation was already cleaned")
    }

    fn cleanup(&mut self) -> Result<ExternalOutputCleanup> {
        let Some(binding) = self.machine_global_retention.as_ref() else {
            let attribution = MachineGlobalBypassAttribution {
                actor: "maco-external-agent".to_string(),
                operation: "delete_private_output_staging".to_string(),
                process_attribution: "not_process_observable".to_string(),
                reason: "no explicit machine-global config/root binding was supplied".to_string(),
            };
            tracing::warn!(
                actor = %attribution.actor,
                operation = %attribution.operation,
                process_attribution = %attribution.process_attribution,
                reason = %attribution.reason,
                "machine-global cleanup bypass"
            );
            self.cleanup_inner()?;
            self.cleanup_completed = true;
            return Ok(ExternalOutputCleanup::Bypassed(attribution));
        };

        let bound_store = self
            .bound_store
            .as_ref()
            .context("bound output staging lost its reviewed-root capability")?;
        bound_store
            .revalidate_root(&binding.root_id)
            .context("reviewed output-staging root changed before cleanup")?;
        let store = MachineGlobalStore::open_config(&binding.config)?;
        if !bound_store.matches_config_binding(&store) {
            bail!("machine-global config binding changed before output-staging cleanup");
        }
        let coordinate =
            store.coordinate_for_existing_directory(&binding.root_id, &self.root_path)?;
        let outcome = store.quarantine(
            &binding.owner,
            &binding.correction_correlation_id,
            vec![DestructiveTargetInput::Declared(coordinate)],
        )?;
        match outcome {
            GateOutcome::Allowed(operation) => {
                self.reservation.take();
                self.bound_root_reservation.take();
                self.bound_store.take();
                self.cleanup_completed = true;
                Ok(ExternalOutputCleanup::Quarantined(operation))
            }
            GateOutcome::Denied(denial) => Ok(ExternalOutputCleanup::Denied(denial)),
        }
    }

    fn cleanup_inner(&mut self) -> Result<()> {
        if let Some(reservation) = self.reservation.take() {
            reservation
                .remove()
                .context("failed to remove reserved raw output staging leaf")?;
        }
        fs::remove_dir(&self.root_path).with_context(|| {
            format!(
                "failed to remove private output staging root {}",
                self.root_path.display()
            )
        })
    }
}

impl Drop for ExternalOutputStaging {
    fn drop(&mut self) {
        if self.cleanup_completed {
            return;
        }
        if self.machine_global_retention.is_some() {
            if self.reservation.is_some() {
                tracing::warn!(
                    actor = "maco-external-agent",
                    operation = "preserve_private_output_staging",
                    process_attribution = "not_process_observable",
                    denied_or_incomplete = true,
                    "preserved machine-global-bound output staging because cleanup did not complete"
                );
            }
            return;
        }
        tracing::warn!(
            actor = "maco-external-agent",
            operation = "delete_private_output_staging",
            process_attribution = "not_process_observable",
            "machine-global cleanup bypass in unbound output-staging Drop"
        );
        if self.cleanup_inner().is_ok() {
            self.cleanup_completed = true;
        }
    }
}

#[derive(Debug)]
struct CodexPreflightFailure {
    failure: Box<EnvironmentFailure>,
    timed_out: bool,
}

#[derive(Debug)]
struct EnvironmentProbeFailure {
    category: EnvironmentFailureCategory,
    summary: String,
    timed_out: bool,
}

#[derive(Debug, Default)]
struct EnvironmentPreflightReport {
    results: Vec<EnvironmentPreflightResult>,
    failures: Vec<EnvironmentFailure>,
    codex_version: Option<EnvironmentVersion>,
    verified_confinement: Option<SideEffectConfinementProfileKind>,
    process_evidence: EnvironmentPreflightProcessEvidence,
    timed_out: bool,
}

#[derive(Debug, Default)]
struct EnvironmentPreflightProcessEvidence {
    started: bool,
    process_tree: Option<ProcessTreeEvidence>,
    side_effects: Option<SideEffectConfinementEvidence>,
}

impl EnvironmentPreflightProcessEvidence {
    fn record_output(&mut self, output: &ProcessOutput) {
        self.record(
            output.process_tree,
            output.side_effects,
            output.safety_evidence_verified(),
        );
    }

    fn record_error(&mut self, error: &ProcessRunError) {
        match error {
            ProcessRunError::Wait { evidence, .. }
            | ProcessRunError::Cancelled {
                evidence: Some(evidence),
                ..
            } => self.record(
                evidence.process_tree,
                evidence.side_effects,
                evidence.process_tree.is_verified_empty() && evidence.side_effects.is_verified(),
            ),
            ProcessRunError::OpenTee { .. }
            | ProcessRunError::TeeConflict { .. }
            | ProcessRunError::Spawn { .. }
            | ProcessRunError::SetupTimeout { .. }
            | ProcessRunError::ProcessOwnership { .. }
            | ProcessRunError::IoSetup { .. } => self.record(
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                false,
            ),
            ProcessRunError::EnvironmentFailure {
                target_process_started: true,
                ..
            } => self.record(
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                false,
            ),
            ProcessRunError::Cancelled { evidence: None, .. }
            | ProcessRunError::ContainmentUnavailable { .. }
            | ProcessRunError::EnvironmentFailure {
                target_process_started: false,
                ..
            }
            | ProcessRunError::StdinTooLarge { .. } => {}
        }
    }

    fn record(
        &mut self,
        process_tree: ProcessTreeEvidence,
        side_effects: SideEffectConfinementEvidence,
        verified: bool,
    ) {
        let retained_verified = self
            .process_tree
            .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && self
                .side_effects
                .is_some_and(SideEffectConfinementEvidence::is_verified);
        if !self.started || (retained_verified && !verified) {
            self.process_tree = Some(process_tree);
            self.side_effects = Some(side_effects);
        }
        self.started = true;
    }
}

fn process_run_error_definitely_before_process_start(error: &ProcessRunError) -> bool {
    matches!(
        error,
        ProcessRunError::Cancelled { evidence: None, .. }
            | ProcessRunError::ContainmentUnavailable { .. }
            | ProcessRunError::EnvironmentFailure {
                target_process_started: false,
                ..
            }
            | ProcessRunError::StdinTooLarge { .. }
    )
}

fn target_process_environment_failure(
    error: &ProcessRunError,
) -> Option<(EnvironmentFailureCategory, Option<EnvironmentRequirement>)> {
    match error {
        ProcessRunError::ContainmentUnavailable { .. }
        | ProcessRunError::ProcessOwnership { .. } => Some((
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
        )),
        ProcessRunError::EnvironmentFailure { failure, .. } => Some((
            failure.category,
            (failure.category == EnvironmentFailureCategory::SandboxUnavailable).then(|| {
                EnvironmentRequirement::sandbox(EnvironmentSandboxCapability::VerifiedExternalCodex)
            }),
        )),
        ProcessRunError::Cancelled { .. }
        | ProcessRunError::OpenTee { .. }
        | ProcessRunError::TeeConflict { .. }
        | ProcessRunError::Spawn { .. }
        | ProcessRunError::SetupTimeout { .. }
        | ProcessRunError::Wait { .. }
        | ProcessRunError::IoSetup { .. }
        | ProcessRunError::StdinTooLarge { .. } => None,
    }
}

fn retain_environment_preflight_process_evidence(
    report: &mut ExternalAgentRun,
    evidence: &EnvironmentPreflightProcessEvidence,
) {
    report
        .stdout
        .run_metadata
        .environment_preflight_process_started = evidence.started;
    report
        .stdout
        .run_metadata
        .environment_preflight_quiescence_verified = evidence.started
        && evidence
            .process_tree
            .is_some_and(ProcessTreeEvidence::is_verified_empty)
        && evidence
            .side_effects
            .is_some_and(SideEffectConfinementEvidence::is_verified);
    if evidence.started {
        report.process_tree = evidence.process_tree;
        report.side_effects = evidence.side_effects;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnvironmentVersionProbe {
    version: EnvironmentVersion,
    verified_confinement: SideEffectConfinementProfileKind,
}

#[allow(clippy::too_many_arguments)]
fn preflight_codex_version(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    side_effect_profile: &SideEffectConfinementProfile,
    codex_auth: Option<&ValidatedCodexAuth>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    process_evidence: &mut EnvironmentPreflightProcessEvidence,
) -> std::result::Result<EnvironmentVersionProbe, CodexPreflightFailure> {
    let requirement = codex_environment_requirement();
    let version = run_fixed_version_probe(
        EnvironmentExecutable::Codex,
        program,
        cwd,
        timeout,
        cancellation,
        environment,
        side_effect_profile,
        codex_auth,
        agent_lifecycle,
        process_evidence,
    )
    .map_err(|probe| CodexPreflightFailure {
        timed_out: probe.timed_out,
        failure: Box::new(environment_failure(
            probe.category,
            Some(requirement.clone()),
            probe.summary,
        )),
    })?;
    let constraint = EnvironmentVersionConstraint::at_least(EnvironmentVersion::new(
        CODEX_MINIMUM_VERSION.0,
        CODEX_MINIMUM_VERSION.1,
        CODEX_MINIMUM_VERSION.2,
    ));
    if !constraint.accepts(version.version) {
        return Err(CodexPreflightFailure {
            failure: Box::new(environment_failure(
                EnvironmentFailureCategory::VersionMismatch,
                Some(requirement),
                format!(
                    "Codex {} is too old; {}.{}.{} or newer custom permissions are required",
                    version.version,
                    CODEX_MINIMUM_VERSION.0,
                    CODEX_MINIMUM_VERSION.1,
                    CODEX_MINIMUM_VERSION.2
                ),
            )),
            timed_out: false,
        });
    }
    Ok(version)
}

fn preflight_custom_codex_version(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    process_evidence: &mut EnvironmentPreflightProcessEvidence,
) -> std::result::Result<EnvironmentVersionProbe, CodexPreflightFailure> {
    let program_parent = program.parent().ok_or_else(|| CodexPreflightFailure {
        failure: Box::new(environment_failure(
            EnvironmentFailureCategory::ProbeFailed,
            Some(codex_environment_requirement()),
            format!(
                "Codex executable has no parent directory: {}",
                program.display()
            ),
        )),
        timed_out: false,
    })?;
    let environment = BTreeMap::from([("PATH".to_string(), TRUSTED_PATH.to_string())]);
    let profile = SideEffectConfinementProfile::StrictOfflineWorkspace(
        StrictOfflineWorkspaceProfile::read_only(cwd).with_visible_read_only_root(program_parent),
    );
    preflight_codex_version(
        program,
        cwd,
        timeout,
        cancellation,
        &environment,
        &profile,
        None,
        agent_lifecycle,
        process_evidence,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_environment_preflight(
    spec: &ExternalAgentCommand,
    resolved_codex: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    side_effect_profile: &SideEffectConfinementProfile,
    codex_auth: Option<&ValidatedCodexAuth>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
) -> EnvironmentPreflightReport {
    let mut report = EnvironmentPreflightReport::default();
    if let Err(error) = validate_environment_requirements(&spec.environment_requirements) {
        report.failures.push(environment_failure(
            EnvironmentFailureCategory::ProbeFailed,
            None,
            format!("invalid environment requirements: {error}"),
        ));
        return report;
    }

    let started = Instant::now();
    let implicit_codex = codex_environment_requirement();
    let codex_probe = preflight_codex_version(
        resolved_codex,
        &spec.cwd,
        timeout,
        cancellation,
        environment,
        side_effect_profile,
        codex_auth,
        agent_lifecycle,
        &mut report.process_evidence,
    );
    match codex_probe {
        Ok(probe) => {
            report.codex_version = Some(probe.version);
            report.verified_confinement = Some(probe.verified_confinement);
            report.results.push(EnvironmentPreflightResult {
                requirement: implicit_codex,
                status: EnvironmentPreflightStatus::Satisfied,
                observation: Some(EnvironmentPreflightObservation::ExecutableVersion {
                    executable: EnvironmentExecutable::Codex,
                    version: probe.version,
                }),
            });
        }
        Err(failure) => {
            report.timed_out = failure.timed_out;
            report.results.push(EnvironmentPreflightResult {
                requirement: implicit_codex,
                status: EnvironmentPreflightStatus::Blocked,
                observation: None,
            });
            report.failures.push(*failure.failure);
        }
    }

    for requirement in &spec.environment_requirements {
        let remaining = timeout.saturating_sub(started.elapsed());
        let (result, failure, timed_out) = evaluate_environment_requirement(
            requirement,
            &spec.cwd,
            remaining,
            cancellation,
            environment,
            side_effect_profile,
            codex_auth,
            report.codex_version,
            report.verified_confinement,
            agent_lifecycle,
            &mut report.process_evidence,
        );
        report.results.push(result);
        if let Some(failure) = failure {
            report.failures.push(failure);
        }
        report.timed_out |= timed_out;
    }
    report
}

#[allow(clippy::too_many_arguments)]
fn evaluate_environment_requirement(
    requirement: &EnvironmentRequirement,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    side_effect_profile: &SideEffectConfinementProfile,
    codex_auth: Option<&ValidatedCodexAuth>,
    observed_codex_version: Option<EnvironmentVersion>,
    verified_confinement: Option<SideEffectConfinementProfileKind>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    process_evidence: &mut EnvironmentPreflightProcessEvidence,
) -> (EnvironmentPreflightResult, Option<EnvironmentFailure>, bool) {
    match requirement {
        EnvironmentRequirement::Executable {
            executable,
            version,
        } => {
            let observed = if *executable == EnvironmentExecutable::Codex {
                match observed_codex_version {
                    Some(version) => Ok(version),
                    None => Err(EnvironmentProbeFailure {
                        category: EnvironmentFailureCategory::ProbeFailed,
                        summary: "Codex version was unavailable after its mandatory preflight"
                            .to_string(),
                        timed_out: false,
                    }),
                }
            } else {
                resolve_environment_executable(*executable).and_then(|program| {
                    run_fixed_version_probe(
                        *executable,
                        &program,
                        cwd,
                        timeout,
                        cancellation,
                        environment,
                        side_effect_profile,
                        codex_auth,
                        agent_lifecycle,
                        process_evidence,
                    )
                    .map(|probe| probe.version)
                })
            };
            match observed {
                Ok(observed_version)
                    if version.is_none_or(|constraint| constraint.accepts(observed_version)) =>
                {
                    (
                        EnvironmentPreflightResult {
                            requirement: requirement.clone(),
                            status: EnvironmentPreflightStatus::Satisfied,
                            observation: Some(EnvironmentPreflightObservation::ExecutableVersion {
                                executable: *executable,
                                version: observed_version,
                            }),
                        },
                        None,
                        false,
                    )
                }
                Ok(observed_version) => {
                    let summary = format!(
                        "{} {observed_version} does not satisfy the declared version constraint",
                        executable.program_name()
                    );
                    (
                        EnvironmentPreflightResult {
                            requirement: requirement.clone(),
                            status: EnvironmentPreflightStatus::Blocked,
                            observation: Some(EnvironmentPreflightObservation::ExecutableVersion {
                                executable: *executable,
                                version: observed_version,
                            }),
                        },
                        Some(environment_failure(
                            EnvironmentFailureCategory::VersionMismatch,
                            Some(requirement.clone()),
                            summary,
                        )),
                        false,
                    )
                }
                Err(probe) => (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    },
                    Some(environment_failure(
                        probe.category,
                        Some(requirement.clone()),
                        probe.summary,
                    )),
                    probe.timed_out,
                ),
            }
        }
        EnvironmentRequirement::Credential { credential } => {
            let present = credential_present(*credential, environment);
            if present {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::CredentialPresent {
                            credential: *credential,
                        }),
                    },
                    None,
                    false,
                )
            } else {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    },
                    Some(environment_failure(
                        EnvironmentFailureCategory::MissingCredential,
                        Some(requirement.clone()),
                        format!(
                            "required credential source {} is absent from the sanitized child environment",
                            credential_name(*credential)
                        ),
                    )),
                    false,
                )
            }
        }
        EnvironmentRequirement::Configuration { configuration } => {
            let present = configuration_present(*configuration, codex_auth);
            if present {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::ConfigurationPresent {
                            configuration: *configuration,
                        }),
                    },
                    None,
                    false,
                )
            } else {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    },
                    Some(environment_failure(
                        EnvironmentFailureCategory::MissingCredential,
                        Some(requirement.clone()),
                        format!(
                            "required configuration source {} is absent from the sanitized child runtime",
                            configuration_name(*configuration)
                        ),
                    )),
                    false,
                )
            }
        }
        EnvironmentRequirement::Network { access } => {
            let enforced_offline =
                verified_confinement == Some(SideEffectConfinementProfileKind::ExternalCodex);
            if *access == EnvironmentNetworkAccess::Disabled && enforced_offline {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::Network {
                            enabled: false,
                        }),
                    },
                    None,
                    false,
                )
            } else if *access == EnvironmentNetworkAccess::Disabled {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: None,
                    },
                    Some(environment_failure(
                        EnvironmentFailureCategory::SandboxUnavailable,
                        Some(requirement.clone()),
                        "the fixed child sandbox did not produce verified offline confinement evidence"
                            .to_string(),
                    )),
                    false,
                )
            } else {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: enforced_offline
                            .then_some(EnvironmentPreflightObservation::Network {
                                enabled: false,
                            }),
                    },
                    Some(environment_failure(
                        EnvironmentFailureCategory::NetworkForbidden,
                        Some(requirement.clone()),
                        "the supervised child requires network access, but its fixed permission profile disables network access"
                            .to_string(),
                    )),
                    false,
                )
            }
        }
        EnvironmentRequirement::Sandbox { capability } => {
            let verified = *capability == EnvironmentSandboxCapability::VerifiedExternalCodex
                && verified_confinement == Some(SideEffectConfinementProfileKind::ExternalCodex);
            if verified {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::Sandbox {
                            profile: SideEffectConfinementProfileKind::ExternalCodex,
                        }),
                    },
                    None,
                    false,
                )
            } else {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Blocked,
                        observation: verified_confinement
                            .map(|profile| EnvironmentPreflightObservation::Sandbox { profile }),
                    },
                    Some(environment_failure(
                        EnvironmentFailureCategory::SandboxUnavailable,
                        Some(requirement.clone()),
                        "the fixed ExternalCodex confinement profile was not safely verified"
                            .to_string(),
                    )),
                    false,
                )
            }
        }
    }
}

include!("external_agent/part2.rs");

#[cfg(test)]
mod preflight_quiescence_regression {
    use super::*;

    fn explicit_custom_policy_refusal(command: &ExternalAgentCommand) -> ExternalAgentRun {
        failed_external_environment_run(
            command,
            Instant::now(),
            vec!["codex".to_string(), "--version".to_string()],
            false,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
            "explicit custom target refused after version preflight".to_string(),
        )
    }

    #[test]
    fn retained_probe_quiescence_is_live_only_and_target_aware() -> Result<()> {
        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        let mut verified_probe = EnvironmentPreflightProcessEvidence::default();
        verified_probe.record(
            ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
            SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            true,
        );

        let mut live_report = explicit_custom_policy_refusal(&command);
        retain_environment_preflight_process_evidence(&mut live_report, &verified_probe);
        live_report.process_tree = None;
        live_report.side_effects = None;
        assert!(live_report.environment_blocked());
        assert!(live_report.scratch_quiescence_verified());
        assert!(live_report.environment_preflight_quiescence_verified());

        let serialized = serde_json::to_string(&live_report)?;
        assert!(!serialized.contains("environment_preflight_quiescence_verified"));
        let restored: ExternalAgentRun = serde_json::from_str(&serialized)?;
        assert!(!restored.scratch_quiescence_verified());
        assert!(!restored.environment_preflight_quiescence_verified());

        live_report.stdout.target_launch_attempted = true;
        assert!(!live_report.scratch_quiescence_verified());
        assert!(!live_report.environment_preflight_quiescence_verified());

        let mut unverified_probe = EnvironmentPreflightProcessEvidence::default();
        unverified_probe.record(
            ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
            SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            false,
        );
        let mut unverified_report = explicit_custom_policy_refusal(&command);
        retain_environment_preflight_process_evidence(&mut unverified_report, &unverified_probe);
        unverified_report.process_tree = None;
        unverified_report.side_effects = None;
        assert!(!unverified_report.scratch_quiescence_verified());
        assert!(!unverified_report.environment_preflight_quiescence_verified());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
