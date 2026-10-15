use crate::account_authority::{
    CodexRunAccountBinding, FrozenClaudeSelectedBinding, FrozenCodexSelectedBinding,
    FrozenCursorSelectedBinding, FrozenGeminiSelectedBinding, FrozenGrokSelectedBinding,
    ManagedCursorAccountSelectionEvidence, ManagedGeminiAccountSelectionEvidence,
    ManagedGrokAccountSelectionEvidence,
};
use crate::agent_lifecycle::{AgentLaunchMetadata, MACO_RUN_ID_ENV, MACO_TASK_ID_ENV};
use crate::artifacts::state_auth::sha256_hex;
use crate::gate_denial::{ExternalSideEffectState, GateDenial};
use crate::llm::provider::Usage;
use crate::machine_global::{
    DestructiveTargetInput, GateOutcome, MachineGlobalRetentionBinding, MachineGlobalStore,
    RetentionOperation, RetentionOperationId,
};
use crate::messaging::transport::AssignmentMessagingLaunch;
use crate::mutation_taxonomy::{
    AssignmentProcessLaunchGrant, AssignmentProcessLaunchGrantError, AssignmentProcessLaunchKind,
    AssignmentProcessMechanicalBinding, CatalogPreflightOrigin, SealedMechanicalExecutorDuty,
    SupervisorCatalogCodexPreflightGrant, SupervisorCatalogCodexPreflightGrantError,
};
use crate::pre_action_review::{
    ActionDescriptor, ApprovalReviewRequest, BlastRadius, CommandClass, CommandInvocation,
    DecisionSource, PathAccess, PathAccessMode, PermissionRequest, PreActionReviewer,
    RedactedClassifierRequest, ReviewContext, ReviewMetricSnapshot, ReviewOutcome,
};
use crate::process_runner::{
    read_bounded_regular_file_nofollow, run_process_cancellable,
    run_process_cancellable_with_filesystem_evidence, run_process_interactive, CapturedBytes,
    ClaudeContainmentOwnerBinding, ContainmentBackend, EnvironmentMode, ExternalClaudeProfile,
    ExternalCodexProfile, ExternalCursorProfile, ExternalGrokProfile, InteractiveProcessOutput,
    ProcessCancellation, ProcessCommand, ProcessOutput, ProcessRunError, ProcessSpec,
    ProcessTreeEvidence, ReadOnlyFilesystemEvidence, SideEffectConfinementEvidence,
    SideEffectConfinementProfile, SideEffectConfinementProfileKind, StdinMode, StreamCapture,
    StrictOfflineWorkspaceProfile, WorkspaceAccess,
};
#[cfg(target_os = "linux")]
use crate::process_runner::{
    run_process_cancellable_with_start_gate_and_filesystem_evidence,
    run_process_interactive_with_start_gate,
};
use crate::protected_path::{DeclaredPathCoordinate, ProtectedPathSpec};
#[cfg(target_os = "linux")]
use crate::runtime_adapter::claude::ClaudeManagedRelay;
#[cfg(target_os = "linux")]
use crate::runtime_adapter::grok::GrokCredentialSource;
use crate::runtime_adapter::{
    claude::{
        self, ClaudeAuthMode, ClaudeBrokerBinding, ClaudeManagedLaunchContract,
        ClaudeNativeEvidence, ClaudeTransportAuthMode, ClaudeWholeCallWitness,
    },
    grok::{
        grok_acp_parent_evidence_from_execution, GrokAcpParentEvidence, GrokAcpParentResolvedField,
        GrokStreamUsageEvidence,
    },
    grok_acp::{
        grok_acp_admitted_identity_publication_status,
        grok_acp_resolution_status_from_parent_label, GrokAcpBoundOutputSchema,
        GrokAcpContainedTransport, GrokAcpExecutionEvidence, GrokAcpLimits, GrokAcpTurn,
    },
    AdapterId, LaunchContext, RuntimeAdapterConfig, RuntimeId, SideEffectConfinement, TypedRuntime,
    TypedRuntimeContract, WritableLaunchTarget,
};
use crate::safe_state::{unsigned_to_u32, ReservedDirectory};
use crate::secure_output::{ReservedOutputFile, SecureOutputRoot};
use crate::supervise::AgentRole;
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
mod codex_parent_evidence;
#[allow(dead_code, unused_imports)]
pub(crate) mod executor;
pub(crate) mod gemini_bridge;
mod grok_steering;
pub(crate) mod researcher_inputs;

use codex_parent_evidence::{
    codex_parent_evidence_from_app_server_run, codex_parent_evidence_from_run,
    CodexParentEvidenceInputs,
};
pub use codex_parent_evidence::{
    CodexParentEvidence, CodexParentResolutionStatus, CodexParentResolvedField,
    CodexParentTurnUsage, CodexServerRerouteEvidence,
};
use grok_steering::GrokAcpSteeringBridge;

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
    effort_metadata: std::collections::BTreeMap<String, CodexModelEffortMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexModelEffortMetadata {
    pub supported: Option<BTreeSet<String>>,
    pub default: Option<String>,
}

impl CodexRuntimeModelCatalog {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_observed_models(
        models: &coding_agent_manager_lib::account_authority::ModelsObservation,
    ) -> Result<Self> {
        coding_agent_manager_lib::account_authority::validate_observed_models(models)
            .map_err(anyhow::Error::msg)?;
        let mut catalog =
            Self::from_slugs(models.models.iter().map(|model| model.model_id.clone()))?;
        for model in &models.models {
            catalog.effort_metadata.insert(
                model.model_id.clone(),
                CodexModelEffortMetadata {
                    supported: model
                        .supported_efforts
                        .as_ref()
                        .map(|efforts| efforts.iter().cloned().collect()),
                    default: model.default_effort.clone(),
                },
            );
        }
        Ok(catalog)
    }
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
        Ok(Self {
            slugs: validated,
            effort_metadata: Default::default(),
        })
    }

    pub(crate) fn contains(&self, slug: &str) -> bool {
        self.slugs.contains(slug)
    }

    #[cfg(test)]
    pub(crate) fn effort_metadata(&self, slug: &str) -> Option<&CodexModelEffortMetadata> {
        self.effort_metadata.get(slug)
    }

    #[cfg(test)]
    pub(crate) fn supports_effort(&self, slug: &str, effort: &str) -> bool {
        self.effort_metadata(slug)
            .and_then(|metadata| metadata.supported.as_ref())
            .is_some_and(|supported| supported.contains(effort))
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
    pub(crate) researcher_source_inputs: Vec<researcher_inputs::ResearcherSourceInput>,
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
    live_token_grant: Option<BoundLiveTokenGrant>,
    /// Parent-private reservation identity and exact Claude launch snapshot. This exists even
    /// when the ledger has no hard-token ceiling and therefore issues no live token grant.
    claude_reservation_binding: Option<BoundClaudeReservationBinding>,
    /// Opaque MACO-owned proof that the selected command, held claims, disposable worktree, and
    /// verified native confinement were authenticated together immediately before launch.
    worktree_writable_confinement: Option<WorktreeWritableConfinementProof>,
    /// Assignment-child / parent-auditor / Inbox-independent-auditor / consult /
    /// merge-arbiter launch kind. CodexConsultant accepts ConsultCodex or
    /// InboxIndependentAuditor; ClaudeConsultant accepts ConsultClaude only.
    /// MergeArbiter accepts only a merge-shaped CodexSupervisor command.
    /// Generic CodexSupervisor constructors still leave kind absent.
    pub(crate) assignment_process_launch_kind: Option<AssignmentProcessLaunchKind>,
    /// One-shot sibling grant consumed against the final ProcessSpec when kind is set.
    pub(crate) assignment_process_launch_grant: Option<AssignmentProcessLaunchGrant>,
    pub(crate) assignment_process_launch_attempt: Option<usize>,
    pub(crate) assignment_process_launch_duty: Option<String>,
    pub(crate) assignment_mechanical_executor_duty: Option<SealedMechanicalExecutorDuty>,
    /// Ephemeral assignment messaging IPC capability for this launch only. Never serialized into
    /// task artifacts or argv.
    assignment_messaging_launch: Option<AssignmentMessagingLaunch>,
    /// Pinned headless CAM authority socket for nested MACO supervise/agent launches only.
    cam_authority_socket_pin: Option<String>,
    /// Explicit initialized Codex selection, including a missing-selection refusal.
    codex_run_account_binding: Option<CodexRunAccountBinding>,
    /// Immutable Grok account binding admitted for this run. Launch must not recover
    /// the selected account from process-global observation state.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    grok_run_account_binding: Option<FrozenGrokSelectedBinding>,
    /// Immutable Cursor account binding admitted for this run. Launch never
    /// recovers authority from an ambient Cursor home.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cursor_run_account_binding: Option<FrozenCursorSelectedBinding>,
    /// Immutable Gemini account binding admitted for this run.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    gemini_run_account_binding: Option<FrozenGeminiSelectedBinding>,
    /// Immutable Claude account binding admitted for this run.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    claude_run_account_binding: Option<FrozenClaudeSelectedBinding>,
    /// Opt-in disable of Codex native multi_agent and goals. Not serialized.
    /// Does not change role identity, permissions, adapter, model, or effort.
    codex_native_delegation_disabled: bool,
    /// Private opt-in to byte-pinned delivery, not launch or permission authority.
    /// The executable capability is captured transiently from this original program context.
    read_only_target_executable_pin: Option<PathBuf>,
    /// Sealed opt-in for the verified managed read-only Codex parent app-server.
    /// Ordinary children, researchers, and workers stay off this route.
    codex_managed_readonly_route: CodexManagedReadonlyRoute,
    /// Selector-issued private admission; never reconstructed from report flags.
    selected_merge_arbiter: Option<std::sync::Arc<SelectedMergeArbiterAdmission>>,
}

/// Private selected admission. The snapshot contains command context, not captured credentials.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SelectedMergeArbiterAdmission {
    selected: crate::selection::routing_policy::SelectedLaunchRequest,
    decision: crate::selection::SelectionProvenance,
    frozen: crate::selection::routing_policy::FrozenRoutingPolicy,
    resolved: crate::selection::routing_policy::ResolvedRoleExecutionEvidence,
    command: Box<ExternalAgentCommand>,
}

impl std::fmt::Debug for SelectedMergeArbiterAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedMergeArbiterAdmission { private_binding: [redacted] }")
    }
}

impl SelectedMergeArbiterAdmission {
    fn matches_command(&self, command: &ExternalAgentCommand) -> bool {
        self.command.as_ref() == &selected_merge_command_snapshot(command)
    }

    pub(crate) fn validated_process_intent(&self) -> Result<(&str, &str, &Path, Option<&str>)> {
        validate_selected_merge_receipt(&self.selected, &self.decision, &self.frozen)?;
        let identity = self
            .command
            .agent_lifecycle
            .as_ref()
            .context("selected merge lifecycle missing")?;
        if identity.role != AgentRole::Auditor.as_str()
            || identity.run_id.is_empty()
            || identity.task_id.is_empty()
        {
            bail!("selected merge lifecycle differs from Auditor admission");
        }
        Ok((
            &identity.run_id,
            &identity.task_id,
            &self.command.program,
            self.command.model.as_deref(),
        ))
    }
}

fn selected_merge_command_snapshot(command: &ExternalAgentCommand) -> ExternalAgentCommand {
    let mut snapshot = command.clone();
    snapshot.selected_merge_arbiter = None;
    // Budget/IPC capabilities remain with their existing live owners, not result metadata.
    snapshot.live_token_grant = None;
    snapshot.claude_reservation_binding = None;
    snapshot.assignment_messaging_launch = None;
    snapshot.worktree_writable_confinement = None;
    snapshot.writable_runtime_selection = None;
    snapshot
}

fn validate_selected_merge_receipt(
    selected: &crate::selection::routing_policy::SelectedLaunchRequest,
    decision: &crate::selection::SelectionProvenance,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
) -> Result<()> {
    use crate::selection::routing_policy::{current_routing_policy, validate_selected_launch};
    let receipt = decision
        .routing_policy
        .as_ref()
        .context("selected merge receipt missing")?;
    let candidate = selected.candidate();
    frozen.resolve_role_execution_evidence(AgentRole::Auditor.as_str())?;
    if current_routing_policy().as_ref() != Some(frozen)
        || &receipt.frozen != frozen
        || receipt.role != AgentRole::Auditor.as_str()
        || decision.status != crate::selection::DecisionStatus::Selected
        || decision.normalized_input.task.authority_role
            != crate::selection::AuthorityRole::ReviewAuditor
        || decision.choice.as_ref().map(|choice| &choice.candidate) != Some(candidate)
        || !decision
            .candidate_set
            .iter()
            .any(|entry| entry.eligible && &entry.candidate == candidate)
        || selected.policy_digest != frozen.sha256
        || selected.task_features != receipt.features
        || selected.catalog_digest.is_empty()
        || selected.catalog_revision.is_empty()
    {
        bail!("selected merge evaluator, policy or feature binding differs");
    }
    validate_selected_launch(
        AgentRole::Auditor.as_str(),
        &candidate.runtime,
        &candidate.model,
        candidate.effort.as_str(),
    )
}

fn selected_merge_account_matches(
    command: &ExternalAgentCommand,
    selected: &crate::selection::routing_policy::SelectedLaunchRequest,
) -> bool {
    let expected = selected.account_binding();
    let matches = |provider: &str, account: &str, incarnation: &str, revision: u64| {
        provider == expected.provider_id
            && account == expected.account_id
            && incarnation == expected.account_incarnation
            && revision == expected.selection_revision
    };
    match command.invocation {
        ExternalAgentInvocation::CodexSupervisor => matches!(&command.codex_run_account_binding,
            Some(CodexRunAccountBinding::Selected(binding)) if matches(&binding.provider_id, &binding.account_id, &binding.account_incarnation, binding.selection_revision)),
        ExternalAgentInvocation::Grok => {
            command
                .grok_run_account_binding
                .as_ref()
                .is_some_and(|binding| {
                    matches(
                        &binding.provider_id,
                        &binding.account_id,
                        &binding.account_incarnation,
                        binding.selection_revision,
                    )
                })
        }
        ExternalAgentInvocation::Cursor => {
            command
                .cursor_run_account_binding
                .as_ref()
                .is_some_and(|binding| {
                    matches(
                        &binding.provider_id,
                        &binding.account_id,
                        &binding.account_incarnation,
                        binding.selection_revision,
                    )
                })
        }
        ExternalAgentInvocation::ClaudeCode => command
            .claude_run_account_binding
            .as_ref()
            .is_some_and(|binding| {
                matches(
                    &binding.provider_id,
                    &binding.account_id,
                    &binding.account_incarnation,
                    binding.selection_revision,
                )
            }),
        ExternalAgentInvocation::GeminiCli => command
            .gemini_run_account_binding
            .as_ref()
            .is_some_and(|binding| {
                matches(
                    &binding.provider_id,
                    &binding.account_id,
                    &binding.account_incarnation,
                    binding.selection_revision,
                )
            }),
        _ => false,
    }
}

fn selected_merge_live_account_matches(command: &ExternalAgentCommand) -> bool {
    let Some(identity) = command.agent_lifecycle.as_ref() else {
        return false;
    };
    match command.invocation {
        ExternalAgentInvocation::CodexSupervisor => {
            crate::account_authority::codex_run_account_binding(&identity.run_id)
                == command.codex_run_account_binding
        }
        ExternalAgentInvocation::Grok => {
            crate::account_authority::grok_run_account_binding(&identity.run_id)
                == command.grok_run_account_binding
        }
        ExternalAgentInvocation::Cursor => {
            crate::account_authority::cursor_run_account_binding(&identity.run_id)
                == command.cursor_run_account_binding
        }
        ExternalAgentInvocation::ClaudeCode => {
            crate::account_authority::claude_run_account_binding(&identity.run_id)
                == command.claude_run_account_binding
        }
        ExternalAgentInvocation::GeminiCli => {
            crate::account_authority::gemini_run_account_binding(&identity.run_id)
                == command.gemini_run_account_binding
        }
        _ => false,
    }
}

fn validate_selected_merge_command(command: &ExternalAgentCommand) -> Result<()> {
    let admission = command
        .selected_merge_arbiter
        .as_ref()
        .context("selected merge authority missing")?;
    admission.validated_process_intent()?;
    if !admission.matches_command(command)
        || !selected_merge_account_matches(command, &admission.selected)
        || !selected_merge_live_account_matches(command)
        || !merge_arbiter_command_is_merge_shaped(command)
    {
        bail!("selected merge command, principal or lifecycle changed");
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct SelectedMergeCompletionBinding {
    admission: std::sync::Arc<SelectedMergeArbiterAdmission>,
    held_output_sha256: String,
}

impl std::fmt::Debug for SelectedMergeCompletionBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedMergeCompletionBinding { held_binding: [redacted] }")
    }
}

/// Which verified managed read-only Codex app-server path this command requested.
/// Inconsistent combinations fail closed at launch instead of falling back to the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CodexManagedReadonlyRoute {
    #[default]
    Off,
    /// Initial parent: dynamic `maco_worker_request` tool forwarded to the sealed inbox.
    InitialWorkerRequests,
    /// Continuation: same read-only app-server, no dynamic tool and no fresh inbox.
    Continuation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundLiveTokenGrant {
    grant: crate::supervise_budget::LiveTokenGrant,
    invocation: ExternalAgentInvocation,
    program: PathBuf,
    cwd: PathBuf,
    prompt: PathBuf,
    model: Option<String>,
    model_provider: Option<String>,
    effort: Option<String>,
    timeout: Duration,
    workspace_access: WorkspaceAccess,
    launch_target: WritableLaunchTarget,
    lifecycle: Option<ExternalAgentLifecycleIdentity>,
    source_inputs: Vec<researcher_inputs::ResearcherSourceInput>,
    input_files: Vec<PathBuf>,
    confinement: WorktreeConfinementSnapshot,
    native_delegation_disabled: bool,
    managed_readonly_route: CodexManagedReadonlyRoute,
    process_kind: Option<AssignmentProcessLaunchKind>,
    process_attempt: Option<usize>,
    process_duty: Option<String>,
}

#[cfg(target_os = "linux")]
struct BoundWorkerJournalAppend {
    helper_path: PathBuf,
    helper_file: fs::File,
    helper_identity: ExternalProgramIdentity,
    helper_sha256: String,
    journal: ExactWritableArtifactFile,
    source_prompt_sha256: String,
}

#[cfg(target_os = "linux")]
impl BoundWorkerJournalAppend {
    fn revalidate(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.helper_file.metadata()?;
        let path_metadata = fs::symlink_metadata(&self.helper_path)?;
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let uid = unsafe { libc::geteuid() };
        if !path_metadata.is_file()
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.mode() != path_metadata.mode()
            || metadata.uid() != path_metadata.uid()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o6000 != 0
            || metadata.mode() & 0o111 == 0
            || fs::canonicalize(&self.helper_path)? != self.helper_path
            || external_program_identity(&self.helper_path)? != self.helper_identity
            || worker_journal_appender_sha256(&self.helper_file)? != self.helper_sha256
        {
            bail!("current MACO journal appender executable bytes or identity changed");
        }
        let held = exact_writable_artifact_identity(&self.journal.held_file.metadata()?)?;
        let path = exact_writable_artifact_identity(&fs::symlink_metadata(&self.journal.path)?)?;
        validate_exact_writable_artifact_identity(held)?;
        if held != self.journal.identity || path != held {
            bail!("precreated worker journal held descriptor/path binding changed");
        }
        Ok(())
    }

    fn command_prefix(&self) -> Result<Vec<String>> {
        let text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .context("worker journal append command requires a UTF-8 path")
        };
        Ok(vec![
            text(&self.helper_path)?,
            "supervise".to_string(),
            "journal-append".to_string(),
            "--journal".to_string(),
            text(&self.journal.path)?,
            "--device".to_string(),
            self.journal.identity.device.to_string(),
            "--inode".to_string(),
            self.journal.identity.inode.to_string(),
        ])
    }

    fn bind_grok_prompt(
        self,
        caller: &ExternalAgentCommand,
        target: &mut ExternalAgentCommand,
        prompt: &[u8],
        profile: &mut Option<SideEffectConfinementProfile>,
        argv: &mut Vec<OsString>,
        staging: &mut ExternalOutputStaging,
    ) -> Result<BoundGrokWorkerJournalLaunch> {
        let source = HeldWorkerPrompt::open(&caller.prompt, &self.source_prompt_sha256)?;
        let effective_sha256 = sha256_hex(prompt);
        target.prompt = staging.stage_worker_effective_prompt(&caller.cwd, prompt)?;
        let effective = HeldWorkerPrompt::open(&target.prompt, &effective_sha256)?;
        *argv = runtime_adapter_argv(target)?;
        let Some(SideEffectConfinementProfile::ExternalGrok(grok)) = profile.as_ref() else {
            bail!("Grok effective prompt requires the qualified native profile");
        };
        *profile = Some(SideEffectConfinementProfile::ExternalGrok(
            grok.clone().with_visible_read_only_file(&target.prompt),
        ));
        Ok(BoundGrokWorkerJournalLaunch {
            append: self,
            source,
            effective,
            effective_sha256,
            caller: caller.clone(),
            target: target.clone(),
            argv: argv.clone(),
            argv_sha256: argv_digest(argv)?,
            profile: None,
        })
    }
}

/// Private derived-launch custody; public reports and caller fields cannot mint it.
/// The caller's sealed command stays unchanged. Only the target prompt pathname
/// is mapped to the held staging leaf, under the same output-staging lifetime.
#[cfg(target_os = "linux")]
struct BoundGrokWorkerJournalLaunch {
    append: BoundWorkerJournalAppend,
    source: HeldWorkerPrompt,
    effective: HeldWorkerPrompt,
    effective_sha256: String,
    caller: ExternalAgentCommand,
    target: ExternalAgentCommand,
    argv: Vec<OsString>,
    argv_sha256: String,
    profile: Option<ExternalGrokProfile>,
}

#[cfg(target_os = "linux")]
impl BoundGrokWorkerJournalLaunch {
    fn seal_credential_profile(
        &mut self,
        profile: &SideEffectConfinementProfile,
        credentials: &BoundGrokCredentials<'_>,
    ) -> Result<()> {
        let SideEffectConfinementProfile::ExternalGrok(grok) = profile else {
            bail!("Grok journal launch lost its native profile");
        };
        if self.profile.is_some() || !credentials.present_in(profile) {
            bail!("Grok journal launch did not bind the exact held credential profile");
        }
        self.profile = Some(grok.clone());
        Ok(())
    }

    fn revalidate(
        &self,
        caller: &ExternalAgentCommand,
        target: &ExternalAgentCommand,
        argv: &[OsString],
        profile: &SideEffectConfinementProfile,
    ) -> Result<()> {
        let SideEffectConfinementProfile::ExternalGrok(grok) = profile else {
            bail!("Grok journal launch profile substituted");
        };
        if self.caller != *caller
            || self.target != *target
            || self.argv.as_slice() != argv
            || self.argv_sha256 != argv_digest(argv)?
            || self.profile.as_ref() != Some(grok)
        {
            bail!("Grok journal final command, argv, account or profile substituted");
        }
        caller.verified_writable_capabilities(RuntimeId::Grok)?;
        let lifecycle = caller
            .agent_lifecycle
            .as_ref()
            .context("Grok Worker identity missing")?;
        caller.verify_grok_run_account_binding(&lifecycle.run_id)?;
        self.append.revalidate()?;
        self.source
            .revalidate(&caller.prompt, &self.append.source_prompt_sha256)?;
        self.effective
            .revalidate(&target.prompt, &self.effective_sha256)
            .context("Grok journal effective prompt identity or bytes substituted")?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn prepare_grok_worker_journal_launch(
    spec: &ExternalAgentCommand,
    target: &mut ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    prompt: &mut Vec<u8>,
    profile: &mut Option<SideEffectConfinementProfile>,
    argv: &mut Vec<OsString>,
    staging: &mut ExternalOutputStaging,
) -> Result<Option<BoundGrokWorkerJournalLaunch>> {
    if spec.invocation != ExternalAgentInvocation::Grok {
        return Ok(None);
    }
    let Some(append) = bind_worker_journal_append_operation(
        spec,
        controls,
        ExternalExecutionRuntime::Verified,
        ExternalProgramTrust::ExplicitCustom,
        prompt,
        profile,
        argv,
    )?
    else {
        return Ok(None);
    };
    append
        .bind_grok_prompt(spec, target, prompt, profile, argv, staging)
        .map(Some)
}

#[cfg(target_os = "linux")]
fn record_grok_journal_custody_failure(report: &mut ExternalAgentRun, error: &anyhow::Error) {
    // Original native spend is already retained. Refuse completion without
    // clearing counters, manufacturing zero usage, or authorizing a refund.
    if let Some(capture) = report.stdout.run_metadata.grok_native_usage.as_mut() {
        capture.process_completed = false;
    }
    report.error = append_external_error(
        report.error.take(),
        Some(format!(
            "Grok journal binding changed during execution: {error:#}"
        )),
    );
    report.publishable = false;
}

#[cfg(all(test, target_os = "linux"))]
mod grok_worker_journal_binding_tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn fixture() -> Result<(
        tempfile::TempDir,
        ExternalAgentCommand,
        ProtectedWorktreeControls,
        ExternalOutputStaging,
    )> {
        let (temp, mut spec, controls) = worker_journal_append_binding_tests::fixture();
        let run = format!(
            "grok-journal-{}",
            temp.path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .trim_start_matches('.')
        );
        let account = FrozenGrokSelectedBinding {
            authority_socket: None,
            authority_id: Some("fixture-authority".into()),
            provider_id: "grok-cli".into(),
            account_id: "fixture-account".into(),
            account_incarnation: "fixture-incarnation".into(),
            selection_revision: 3,
        };
        crate::account_authority::admit_grok_run_account_binding(&run, Some(account.clone()));
        spec.program = PathBuf::from("/pinned/grok");
        spec = spec
            .with_runtime_adapter(
                RuntimeId::Grok,
                RuntimeAdapterConfig::defaults(RuntimeId::Grok),
            )
            .with_model_selection(Some("grok-4.7".into()), Some("xhigh".into()))
            .with_agent_lifecycle(temp.path(), "worker", &run, "worker")
            .with_agent_parent("parent")
            .with_grok_run_account_binding(Some(account));
        fs::write(&spec.prompt, b"original bounded Worker prompt")?;
        let schema = temp.path().join("worker.schema.json");
        fs::write(&schema, b"{\"type\":\"object\"}")?;
        spec.output_schema = Some(schema);
        spec = spec
            .with_writable_runtime_selection("worker", RuntimeId::Grok, true)?
            .with_worktree_writable_confinement(WorktreeWritableAdmission {
                version: WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION,
                assignment_id: "worker".into(),
                attempt: 1,
                target: WritableLaunchTarget::ManagedChildWorktree,
                worktree: ManagedWorktreeAdmission {
                    kind: ManagedWorktreeAdmissionKind::ManagedDisposable,
                    worktree_id: "worker".into(),
                },
                claims: HeldPathClaimsAdmission {
                    state: HeldPathClaimsAdmissionState::Held,
                    token: 41,
                    paths: vec![PathBuf::from("src")],
                },
                native_sandbox: NativeSandboxAdmission {
                    runtime: RuntimeId::Grok,
                    workspace_access: WorkspaceAccess::ReadWrite,
                    side_effect_confinement: SideEffectConfinement::Verified,
                },
            });
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            &run,
            "worker",
            1,
            Path::new("codex"),
            spec.model.as_deref(),
            "grok-worker-duty",
        )?;
        spec = spec
            .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant);
        let staging = ExternalOutputStaging::create_under(temp.path(), &spec.cwd)?;
        Ok((temp, spec, controls, staging))
    }

    fn profile(
        spec: &ExternalAgentCommand,
        controls: &ProtectedWorktreeControls,
    ) -> Result<Option<SideEffectConfinementProfile>> {
        let journal = &controls.exact_writable_artifact_files[0];
        Ok(Some(SideEffectConfinementProfile::ExternalGrok(
            ExternalGrokProfile::read_write(&spec.cwd)
                .with_hidden_root(spec.cwd.join(".maco"))
                .with_visible_read_only_file(&spec.prompt)
                .with_visible_read_only_file(spec.output_schema.as_ref().unwrap())
                .with_visible_read_only_root(journal.path.parent().unwrap())
                .with_visible_read_write_file_capability(
                    &journal.path,
                    std::sync::Arc::clone(&journal.held_file),
                )?,
        )))
    }

    fn nested_fixture() -> Result<(
        tempfile::TempDir,
        ExternalAgentCommand,
        ProtectedWorktreeControls,
        ExternalOutputStaging,
    )> {
        let (temp, spec, controls, staging) = fixture()?;
        let run = &spec.agent_lifecycle.as_ref().unwrap().run_id;
        let admission = NestedWorktreeWritableAdmission::from_live_assignment_authority(
            "worker",
            "parent",
            run,
            1,
            1,
            "parent",
            &spec.cwd,
            "maco/parent",
            "parent",
            41,
            &[PathBuf::from("src")],
            &[PathBuf::from("src/a.py")],
            Some(19),
            NativeSandboxAdmission {
                runtime: RuntimeId::Grok,
                workspace_access: WorkspaceAccess::ReadWrite,
                side_effect_confinement: SideEffectConfinement::Verified,
            },
            &spec.worker_journal_artifacts,
        )?;
        let spec = spec.with_nested_worktree_writable_confinement(admission)?;
        Ok((temp, spec, controls, staging))
    }

    fn seal_profile(
        temp: &Path,
        binding: &mut BoundGrokWorkerJournalLaunch,
        profile: &mut Option<SideEffectConfinementProfile>,
    ) -> Result<AdmittedGrokCredentials> {
        let home = temp.join("synthetic-grok-home");
        fs::create_dir(&home)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        let mut auth = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.join("auth.json"))?;
        std::io::Write::write_all(&mut auth, b"synthetic-unread-auth-fixture")?;
        let credentials = AdmittedGrokCredentials::from_managed_grok_home(&home)?;
        let Some(SideEffectConfinementProfile::ExternalGrok(grok)) = profile.take() else {
            bail!("expected native profile");
        };
        let bound = BoundGrokCredentials::new(&credentials, grok)?;
        *profile = Some(SideEffectConfinementProfile::ExternalGrok(
            bound.profile.clone(),
        ));
        binding.seal_credential_profile(profile.as_ref().unwrap(), &bound)?;
        Ok(credentials)
    }

    #[test]
    fn grok_journal_production_caller_binds_effective_prompt_and_exact_helper() -> Result<()> {
        let (temp, spec, controls, mut staging) = nested_fixture()?;
        let original = spec.clone();
        let mut target = spec.clone();
        target.output_last_message = staging.path()?.to_path_buf();
        let mut prompt = fs::read(&spec.prompt)?;
        let mut mounted = profile(&spec, &controls)?;
        let mut argv = runtime_adapter_argv(&spec)?;
        let original_argv = argv.clone();
        let mut binding = prepare_grok_worker_journal_launch(
            &spec,
            &mut target,
            &controls,
            &mut prompt,
            &mut mounted,
            &mut argv,
            &mut staging,
        )?
        .context("qualified Worker must bind the actual operation")?;
        let _credentials = seal_profile(temp.path(), &mut binding, &mut mounted)?;
        binding.revalidate(&spec, &target, &argv, mounted.as_ref().unwrap())?;
        assert_eq!(spec, original);
        assert_eq!(fs::read(&spec.prompt)?, b"original bounded Worker prompt");
        assert_eq!(fs::read(&target.prompt)?, prompt);
        assert!(target.prompt.starts_with(staging.root_path()));
        let mut expected = original_argv;
        let position = expected
            .iter()
            .position(|arg| arg == OsStr::new("--prompt-file"))
            .unwrap();
        expected[position + 1] = target.prompt.clone().into_os_string();
        assert_eq!(argv, expected);
        for flag in [
            "--no-subagents",
            "--no-memory",
            "--disable-web-search",
            "--always-approve",
        ] {
            assert_eq!(
                argv.iter()
                    .filter(|arg| arg.as_os_str() == OsStr::new(flag))
                    .count(),
                1
            );
        }
        assert!(argv
            .windows(2)
            .any(|args| args[0] == OsStr::new("--sandbox") && args[1] == OsStr::new("strict")));
        let prefix = serde_json::to_string(&binding.append.command_prefix()?)?;
        assert!(String::from_utf8(prompt)?.contains(&prefix));
        let SideEffectConfinementProfile::ExternalGrok(grok) = mounted.as_ref().unwrap() else {
            unreachable!()
        };
        assert!(grok
            .visible_read_only_files()
            .contains(&binding.append.helper_path));
        assert!(grok.visible_read_only_files().contains(&target.prompt));
        assert!(grok.visible_read_write_roots().is_empty());
        assert_eq!(
            grok.visible_read_write_files(),
            &[controls.exact_writable_artifact_files[0].path.clone()]
        );
        let entry = crate::supervise::WorkerExecutionJournalEntry {
            command: vec!["apply_patch".into(), "*** Begin Patch\n*** Update File: src/a.py\n-old\n+print(\"a\\\\b\")\n*** End Patch".into()],
            cwd: spec.cwd.clone(),
            start_timestamp: "2026-09-30T00:00:00Z".into(),
            end_timestamp: "2026-09-30T00:00:01Z".into(),
            changed_paths: vec![PathBuf::from("src/a.py")],
        };
        crate::supervise::append_precreated_worker_execution_journal(
            &binding.append.journal.path,
            &crate::safe_state::FileIdentity {
                device: binding.append.journal.identity.device,
                file: binding.append.journal.identity.inode,
            },
            &entry,
        )?;
        let decoded: crate::supervise::WorkerExecutionJournalEntry =
            serde_json::from_slice(&fs::read(&binding.append.journal.path)?)?;
        assert_eq!(decoded.command, entry.command);
        assert_eq!(decoded.changed_paths, entry.changed_paths);
        binding.revalidate(&spec, &target, &argv, mounted.as_ref().unwrap())?;
        let staging_path = staging.root_path().to_path_buf();
        assert!(matches!(
            staging.cleanup()?,
            ExternalOutputCleanup::Bypassed(_)
        ));
        assert!(!staging_path.exists());
        Ok(())
    }

    #[test]
    fn grok_journal_binding_refuses_account_argv_profile_and_target_substitution() -> Result<()> {
        let (temp, spec, controls, mut staging) = fixture()?;
        let mut target = spec.clone();
        let mut prompt = fs::read(&spec.prompt)?;
        let mut mounted = profile(&spec, &controls)?;
        let mut argv = runtime_adapter_argv(&spec)?;
        let mut binding = prepare_grok_worker_journal_launch(
            &spec,
            &mut target,
            &controls,
            &mut prompt,
            &mut mounted,
            &mut argv,
            &mut staging,
        )?
        .unwrap();
        let _credentials = seal_profile(temp.path(), &mut binding, &mut mounted)?;
        for field in ["account", "timeout", "grant", "prompt", "model"] {
            let mut changed = spec.clone();
            match field {
                "account" => {
                    changed
                        .grok_run_account_binding
                        .as_mut()
                        .unwrap()
                        .selection_revision += 1
                }
                "timeout" => changed.timeout += Duration::from_secs(1),
                "grant" => changed.assignment_process_launch_attempt = Some(2),
                "prompt" => changed.prompt = target.prompt.clone(),
                "model" => changed.model = Some("grok-4.6".into()),
                _ => unreachable!(),
            }
            assert!(
                binding
                    .revalidate(&changed, &target, &argv, mounted.as_ref().unwrap())
                    .is_err(),
                "{field}"
            );
        }
        let mut changed_argv = argv.clone();
        changed_argv.push("--no-subagents".into());
        assert!(binding
            .revalidate(&spec, &target, &changed_argv, mounted.as_ref().unwrap())
            .is_err());
        let mut changed_target = target.clone();
        changed_target.prompt = spec.prompt.clone();
        assert!(binding
            .revalidate(&spec, &changed_target, &argv, mounted.as_ref().unwrap())
            .is_err());
        let wrong_profile =
            SideEffectConfinementProfile::ExternalGrok(ExternalGrokProfile::read_write(&spec.cwd));
        assert!(binding
            .revalidate(&spec, &target, &argv, &wrong_profile)
            .is_err());
        let run = &spec.agent_lifecycle.as_ref().unwrap().run_id;
        crate::account_authority::admit_grok_run_account_binding(run, None);
        assert!(binding
            .revalidate(&spec, &target, &argv, mounted.as_ref().unwrap())
            .is_err());
        Ok(())
    }

    #[test]
    fn grok_journal_binding_refuses_source_and_effective_prompt_changes() -> Result<()> {
        for leaf in [
            "source",
            "effective",
            "effective-replaced",
            "effective-symlink",
        ] {
            let (temp, spec, controls, mut staging) = fixture()?;
            let mut target = spec.clone();
            let mut prompt = fs::read(&spec.prompt)?;
            let mut mounted = profile(&spec, &controls)?;
            let mut argv = runtime_adapter_argv(&spec)?;
            let mut binding = prepare_grok_worker_journal_launch(
                &spec,
                &mut target,
                &controls,
                &mut prompt,
                &mut mounted,
                &mut argv,
                &mut staging,
            )?
            .unwrap();
            let _credentials = seal_profile(temp.path(), &mut binding, &mut mounted)?;
            match leaf {
                "source" => fs::write(&spec.prompt, b"different source bytes")?,
                "effective" => fs::write(&target.prompt, b"missing bound appendix")?,
                "effective-replaced" => {
                    fs::rename(&target.prompt, target.prompt.with_extension("held"))?;
                    fs::write(&target.prompt, &prompt)?;
                    fs::set_permissions(&target.prompt, fs::Permissions::from_mode(0o600))?;
                }
                "effective-symlink" => {
                    fs::rename(&target.prompt, target.prompt.with_extension("held"))?;
                    std::os::unix::fs::symlink(&spec.prompt, &target.prompt)?;
                }
                _ => unreachable!(),
            }
            assert!(
                binding
                    .revalidate(&spec, &target, &argv, mounted.as_ref().unwrap())
                    .is_err(),
                "{leaf}"
            );
        }
        Ok(())
    }

    #[test]
    fn grok_journal_binding_refuses_helper_and_journal_identity_substitution() -> Result<()> {
        for leaf in [
            "helper",
            "journal-replaced",
            "journal-missing",
            "journal-symlink",
        ] {
            let (temp, spec, controls, mut staging) = fixture()?;
            let mut target = spec.clone();
            let mut prompt = fs::read(&spec.prompt)?;
            let mut mounted = profile(&spec, &controls)?;
            let mut argv = runtime_adapter_argv(&spec)?;
            let mut binding = prepare_grok_worker_journal_launch(
                &spec,
                &mut target,
                &controls,
                &mut prompt,
                &mut mounted,
                &mut argv,
                &mut staging,
            )?
            .unwrap();
            let _credentials = seal_profile(temp.path(), &mut binding, &mut mounted)?;
            let path = &binding.append.journal.path;
            match leaf {
                "helper" => binding.append.helper_sha256 = "0".repeat(64),
                "journal-replaced" => {
                    fs::rename(path, path.with_extension("held"))?;
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                }
                "journal-missing" => {
                    fs::rename(path, path.with_extension("held"))?;
                }
                "journal-symlink" => {
                    fs::rename(path, path.with_extension("held"))?;
                    std::os::unix::fs::symlink(&spec.prompt, path)?;
                }
                _ => unreachable!(),
            }
            assert!(
                binding
                    .revalidate(&spec, &target, &argv, mounted.as_ref().unwrap())
                    .is_err(),
                "{leaf}"
            );
        }
        Ok(())
    }

    #[test]
    fn grok_journal_production_caller_preserves_inactive_shapes_and_refuses_unqualified_workers(
    ) -> Result<()> {
        let (_temp, spec, controls, mut staging) = fixture()?;
        for shape in ["readonly", "primary", "auditor", "no-journal"] {
            let mut changed = spec.clone();
            match shape {
                "readonly" => changed.workspace_access = WorkspaceAccess::ReadOnly,
                "primary" => changed.writable_launch_target = WritableLaunchTarget::PrimaryWorktree,
                "auditor" => changed.agent_lifecycle.as_mut().unwrap().role = "auditor".into(),
                "no-journal" => changed.worker_journal_artifacts.clear(),
                _ => unreachable!(),
            }
            let mut target = changed.clone();
            let mut prompt = fs::read(&spec.prompt)?;
            let mut mounted = profile(&spec, &controls)?;
            let original_profile = mounted.clone();
            let mut argv = runtime_adapter_argv(&spec)?;
            let original_argv = argv.clone();
            assert!(prepare_grok_worker_journal_launch(
                &changed,
                &mut target,
                &controls,
                &mut prompt,
                &mut mounted,
                &mut argv,
                &mut staging,
            )?
            .is_none());
            assert_eq!(prompt, fs::read(&spec.prompt)?);
            assert_eq!(argv, original_argv);
            assert_eq!(mounted, original_profile);
        }
        for shape in ["proof", "grant", "lower", "acp", "argv"] {
            let mut changed = spec.clone();
            match shape {
                "proof" => changed.worktree_writable_confinement = None,
                "grant" => changed.assignment_process_launch_grant = None,
                "lower" => changed.reasoning_effort = Some("high".into()),
                "acp" => {
                    changed
                        .runtime_adapter
                        .as_mut()
                        .unwrap()
                        .grok_interaction_protocol =
                        crate::runtime_adapter::GrokInteractionProtocol::AcpStdio
                }
                "argv" => (),
                _ => unreachable!(),
            }
            let mut target = changed.clone();
            let mut prompt = fs::read(&spec.prompt)?;
            let mut mounted = profile(&spec, &controls)?;
            let mut argv = runtime_adapter_argv(&spec)?;
            if shape == "argv" {
                argv.push("--always-approve".into());
            }
            assert!(
                prepare_grok_worker_journal_launch(
                    &changed,
                    &mut target,
                    &controls,
                    &mut prompt,
                    &mut mounted,
                    &mut argv,
                    &mut staging,
                )
                .is_err(),
                "{shape}"
            );
            assert_eq!(prompt, fs::read(&spec.prompt)?);
        }
        Ok(())
    }

    #[test]
    fn grok_journal_custody_failure_retains_private_four_bucket_usage_floor() -> Result<()> {
        let (_temp, spec, _controls, _staging) = nested_fixture()?;
        let mut report = refused_external_run_before_launch(&spec, "fixture".into());
        let capture = CapturedBytes::from_bytes_for_test(
            b"{\"type\":\"end\",\"stopReason\":\"stop\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":12,\"output_tokens\":5,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":3,\"total_tokens\":24}}\n".to_vec(),
        );
        report.retain_grok_native_usage_for_test(&spec, &capture, true);
        let (before, complete) = report.authenticated_grok_usage(&spec).unwrap();
        assert!(complete);
        assert_eq!(before.total_tokens, 24);
        record_grok_journal_custody_failure(
            &mut report,
            &anyhow::anyhow!("effective prompt changed"),
        );
        let (after, complete) = report.authenticated_grok_usage(&spec).unwrap();
        assert_eq!(after.input_tokens, 19);
        assert_eq!(after.output_tokens, 5);
        assert_eq!(after.total_tokens, before.total_tokens);
        assert!(!complete);
        assert!(!report.publishable);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("effective prompt changed"));
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn worker_journal_appender_sha256(file: &fs::File) -> Result<String> {
    use std::os::unix::fs::FileExt;
    // The only production input is the kernel-selected running MACO image,
    // never a caller-selected file. This one-shot read uses temporary memory
    // proportional to its exact bytes; it is not a streaming digest.
    let length = file.metadata()?.len();
    if length == 0 {
        bail!("current MACO journal appender image is empty");
    }
    let mut bytes = vec![0_u8; usize::try_from(length)?];
    file.read_exact_at(&mut bytes, 0)?;
    if !bytes.starts_with(b"\x7fELF") {
        bail!("current MACO journal appender must be the running native executable");
    }
    Ok(sha256_hex(&bytes))
}

#[cfg(target_os = "linux")]
fn bind_worker_journal_append_operation(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    runtime: ExternalExecutionRuntime,
    trust: ExternalProgramTrust,
    prompt: &mut Vec<u8>,
    profile: &mut Option<SideEffectConfinementProfile>,
    argv: &mut [OsString],
) -> Result<Option<BoundWorkerJournalAppend>> {
    // No new route, program selection, delegation, or workspace authority.
    let codex = trust == ExternalProgramTrust::TrustedSystemCodex
        && spec.invocation == ExternalAgentInvocation::CodexSupervisor;
    let grok = spec.invocation == ExternalAgentInvocation::Grok;
    if runtime != ExternalExecutionRuntime::Verified
        || (!codex && !grok)
        || spec.workspace_access != WorkspaceAccess::ReadWrite
        || spec.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree
        || spec
            .agent_lifecycle
            .as_ref()
            .is_none_or(|id| id.role != "worker")
        || spec.worker_journal_artifacts.is_empty()
    {
        return Ok(None);
    }
    refuse_assignment_process_launch_before_preflight(spec)?;
    if spec.assignment_process_launch_kind != Some(AssignmentProcessLaunchKind::AssignmentChild)
        || spec.codex_managed_readonly_route_active()
        || spec.worker_journal_artifacts.len() != 1
        || controls.exact_writable_artifact_files.len() != 1
    {
        bail!("worker journal appender requires the exact journal-bound assignment child");
    }
    let identity = spec
        .agent_lifecycle
        .as_ref()
        .context("worker lifecycle identity missing")?;
    let declared = &spec.worker_journal_artifacts[0];
    let journal = &controls.exact_writable_artifact_files[0];
    if identity.task_id != declared.worker_id
        || journal.worker_id != declared.worker_id
        || journal.path != declared.path
        || journal.path
            != declared
                .incoming_root
                .join("worker-journals")
                .join(format!("{}.jsonl", identity.task_id))
    {
        bail!("worker journal appender subject/path differs from the held launch contract");
    }
    let codex_rule = if codex {
        if !matches!(
            profile,
            Some(SideEffectConfinementProfile::ExternalCodex(_))
        ) {
            bail!("worker journal appender requires the existing ExternalCodex containment");
        }
        for feature in ["multi_agent", "goals"] {
            if !argv
                .windows(2)
                .any(|pair| pair[0] == OsStr::new("--disable") && pair[1] == OsStr::new(feature))
                || argv
                    .windows(2)
                    .any(|pair| pair[0] == OsStr::new("--enable") && pair[1] == OsStr::new(feature))
            {
                bail!("worker journal appender requires native delegation to remain disabled");
            }
        }
        let original_permissions = OsString::from(codex_filesystem_permissions(spec, controls));
        let positions = argv
            .iter()
            .enumerate()
            .filter_map(|(index, argument)| (argument == &original_permissions).then_some(index))
            .collect::<Vec<_>>();
        if positions.len() != 1 || positions[0] == 0 || argv[positions[0] - 1] != OsStr::new("-c") {
            bail!("worker journal appender requires the exact existing inner filesystem rule");
        }
        Some(positions[0])
    } else {
        spec.verified_writable_capabilities(RuntimeId::Grok)?;
        spec.verify_grok_run_account_binding(&identity.run_id)?;
        if !matches!(profile, Some(SideEffectConfinementProfile::ExternalGrok(_)))
            || grok_acp_stdio_protocol_selected(spec)
            || &*argv != runtime_adapter_argv(spec)?.as_slice()
        {
            bail!("Grok worker journal appender requires the exact qualified native argv/profile");
        }
        None
    };
    let helper_path = env::current_exe().context("current MACO executable is unavailable")?;
    let helper_path = normalized_absolute_path(&helper_path, "current MACO journal appender")?;
    // Read only the kernel-selected running image, never a caller-supplied program.
    let helper_file = fs::File::open("/proc/self/exe")?;
    let helper_identity = external_program_identity(&helper_path)?;
    let helper_sha256 = worker_journal_appender_sha256(&helper_file)?;
    let binding = BoundWorkerJournalAppend {
        helper_path,
        helper_file,
        helper_identity,
        helper_sha256,
        journal: journal.clone(),
        source_prompt_sha256: sha256_hex(prompt),
    };
    binding.revalidate()?;
    let hidden_roots = spec
        .hidden_roots
        .iter()
        .map(|path| normalized_absolute_path(path, "hidden root"))
        .collect::<Result<Vec<_>>>()?;
    let overlaps = |path: &Path| {
        binding.helper_path.starts_with(path) || path.starts_with(&binding.helper_path)
    };
    if overlaps(&spec.cwd)
        || overlaps(&declared.incoming_root)
        || hidden_roots.iter().any(|path| overlaps(path))
        || controls.iter().any(|control| overlaps(&control.absolute))
        || controls.managed_git.as_ref().is_some_and(|git| {
            std::iter::once(&git.worktree_git_dir)
                .chain(&git.common_read_only_roots)
                .chain(&git.common_read_only_files)
                .any(|path| overlaps(path))
        })
    {
        bail!("worker journal appender overlaps a workspace, private, or protected path");
    }
    let prefix = serde_json::to_string(&binding.command_prefix()?)?;
    let appendix = format!(
        "\n\nParent-bound Worker journal append operation:\n- Exact argv prefix (JSON array, not a shell command): {prefix}\n- Current MACO executable SHA-256: {}\n- Invoke this exact executable/prefix; append --cwd, --start-timestamp, --end-timestamp, repeated --changed-path, then -- and the original command argv. Preserve the entire apply_patch payload as one argument. Use argument passing, never hand-escaped JSON/printf/echo. No PATH, identity discovery, replacement, truncation, or alternative appender. If this operation fails, stop and report WorkerExecutionJournalRecordError; do not execute the action or repair the journal. The appender is record transport, not an action to recursively journal. Its arguments confer no launch, claim, or evidence authority.\n",
        binding.helper_sha256,
    );
    if prompt
        .len()
        .checked_add(appendix.len())
        .filter(|len| *len <= MAX_PROMPT_BYTES)
        .is_none()
    {
        bail!("worker journal append operation exceeds the existing prompt byte limit");
    }
    *profile = Some(match profile.as_ref() {
        Some(SideEffectConfinementProfile::ExternalCodex(codex_profile)) => {
            // Preserve Codex's exact :minimal inner rule as well as the outer mount.
            let mut inner_controls = controls.clone();
            inner_controls
                .exact_read_only_input_files
                .push(binding.helper_path.clone());
            argv[codex_rule.context("Codex inner rule missing")?] =
                OsString::from(codex_filesystem_permissions(spec, &inner_controls));
            SideEffectConfinementProfile::ExternalCodex(
                codex_profile
                    .clone()
                    .with_visible_read_only_file(&binding.helper_path),
            )
        }
        Some(SideEffectConfinementProfile::ExternalGrok(grok_profile)) if grok => {
            // Grok's fixed strict native sandbox stays unchanged. Only this exact
            // running image is exposed; no sibling executable or directory grant.
            SideEffectConfinementProfile::ExternalGrok(
                grok_profile
                    .clone()
                    .with_visible_read_only_file(&binding.helper_path),
            )
        }
        _ => bail!("worker journal appender profile changed during binding"),
    });
    prompt.extend_from_slice(appendix.as_bytes());
    Ok(Some(binding))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundClaudeManagedLaunch {
    auth_mode: ClaudeAuthMode,
    adapter_config: RuntimeAdapterConfig,
    selected_launch: WritableRuntimeSelectionEvidence,
    confinement: WorktreeWritableConfinementProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundClaudeReservationBinding {
    reservation_id: u64,
    live_token_grant: Option<crate::supervise_budget::LiveTokenGrant>,
    invocation: ExternalAgentInvocation,
    program: PathBuf,
    cwd: PathBuf,
    prompt: PathBuf,
    model: Option<String>,
    effort: Option<String>,
    timeout: Duration,
    workspace_access: WorkspaceAccess,
    launch_target: WritableLaunchTarget,
    lifecycle: Option<ExternalAgentLifecycleIdentity>,
    source_inputs: Vec<researcher_inputs::ResearcherSourceInput>,
    input_files: Vec<PathBuf>,
    claude_managed_launch: BoundClaudeManagedLaunch,
}

impl ExternalAgentCommand {
    pub(crate) fn uses_live_app_server_budget(&self) -> bool {
        should_use_read_only_terminal_app_server(self, ExternalExecutionRuntime::Verified)
            || managed_worker_app_server_shape(self, ExternalExecutionRuntime::Verified)
            || should_use_duplex_review(self, ExternalExecutionRuntime::Verified, true)
    }

    pub(crate) fn uses_live_claude_managed_worker_budget(&self) -> bool {
        self.invocation == ExternalAgentInvocation::ClaudeCode
            && self.workspace_access == WorkspaceAccess::ReadWrite
            && self.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree
    }

    pub(crate) fn uses_gemini_bridge(&self) -> bool {
        self.invocation == ExternalAgentInvocation::GeminiCli
    }

    pub(crate) fn bind_live_token_grant(
        &mut self,
        grant: Option<crate::supervise_budget::LiveTokenGrant>,
    ) {
        self.live_token_grant = grant.map(|grant| BoundLiveTokenGrant {
            grant,
            invocation: self.invocation,
            program: self.program.clone(),
            cwd: self.cwd.clone(),
            prompt: self.prompt.clone(),
            model: self.model.clone(),
            model_provider: self.model_provider.clone(),
            effort: self.reasoning_effort.clone(),
            timeout: self.timeout,
            workspace_access: self.workspace_access,
            launch_target: self.writable_launch_target,
            lifecycle: self.agent_lifecycle.clone(),
            source_inputs: self.researcher_source_inputs.clone(),
            input_files: self.read_only_input_files.clone(),
            confinement: WorktreeConfinementSnapshot::from_command(self, true),
            native_delegation_disabled: self.codex_native_delegation_disabled,
            managed_readonly_route: self.codex_managed_readonly_route,
            process_kind: self.assignment_process_launch_kind,
            process_attempt: self.assignment_process_launch_attempt,
            process_duty: self.assignment_process_launch_duty.clone(),
        });
    }

    pub(crate) fn bind_claude_managed_reservation(
        &mut self,
        reservation_id: u64,
        live_token_grant: Option<crate::supervise_budget::LiveTokenGrant>,
    ) -> Result<(), String> {
        if !self.uses_live_claude_managed_worker_budget() {
            return Err("Claude reservation binding was requested for a different launch".into());
        }
        let config = self
            .runtime_adapter
            .clone()
            .ok_or_else(|| "Claude managed-Worker adapter binding is missing".to_string())?;
        let contract = config
            .claude_managed_launch_contract(&LaunchContext {
                prompt: &self.prompt,
                model: self.model.as_deref(),
                effort: self.reasoning_effort.as_deref(),
                cwd: &self.cwd,
                output: &self.output_last_message,
            })
            .ok_or_else(|| "Claude managed-Worker native launch contract is invalid".to_string())?;
        if self.claude_run_account_binding.is_none() {
            return Err(
                "Claude managed-Worker OAuth launch has no frozen selected CAM account binding"
                    .to_string(),
            );
        }
        let selected_launch = self
            .writable_runtime_selection
            .clone()
            .ok_or_else(|| "Claude managed-Worker selection binding is missing".to_string())?;
        let confinement = self
            .worktree_writable_confinement
            .clone()
            .ok_or_else(|| "Claude managed-Worker confinement binding is missing".to_string())?;
        self.claude_reservation_binding = Some(BoundClaudeReservationBinding {
            reservation_id,
            live_token_grant,
            invocation: self.invocation,
            program: self.program.clone(),
            cwd: self.cwd.clone(),
            prompt: self.prompt.clone(),
            model: self.model.clone(),
            effort: self.reasoning_effort.clone(),
            timeout: self.timeout,
            workspace_access: self.workspace_access,
            launch_target: self.writable_launch_target,
            lifecycle: self.agent_lifecycle.clone(),
            source_inputs: self.researcher_source_inputs.clone(),
            input_files: self.read_only_input_files.clone(),
            claude_managed_launch: BoundClaudeManagedLaunch {
                auth_mode: match contract.auth_mode() {
                    ClaudeAuthMode::BareApiKey => ClaudeAuthMode::ManagedOAuth,
                    ClaudeAuthMode::ManagedOAuth => ClaudeAuthMode::ManagedOAuth,
                },
                adapter_config: config,
                selected_launch,
                confinement,
            },
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn live_token_grant_for_test(
        &self,
    ) -> Option<&crate::supervise_budget::LiveTokenGrant> {
        self.verified_live_token_grant()
            .expect("valid launch grant")
    }

    fn verified_live_token_grant(
        &self,
    ) -> Result<Option<&crate::supervise_budget::LiveTokenGrant>, String> {
        let grant = self.bound_live_token_grant()?;
        if grant.is_some_and(|grant| grant.stopped()) {
            return Err("live token grant was stopped or released".to_string());
        }
        Ok(grant)
    }

    // Post-quiescence evidence can compare the original launch binding after
    // settlement. This does not authorize another physical request/release.
    fn bound_live_token_grant(
        &self,
    ) -> Result<Option<&crate::supervise_budget::LiveTokenGrant>, String> {
        let Some(bound) = &self.live_token_grant else {
            return Ok(None);
        };
        if bound.invocation != self.invocation
            || bound.program != self.program
            || bound.cwd != self.cwd
            || bound.prompt != self.prompt
            || bound.model != self.model
            || bound.model_provider != self.model_provider
            || bound.effort != self.reasoning_effort
            || bound.timeout != self.timeout
            || bound.workspace_access != self.workspace_access
            || bound.launch_target != self.writable_launch_target
            || bound.lifecycle != self.agent_lifecycle
            || bound.source_inputs != self.researcher_source_inputs
            || bound.input_files != self.read_only_input_files
            || !bound.confinement.matches_command(self, true)
            || bound.native_delegation_disabled != self.codex_native_delegation_disabled
            || bound.managed_readonly_route != self.codex_managed_readonly_route
            || bound.process_kind != self.assignment_process_launch_kind
            || bound.process_attempt != self.assignment_process_launch_attempt
            || bound.process_duty != self.assignment_process_launch_duty
        {
            return Err("live token grant launch binding changed".to_string());
        }
        Ok(Some(&bound.grant))
    }

    fn verified_claude_managed_reservation(
        &self,
    ) -> Result<Option<&crate::supervise_budget::LiveTokenGrant>, String> {
        if !self.uses_live_claude_managed_worker_budget() {
            return Ok(None);
        }
        let bound = self.claude_reservation_binding.as_ref().ok_or_else(|| {
            "Claude managed-Worker reservation identity binding is missing".to_string()
        })?;
        if bound.reservation_id == 0
            || bound.invocation != self.invocation
            || bound.program != self.program
            || bound.cwd != self.cwd
            || bound.prompt != self.prompt
            || bound.model != self.model
            || bound.effort != self.reasoning_effort
            || bound.timeout != self.timeout
            || bound.workspace_access != self.workspace_access
            || bound.launch_target != self.writable_launch_target
            || bound.lifecycle != self.agent_lifecycle
            || bound.source_inputs != self.researcher_source_inputs
            || bound.input_files != self.read_only_input_files
        {
            return Err(
                "Claude managed-Worker reservation/deadline launch binding changed".to_string(),
            );
        }
        let held = &bound.claude_managed_launch;
        let config = self
            .runtime_adapter
            .as_ref()
            .ok_or_else(|| "Claude managed-Worker adapter binding disappeared".to_string())?;
        let contract = config
            .claude_managed_launch_contract(&LaunchContext {
                prompt: &self.prompt,
                model: self.model.as_deref(),
                effort: self.reasoning_effort.as_deref(),
                cwd: &self.cwd,
                output: &self.output_last_message,
            })
            .ok_or_else(|| "Claude managed-Worker native launch contract changed".to_string())?;
        let expected_auth_mode = match contract.auth_mode() {
            ClaudeAuthMode::BareApiKey if self.claude_run_account_binding.is_some() => {
                ClaudeAuthMode::ManagedOAuth
            }
            mode => mode,
        };
        if held.auth_mode != expected_auth_mode
            || &held.adapter_config != config
            || self.writable_runtime_selection.as_ref() != Some(&held.selected_launch)
            || self.worktree_writable_confinement.as_ref() != Some(&held.confinement)
        {
            return Err(
                "Claude managed-Worker claim/auth/reservation/deadline binding changed".to_string(),
            );
        }
        if bound
            .live_token_grant
            .as_ref()
            .is_some_and(crate::supervise_budget::LiveTokenGrant::stopped)
        {
            return Err("Claude managed-Worker live token grant was stopped or released".into());
        }
        Ok(bound.live_token_grant.as_ref())
    }

    fn claude_managed_binding(&self) -> Result<(u64, ClaudeAuthMode), String> {
        self.verified_claude_managed_reservation()?;
        let bound = self.claude_reservation_binding.as_ref().ok_or_else(|| {
            "Claude managed-Worker reservation identity binding is missing".to_string()
        })?;
        Ok((bound.reservation_id, bound.claude_managed_launch.auth_mode))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod worker_journal_append_binding_tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    pub(super) fn fixture() -> (
        tempfile::TempDir,
        ExternalAgentCommand,
        ProtectedWorktreeControls,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let incoming = root.join("incoming");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir_all(incoming.join("worker-journals")).unwrap();
        let path = incoming.join("worker-journals/worker.jsonl");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let identity = exact_writable_artifact_identity(&file.metadata().unwrap()).unwrap();
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            "run",
            "worker",
            1,
            Path::new("codex"),
            None,
            "worker-duty",
        )
        .unwrap();
        let spec = ExternalAgentCommand::codex(
            "codex",
            &workspace,
            root.join("prompt.md"),
            root.join("events.jsonl"),
            incoming.join("report.json"),
            Duration::from_secs(30),
        )
        .with_agent_lifecycle(&root, "worker", "run", "worker")
        .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant)
        .with_worker_journal_artifact("worker", &incoming, &path);
        let controls = ProtectedWorktreeControls {
            exact_writable_artifact_files: vec![ExactWritableArtifactFile {
                worker_id: "worker".to_string(),
                path,
                held_file: std::sync::Arc::new(file),
                identity,
            }],
            writable_artifact_root: Some(incoming),
            ..ProtectedWorktreeControls::default()
        };
        (temp, spec, controls)
    }

    pub(super) fn profile(spec: &ExternalAgentCommand) -> Option<SideEffectConfinementProfile> {
        Some(SideEffectConfinementProfile::ExternalCodex(
            ExternalCodexProfile::read_write(&spec.cwd)
                .with_hidden_root(spec.cwd.join(".maco"))
                .with_visible_read_only_file(spec.cwd.join(".gitignore")),
        ))
    }

    #[test]
    fn worker_append_production_binding_preserves_native_flags_and_mounts_only_current_executable()
    {
        let (_temp, spec, controls) = fixture();
        let original_profile = profile(&spec);
        let mut mounted = original_profile.clone();
        let mut prompt = b"original prompt".to_vec();
        let original_argv = codex_supervisor_argv(&spec, &controls, None);
        let mut argv = original_argv.clone();
        let original_digest = argv_digest(&argv).unwrap();
        let binding = bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .unwrap()
        .unwrap();
        assert_eq!(binding.helper_path, env::current_exe().unwrap());
        assert_eq!(
            binding.helper_sha256,
            sha256_hex(&fs::read(&binding.helper_path).unwrap())
        );
        let prefix = binding.command_prefix().unwrap();
        assert_eq!(
            prefix,
            vec![
                binding.helper_path.to_str().unwrap().to_string(),
                "supervise".to_string(),
                "journal-append".to_string(),
                "--journal".to_string(),
                controls.exact_writable_artifact_files[0]
                    .path
                    .to_str()
                    .unwrap()
                    .to_string(),
                "--device".to_string(),
                controls.exact_writable_artifact_files[0]
                    .identity
                    .device
                    .to_string(),
                "--inode".to_string(),
                controls.exact_writable_artifact_files[0]
                    .identity
                    .inode
                    .to_string(),
            ]
        );
        let Some(SideEffectConfinementProfile::ExternalCodex(original)) = original_profile else {
            panic!("Codex profile expected");
        };
        assert_eq!(
            mounted,
            Some(SideEffectConfinementProfile::ExternalCodex(
                original.with_visible_read_only_file(&binding.helper_path),
            ))
        );
        let before_permissions = OsString::from(codex_filesystem_permissions(&spec, &controls));
        let mut expected_controls = controls.clone();
        expected_controls
            .exact_read_only_input_files
            .push(binding.helper_path.clone());
        let after_permissions =
            OsString::from(codex_filesystem_permissions(&spec, &expected_controls));
        for (before, after) in original_argv.iter().zip(&argv) {
            assert_eq!(
                after,
                if before == &before_permissions {
                    &after_permissions
                } else {
                    before
                }
            );
        }
        assert_eq!(argv.len(), original_argv.len());
        assert_ne!(argv_digest(&argv).unwrap(), original_digest);
        assert!(after_permissions.to_str().unwrap().contains(&format!(
            "{}=\"read\"",
            toml_basic_string(binding.helper_path.to_str().unwrap())
        )));
        let prompt = std::str::from_utf8(&prompt).unwrap();
        assert!(prompt.starts_with("original prompt"));
        assert!(prompt.contains(&serde_json::to_string(&prefix).unwrap()));
        assert!(prompt.contains(&binding.helper_sha256));
        assert!(controls.exact_read_only_input_files.is_empty());
        binding.revalidate().unwrap();
        assert!(fs::read(&binding.journal.path).unwrap().is_empty());
    }

    #[test]
    fn worker_append_binding_refuses_changed_identity_flags_and_profile_without_side_effects() {
        let (_temp, mut spec, mut controls) = fixture();
        let mut prompt = b"original".to_vec();
        let mut mounted = profile(&spec);
        let original_profile = mounted.clone();
        let mut argv = codex_supervisor_argv(&spec, &controls, None);
        let original_argv = argv.clone();
        spec.worker_journal_artifacts[0].worker_id = "foreign".to_string();
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        spec.worker_journal_artifacts[0].worker_id = "worker".to_string();
        let flag = argv
            .windows(2)
            .position(|pair| pair[1] == OsStr::new("multi_agent"))
            .unwrap();
        argv[flag] = OsString::from("--enable");
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        argv = original_argv.clone();
        argv.push(OsString::from("--enable"));
        argv.push(OsString::from("goals"));
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        argv = original_argv.clone();
        let permissions = OsString::from(codex_filesystem_permissions(&spec, &controls));
        let rule = argv
            .iter()
            .position(|argument| argument == &permissions)
            .unwrap();
        argv[rule] = OsString::from("permissions.maco_external_codex.filesystem={}");
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        argv = original_argv.clone();
        argv[rule - 1] = OsString::from("--model");
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        argv = original_argv.clone();
        mounted = None;
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        mounted = original_profile.clone();
        let artifact = controls.exact_writable_artifact_files.remove(0);
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .is_err());
        controls.exact_writable_artifact_files.push(artifact);
        assert_eq!(prompt.as_slice(), b"original");
        assert_eq!(mounted, original_profile);
        assert_eq!(argv, original_argv);
        spec.hidden_roots
            .push(env::current_exe().unwrap().parent().unwrap().to_path_buf());
        assert!(bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .err()
        .expect("hidden helper must be refused")
        .to_string()
        .contains("private, or protected path"));
        spec.hidden_roots.clear();
        assert_eq!(prompt.as_slice(), b"original");
        assert_eq!(mounted, original_profile);
        assert_eq!(argv, original_argv);
        let mut binding = bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::TrustedSystemCodex,
            &mut prompt,
            &mut mounted,
            &mut argv,
        )
        .unwrap()
        .unwrap();
        let digest = binding.helper_sha256.clone();
        binding.helper_sha256 = "0".repeat(64);
        assert!(binding.revalidate().is_err());
        binding.helper_sha256 = digest;
        fs::rename(
            &binding.journal.path,
            binding.journal.path.with_extension("original"),
        )
        .unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&binding.journal.path)
            .unwrap();
        assert!(binding
            .revalidate()
            .unwrap_err()
            .to_string()
            .contains("held descriptor/path binding changed"));
    }

    #[test]
    fn worker_append_binding_leaves_other_runtime_role_and_target_shapes_unchanged() {
        let (_temp, spec, controls) = fixture();
        let mut variants = Vec::new();
        let mut other = spec.clone();
        other.invocation = ExternalAgentInvocation::GeminiCli;
        variants.push(other);
        let mut other = spec.clone();
        other.workspace_access = WorkspaceAccess::ReadOnly;
        variants.push(other);
        let mut other = spec.clone();
        other.writable_launch_target = WritableLaunchTarget::PrimaryWorktree;
        variants.push(other);
        let mut other = spec.clone();
        other.agent_lifecycle.as_mut().unwrap().role = "child_orchestrator".to_string();
        variants.push(other);
        let mut other = spec.clone();
        other.worker_journal_artifacts.clear();
        variants.push(other);
        for variant in variants {
            let mut mounted = profile(&variant);
            let original_profile = mounted.clone();
            let mut prompt = b"original".to_vec();
            let mut argv = codex_supervisor_argv(&variant, &controls, None);
            let original_argv = argv.clone();
            assert!(bind_worker_journal_append_operation(
                &variant,
                &controls,
                ExternalExecutionRuntime::Verified,
                ExternalProgramTrust::TrustedSystemCodex,
                &mut prompt,
                &mut mounted,
                &mut argv,
            )
            .unwrap()
            .is_none());
            assert_eq!(prompt.as_slice(), b"original");
            assert_eq!(mounted, original_profile);
            assert_eq!(argv, original_argv);
        }
    }
}

const ASSIGNMENT_MESSAGING_PROTOCOL_PROMPT_APPENDIX: &str = r#"

## Assignment messaging (loopback IPC)

This launch exposes private environment variables MACO_MESSAGE_ENDPOINT and MACO_MESSAGE_TOKEN.
Connect to MACO_MESSAGE_ENDPOINT on loopback only. Send exactly one NDJSON request line per TCP
connection, then read exactly one NDJSON response line.

Request shape:
{"bearer":"<value from MACO_MESSAGE_TOKEN>","request":{"operation":"<name>", ...}}

Response shape:
{"ok":true,"result":<value>} or {"ok":false,"error":"<message>"}

The inner `request` object must not include run_id, task_id, artifact paths, sender identity, or
any attempt to override MACO_MESSAGE_TOKEN or MACO_MESSAGE_ENDPOINT. Supported operations:
send_direct (recipient_id, payload), create_channel (channel_id, members, publishers),
publish_channel (channel_id, payload), receive_next, receive_next_from_channel (channel_id),
acknowledge (message_id). Delivery is at-least-once until acknowledge succeeds; duplicates may
arrive until then.

"#;

pub(crate) fn render_prompt_with_assignment_messaging_protocol_appendix(
    prompt: String,
) -> Result<String> {
    let combined_len = prompt
        .len()
        .saturating_add(ASSIGNMENT_MESSAGING_PROTOCOL_PROMPT_APPENDIX.len());
    if combined_len > MAX_PROMPT_BYTES {
        bail!(
            "assignment messaging protocol appendix would exceed the bounded prompt size ({} bytes)",
            combined_len
        );
    }
    let mut rendered = prompt;
    rendered.push_str(ASSIGNMENT_MESSAGING_PROTOCOL_PROMPT_APPENDIX);
    Ok(rendered)
}

fn prompt_includes_assignment_messaging_protocol_appendix(prompt: &[u8]) -> bool {
    prompt.ends_with(ASSIGNMENT_MESSAGING_PROTOCOL_PROMPT_APPENDIX.as_bytes())
}

const MANAGED_WORKER_REQUEST_TOOL_APPENDIX: &str = r#"

## Managed worker requests (parent dynamic tool)

Verifier acceptance for this appendix is only the exact managed initial parent mode: Codex supervisor, read-only workspace, managed child worktree, native delegation disabled, verified execution, lifecycle role child_orchestrator, and the sealed parent inbox endpoint held by the supervisor. Invoke the dynamic tool named maco_worker_request. Yield only requests that this tool acknowledges. Do not use a shell, socket, or network connection.

Tool arguments contain operation and the fields for that operation. Do not include run_id, task_id, a bearer token, an endpoint, or any path.
- operation submit_worker_request requires request_id and worker_id
- operation worker_request_status requires request_id

"#;

pub(crate) fn render_prompt_with_managed_worker_request_tool_appendix(
    prompt: String,
) -> Result<String> {
    let combined_len = prompt
        .len()
        .saturating_add(MANAGED_WORKER_REQUEST_TOOL_APPENDIX.len());
    if combined_len > MAX_PROMPT_BYTES {
        bail!(
            "managed worker-request tool appendix would exceed the bounded prompt size ({} bytes)",
            combined_len
        );
    }
    let mut rendered = prompt;
    rendered.push_str(MANAGED_WORKER_REQUEST_TOOL_APPENDIX);
    Ok(rendered)
}

fn prompt_includes_managed_worker_request_tool_appendix(prompt: &[u8]) -> bool {
    prompt.ends_with(MANAGED_WORKER_REQUEST_TOOL_APPENDIX.as_bytes())
}

pub(crate) const WRITABLE_GROK_TERMINAL_WORKER_REQUIRED: &str =
    "writable_grok_terminal_worker_required";
pub(crate) const WRITABLE_GROK_SELECTION_EVIDENCE_MISSING: &str =
    "writable_grok_selection_evidence_missing";
pub(crate) const WRITABLE_GROK_SELECTION_EVIDENCE_STALE: &str =
    "writable_grok_selection_evidence_stale";
pub(crate) const WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED: &str =
    "writable_grok_adapter_configuration_unverified";
pub(crate) const WRITABLE_GROK_CONFINEMENT_PROOF_MISSING: &str =
    "writable_grok_confinement_proof_missing";
pub(crate) const WRITABLE_GROK_CONFINEMENT_PROOF_STALE: &str =
    "writable_grok_confinement_proof_stale";
pub(crate) const WRITABLE_GROK_CONFINEMENT_UNVERIFIED: &str =
    "writable_grok_confinement_unverified";
pub(crate) const WRITABLE_CLAUDE_TERMINAL_WORKER_REQUIRED: &str =
    "writable_claude_terminal_worker_required";
pub(crate) const WRITABLE_CLAUDE_SELECTION_EVIDENCE_MISSING: &str =
    "writable_claude_selection_evidence_missing";
pub(crate) const WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE: &str =
    "writable_claude_selection_evidence_stale";
pub(crate) const WRITABLE_CLAUDE_ADAPTER_CONFIGURATION_UNVERIFIED: &str =
    "writable_claude_adapter_configuration_unverified";
pub(crate) const WRITABLE_CLAUDE_CONFINEMENT_PROOF_MISSING: &str =
    "writable_claude_confinement_proof_missing";
pub(crate) const WRITABLE_CLAUDE_CONFINEMENT_PROOF_STALE: &str =
    "writable_claude_confinement_proof_stale";
pub(crate) const WRITABLE_CLAUDE_CONFINEMENT_UNVERIFIED: &str =
    "writable_claude_confinement_unverified";
pub(crate) const WRITABLE_GEMINI_TERMINAL_WORKER_REQUIRED: &str =
    "writable_gemini_terminal_worker_required";
pub(crate) const WRITABLE_GEMINI_SELECTION_EVIDENCE_MISSING: &str =
    "writable_gemini_selection_evidence_missing";
pub(crate) const WRITABLE_GEMINI_SELECTION_EVIDENCE_STALE: &str =
    "writable_gemini_selection_evidence_stale";
pub(crate) const WRITABLE_GEMINI_CONFINEMENT_PROOF_MISSING: &str =
    "writable_gemini_confinement_proof_missing";
pub(crate) const WRITABLE_GEMINI_CONFINEMENT_PROOF_STALE: &str =
    "writable_gemini_confinement_proof_stale";
pub(crate) const WRITABLE_GEMINI_CONFINEMENT_UNVERIFIED: &str =
    "writable_gemini_confinement_unverified";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WritableRuntimeSelectionEvidence {
    assignment_id: String,
    runtime: RuntimeId,
    invocation: ExternalAgentInvocation,
    program: PathBuf,
    cwd: PathBuf,
    workspace_access: WorkspaceAccess,
    writable_launch_target: WritableLaunchTarget,
    model: Option<String>,
    reasoning_effort: Option<String>,
    adapter_config: Option<RuntimeAdapterConfig>,
    output_schema: Option<PathBuf>,
    program_sha256: Option<String>,
}

impl WritableRuntimeSelectionEvidence {
    fn from_command(
        assignment_id: impl Into<String>,
        runtime: RuntimeId,
        command: &ExternalAgentCommand,
    ) -> Result<Self> {
        let program_sha256 = if runtime == RuntimeId::ClaudeCode {
            let (resolved, digest) =
                resolve_claude_native_program_identity(&command.program, &command.cwd)?;
            if !claude::admitted_native_executable(&resolved, &digest) {
                bail!(
                    "{WRITABLE_CLAUDE_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Claude requires admitted native {} executable {} with SHA-256 {}",
                    claude::CLAUDE_NATIVE_VERSION,
                    claude::CLAUDE_NATIVE_EXECUTABLE,
                    claude::CLAUDE_NATIVE_SHA256
                );
            }
            Some(digest)
        } else {
            None
        };
        Ok(Self {
            assignment_id: assignment_id.into(),
            runtime,
            invocation: command.invocation,
            program: command.program.clone(),
            cwd: command.cwd.clone(),
            workspace_access: command.workspace_access,
            writable_launch_target: command.writable_launch_target,
            model: command.model.clone(),
            reasoning_effort: command.reasoning_effort.clone(),
            adapter_config: command.runtime_adapter.clone(),
            output_schema: command.output_schema.clone(),
            program_sha256,
        })
    }

    fn matches_command(&self, command: &ExternalAgentCommand, runtime: RuntimeId) -> bool {
        self.runtime == runtime
            && self.invocation == command.invocation
            && self.program == command.program
            && self.cwd == command.cwd
            && self.workspace_access == command.workspace_access
            && self.writable_launch_target == command.writable_launch_target
            && self.model == command.model
            && self.reasoning_effort == command.reasoning_effort
            && self.adapter_config == command.runtime_adapter
            && self.output_schema == command.output_schema
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeWritableConfinementProof {
    authority: WorktreeWritableConfinementAuthority,
    selected_launch: Option<WritableRuntimeSelectionEvidence>,
    command: WorktreeConfinementSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorktreeWritableConfinementAuthority {
    Direct(WorktreeWritableAdmission),
    Nested(Box<NestedWorktreeWritableAdmission>),
}

/// Private, in-memory evidence for a terminal Worker borrowing its enclosing
/// ChildOrchestrator's held worktree and claim. It is deliberately not serializable:
/// only the live assignment authority can mint it, and the external boundary compares
/// it with the selected launch and finalized command before target release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NestedWorktreeWritableAdmission {
    worker_id: String,
    resource_owner_id: String,
    run_id: String,
    attempt: usize,
    serial_permit_attempt: usize,
    worktree_id: String,
    worktree_path: PathBuf,
    lease_worktree_branch: String,
    claim_owner_id: String,
    claim_token: u64,
    claim_paths: Vec<PathBuf>,
    worker_paths: Vec<PathBuf>,
    semantic_token: Option<u64>,
    native_sandbox: NativeSandboxAdmission,
    worker_journals: Vec<WorkerJournalArtifactSpec>,
}

impl NestedWorktreeWritableAdmission {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_live_assignment_authority(
        worker_id: &str,
        resource_owner_id: &str,
        run_id: &str,
        attempt: usize,
        serial_permit_attempt: usize,
        worktree_id: &str,
        worktree_path: &Path,
        lease_worktree_branch: &str,
        claim_owner_id: &str,
        claim_token: u64,
        claim_paths: &[PathBuf],
        worker_paths: &[PathBuf],
        semantic_token: Option<u64>,
        native_sandbox: NativeSandboxAdmission,
        worker_journals: &[WorkerJournalArtifactSpec],
    ) -> Result<Self> {
        if worker_id.is_empty()
            || resource_owner_id.is_empty()
            || worker_id == resource_owner_id
            || run_id.is_empty()
            || attempt == 0
            || serial_permit_attempt != attempt
            || worktree_id != resource_owner_id
            || worktree_path.as_os_str().is_empty()
            || lease_worktree_branch.is_empty()
            || claim_owner_id != resource_owner_id
            || claim_token == 0
            || claim_paths.is_empty()
            || worker_paths.is_empty()
            || worker_paths.iter().any(|worker_path| {
                !claim_paths
                    .iter()
                    .any(|claim_path| worker_path.starts_with(claim_path))
            })
            || native_sandbox.runtime != RuntimeId::Grok
            || native_sandbox.workspace_access != WorkspaceAccess::ReadWrite
            || native_sandbox.side_effect_confinement != SideEffectConfinement::Verified
            || worker_journals.len() != 1
            || worker_journals[0].worker_id != worker_id
        {
            bail!(
                "{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: nested Grok authority does not bind one terminal Worker to its live parent resources and serial permit"
            );
        }
        Ok(Self {
            worker_id: worker_id.to_owned(),
            resource_owner_id: resource_owner_id.to_owned(),
            run_id: run_id.to_owned(),
            attempt,
            serial_permit_attempt,
            worktree_id: worktree_id.to_owned(),
            worktree_path: worktree_path.to_path_buf(),
            lease_worktree_branch: lease_worktree_branch.to_owned(),
            claim_owner_id: claim_owner_id.to_owned(),
            claim_token,
            claim_paths: claim_paths.to_vec(),
            worker_paths: worker_paths.to_vec(),
            semantic_token,
            native_sandbox,
            worker_journals: worker_journals.to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeConfinementSnapshot {
    invocation: ExternalAgentInvocation,
    program: PathBuf,
    cwd: PathBuf,
    prompt: PathBuf,
    json_log: PathBuf,
    output_last_message: PathBuf,
    output_schema: Option<PathBuf>,
    read_only_input_files: Vec<PathBuf>,
    researcher_source_inputs: Vec<researcher_inputs::ResearcherSourceInput>,
    worker_journal_artifacts: Vec<WorkerJournalArtifactSpec>,
    workspace_access: WorkspaceAccess,
    hidden_roots: Vec<PathBuf>,
    worktree_control_exceptions: Vec<PathBuf>,
    writable_launch_target: WritableLaunchTarget,
    model: Option<String>,
    model_provider: Option<String>,
    reasoning_effort: Option<String>,
    runtime_adapter: Option<RuntimeAdapterConfig>,
    environment_requirements: Vec<EnvironmentRequirement>,
    machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    timeout: Duration,
    agent_lifecycle: Option<ExternalAgentLifecycleIdentity>,
    assignment_process_launch_kind: Option<AssignmentProcessLaunchKind>,
    assignment_process_launch_grant: Option<AssignmentProcessLaunchGrant>,
    assignment_process_launch_attempt: Option<usize>,
    assignment_process_launch_duty: Option<String>,
    assignment_mechanical_executor_duty: Option<SealedMechanicalExecutorDuty>,
    assignment_messaging_launch: Option<AssignmentMessagingLaunch>,
    cam_authority_socket_pin: Option<String>,
    codex_run_account_binding: Option<CodexRunAccountBinding>,
    grok_run_account_binding: Option<FrozenGrokSelectedBinding>,
}

impl WorktreeConfinementSnapshot {
    fn from_command(command: &ExternalAgentCommand, bind_assignment_process_launch: bool) -> Self {
        Self {
            invocation: command.invocation,
            program: command.program.clone(),
            cwd: command.cwd.clone(),
            prompt: command.prompt.clone(),
            json_log: command.json_log.clone(),
            output_last_message: command.output_last_message.clone(),
            output_schema: command.output_schema.clone(),
            read_only_input_files: command.read_only_input_files.clone(),
            researcher_source_inputs: command.researcher_source_inputs.clone(),
            worker_journal_artifacts: command.worker_journal_artifacts.clone(),
            workspace_access: command.workspace_access,
            hidden_roots: command.hidden_roots.clone(),
            worktree_control_exceptions: command.worktree_control_exceptions.clone(),
            writable_launch_target: command.writable_launch_target,
            model: command.model.clone(),
            model_provider: command.model_provider.clone(),
            reasoning_effort: command.reasoning_effort.clone(),
            runtime_adapter: command.runtime_adapter.clone(),
            environment_requirements: command.environment_requirements.clone(),
            machine_global_retention: command.machine_global_retention.clone(),
            timeout: command.timeout,
            agent_lifecycle: command.agent_lifecycle.clone(),
            assignment_process_launch_kind: if bind_assignment_process_launch {
                command.assignment_process_launch_kind
            } else {
                None
            },
            assignment_process_launch_grant: if bind_assignment_process_launch {
                command.assignment_process_launch_grant.clone()
            } else {
                None
            },
            assignment_process_launch_attempt: if bind_assignment_process_launch {
                command.assignment_process_launch_attempt
            } else {
                None
            },
            assignment_process_launch_duty: if bind_assignment_process_launch {
                command.assignment_process_launch_duty.clone()
            } else {
                None
            },
            assignment_mechanical_executor_duty: if bind_assignment_process_launch {
                command.assignment_mechanical_executor_duty
            } else {
                None
            },
            assignment_messaging_launch: command.assignment_messaging_launch.clone(),
            cam_authority_socket_pin: command.cam_authority_socket_pin.clone(),
            codex_run_account_binding: command.codex_run_account_binding.clone(),
            grok_run_account_binding: command.grok_run_account_binding.clone(),
        }
    }

    fn matches_command(
        &self,
        command: &ExternalAgentCommand,
        bind_assignment_process_launch: bool,
    ) -> bool {
        self == &Self::from_command(command, bind_assignment_process_launch)
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
    AnthropicApiKey,
    ClaudeManagedOAuth,
    CodexAccessToken,
    CodexApiKey,
    OpenAiApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentConfiguration {
    CodexAuthFile,
    GrokAuthFile,
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
    VerifiedExternalClaude,
    VerifiedExternalGrok,
    VerifiedExternalCursor,
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

/// Bounded, redacted capture from the fixed `--version` preflight probe. Parent-held only;
/// propagated through private supervisor command records, not child-writable report summaries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFixedVersionProbeStream {
    pub text: String,
    pub truncated: bool,
}

/// Structured diagnostic for a fixed-argv version preflight launch. Separate from main target
/// stdout/stderr and from sanitized public environment-failure summaries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFixedVersionProbeEvidence {
    pub executable: EnvironmentExecutable,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: EnvironmentFixedVersionProbeStream,
    pub stderr: EnvironmentFixedVersionProbeStream,
    pub process_tree: ProcessTreeEvidence,
    pub side_effects: SideEffectConfinementEvidence,
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
            researcher_source_inputs: Vec::new(),
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
            live_token_grant: None,
            claude_reservation_binding: None,
            worktree_writable_confinement: None,
            assignment_process_launch_kind: None,
            assignment_process_launch_grant: None,
            assignment_process_launch_attempt: None,
            assignment_process_launch_duty: None,
            assignment_mechanical_executor_duty: None,
            assignment_messaging_launch: None,
            cam_authority_socket_pin: None,
            codex_run_account_binding: None,
            grok_run_account_binding: None,
            codex_native_delegation_disabled: false,
            read_only_target_executable_pin: None,
            codex_managed_readonly_route: CodexManagedReadonlyRoute::Off,
            selected_merge_arbiter: None,
            claude_run_account_binding: None,
            gemini_run_account_binding: None,
            cursor_run_account_binding: None,
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
            researcher_source_inputs: Vec::new(),
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
            live_token_grant: None,
            claude_reservation_binding: None,
            worktree_writable_confinement: None,
            assignment_process_launch_kind: None,
            assignment_process_launch_grant: None,
            assignment_process_launch_attempt: None,
            assignment_process_launch_duty: None,
            assignment_mechanical_executor_duty: None,
            assignment_messaging_launch: None,
            cam_authority_socket_pin: None,
            codex_run_account_binding: None,
            grok_run_account_binding: None,
            codex_native_delegation_disabled: false,
            read_only_target_executable_pin: None,
            codex_managed_readonly_route: CodexManagedReadonlyRoute::Off,
            selected_merge_arbiter: None,
            claude_run_account_binding: None,
            gemini_run_account_binding: None,
            cursor_run_account_binding: None,
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
            researcher_source_inputs: Vec::new(),
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
            live_token_grant: None,
            claude_reservation_binding: None,
            worktree_writable_confinement: None,
            assignment_process_launch_kind: None,
            assignment_process_launch_grant: None,
            assignment_process_launch_attempt: None,
            assignment_process_launch_duty: None,
            assignment_mechanical_executor_duty: None,
            assignment_messaging_launch: None,
            cam_authority_socket_pin: None,
            codex_run_account_binding: None,
            grok_run_account_binding: None,
            codex_native_delegation_disabled: false,
            read_only_target_executable_pin: None,
            codex_managed_readonly_route: CodexManagedReadonlyRoute::Off,
            selected_merge_arbiter: None,
            claude_run_account_binding: None,
            gemini_run_account_binding: None,
            cursor_run_account_binding: None,
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

    /// Account-selected merge admission only; execution qualification remains independent.
    pub(crate) fn with_selected_merge_arbiter(
        mut self,
        selected: crate::selection::routing_policy::SelectedLaunchRequest,
        decision: crate::selection::SelectionProvenance,
        frozen: crate::selection::routing_policy::FrozenRoutingPolicy,
    ) -> Result<Self> {
        validate_selected_merge_receipt(&selected, &decision, &frozen)?;
        let candidate = selected.candidate();
        let runtime = match self.invocation {
            ExternalAgentInvocation::CodexSupervisor => RuntimeId::Codex,
            ExternalAgentInvocation::Grok => RuntimeId::Grok,
            ExternalAgentInvocation::Cursor => RuntimeId::Cursor,
            ExternalAgentInvocation::ClaudeCode => RuntimeId::ClaudeCode,
            ExternalAgentInvocation::GeminiCli => RuntimeId::GeminiCli,
            _ => bail!("selected merge invocation is not a supervisor runtime"),
        };
        if runtime.as_str() != candidate.runtime
            || self.model.as_deref() != Some(candidate.model.as_str())
            || self.reasoning_effort.as_deref() != Some(candidate.effort.as_str())
            || !merge_arbiter_command_is_merge_shaped(&self)
            || self
                .output_schema
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
            || self.prompt.as_os_str().is_empty()
            || self.json_log.as_os_str().is_empty()
            || self.output_last_message.as_os_str().is_empty()
            || self.cwd.as_os_str().is_empty()
            || self.hidden_roots.iter().any(|root| root == &self.cwd)
            || !selected_merge_account_matches(&self, &selected)
            || !selected_merge_live_account_matches(&self)
            || (self.invocation == ExternalAgentInvocation::Grok
                && grok_acp_stdio_protocol_selected(&self))
        {
            bail!("selected merge command, account, controls or workspace binding differs");
        }
        if runtime.is_adapter_subprocess()
            && self
                .runtime_adapter
                .as_ref()
                .is_none_or(|config| config.binary_path() != self.program.as_path())
        {
            bail!("selected merge adapter program binding differs");
        }
        let resolved = frozen.resolve_role_execution_evidence(AgentRole::Auditor.as_str())?;
        self.assignment_process_launch_kind = Some(AssignmentProcessLaunchKind::MergeArbiter);
        self.assignment_process_launch_attempt = Some(0);
        self.assignment_process_launch_duty =
            Some(crate::mutation_taxonomy::MERGE_ARBITER_PROCESS_DUTY.to_string());
        self.assignment_process_launch_grant = None;
        self.selected_merge_arbiter = None;
        let mut admission = SelectedMergeArbiterAdmission {
            selected,
            decision,
            frozen,
            resolved,
            command: Box::new(selected_merge_command_snapshot(&self)),
        };
        let grant =
            crate::mutation_taxonomy::admit_selected_merge_arbiter_process_intent(&admission)?;
        self.assignment_process_launch_grant = Some(grant);
        admission.command = Box::new(selected_merge_command_snapshot(&self));
        self.selected_merge_arbiter = Some(std::sync::Arc::new(admission));
        Ok(self)
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

    /// Opt into byte-pinned Linux headless read-only target delivery.
    /// Imported modules, source semantics and effective native permissions remain unqualified.
    pub(crate) fn with_read_only_target_executable_pin(mut self) -> Result<Self> {
        validate_read_only_target_executable_pin_mode(&self)?;
        if !self.program.is_absolute() {
            bail!("read-only target executable pin requires an explicit absolute program");
        }
        self.read_only_target_executable_pin = Some(self.program.clone());
        Ok(self)
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

    /// Bind the supervisor-resolved identity used for invocation-qualified
    /// writable native-runtime admission.
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
        if !matches!(
            runtime,
            RuntimeId::Grok | RuntimeId::ClaudeCode | RuntimeId::GeminiCli | RuntimeId::Cursor
        ) || !non_delegating_terminal_worker
        {
            let reason = if runtime == RuntimeId::ClaudeCode {
                WRITABLE_CLAUDE_TERMINAL_WORKER_REQUIRED
            } else if runtime == RuntimeId::GeminiCli {
                WRITABLE_GEMINI_TERMINAL_WORKER_REQUIRED
            } else {
                WRITABLE_GROK_TERMINAL_WORKER_REQUIRED
            };
            bail!(
                "{reason}: writable native runtime requires an explicitly bound non-delegating terminal Worker"
            );
        }
        let expected_invocation = match runtime {
            RuntimeId::Grok => ExternalAgentInvocation::Grok,
            RuntimeId::ClaudeCode => ExternalAgentInvocation::ClaudeCode,
            RuntimeId::GeminiCli => ExternalAgentInvocation::GeminiCli,
            RuntimeId::Cursor => ExternalAgentInvocation::Cursor,
            _ => unreachable!("filtered above"),
        };
        if self.invocation != expected_invocation {
            let reason = if runtime == RuntimeId::ClaudeCode {
                WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE
            } else if runtime == RuntimeId::GeminiCli {
                WRITABLE_GEMINI_SELECTION_EVIDENCE_STALE
            } else {
                WRITABLE_GROK_SELECTION_EVIDENCE_STALE
            };
            bail!("{reason}: selected native runtime does not match the executable invocation");
        }
        self.writable_runtime_selection = Some(WritableRuntimeSelectionEvidence::from_command(
            assignment_id,
            runtime,
            &self,
        )?);
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
            authority: WorktreeWritableConfinementAuthority::Direct(admission),
            selected_launch: self.writable_runtime_selection.clone(),
            // The assignment-child process grant has its own sealed validation at
            // the process boundary, independent of this direct command snapshot.
            command: WorktreeConfinementSnapshot::from_command(&self, false),
        });
        self
    }

    /// Attach the live parent-issued nested authority to the finalized command. The
    /// caller must already have revalidated the unique serial permit and parent leases.
    pub(crate) fn with_nested_worktree_writable_confinement(
        mut self,
        admission: NestedWorktreeWritableAdmission,
    ) -> Result<Self> {
        if self.grok_run_account_binding.is_none() {
            bail!(
                "{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: nested Grok launch has no run-bound selected CAM account"
            );
        }
        if self.runtime_adapter.as_ref().is_none_or(|adapter| {
            adapter.grok_interaction_protocol()
                != crate::runtime_adapter::GrokInteractionProtocol::HeadlessStreamingJson
        }) {
            bail!(
                "{WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED}: nested Grok admits only native headless streaming-json"
            );
        }
        self.worktree_writable_confinement = Some(WorktreeWritableConfinementProof {
            authority: WorktreeWritableConfinementAuthority::Nested(Box::new(admission)),
            selected_launch: self.writable_runtime_selection.clone(),
            // Nested authority is minted only after the final process grant exists, so
            // retain that exact grant and final-command binding in its private proof.
            command: WorktreeConfinementSnapshot::from_command(&self, true),
        });
        Ok(self)
    }

    /// Reuse the process boundary's typed identity check during supervisor admission.
    /// A wire report or messaging capability is never a substitute for this grant.
    pub(crate) fn verify_assignment_child_admission_identity(&self) -> Result<()> {
        if self.assignment_process_launch_kind != Some(AssignmentProcessLaunchKind::AssignmentChild)
        {
            bail!("assignment admission requires an assignment-child process intent");
        }
        refuse_assignment_process_launch_before_preflight(self)?;
        Ok(())
    }

    fn current_grok_writable_contract(&self) -> Result<TypedRuntimeContract> {
        if self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree {
            bail!(
                "writable_grok_managed_worktree_required: writable Grok is restricted to a managed child worktree"
            );
        }
        TypedRuntime::from_launch(
            AdapterId::Grok,
            self.model.as_deref(),
            self.reasoning_effort.as_deref(),
        )
        .context("writable Grok requires a safe selected model and canonical native effort")?;
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
        let context = LaunchContext {
            prompt: &self.prompt,
            model: self.model.as_deref(),
            effort: self.reasoning_effort.as_deref(),
            cwd: &self.cwd,
            output: &self.output_last_message,
        };
        let contract = if grok_acp_stdio_protocol_selected(self) {
            config.grok_acp_runtime_contract(
                &context,
                &crate::runtime_adapter::grok::GROK_ACP_RUNTIME_DESCRIPTOR.required_environment(),
            )
        } else {
            config.typed_runtime_contract_with_output_schema(
                AdapterId::Grok,
                &context,
                self.output_schema.as_deref(),
            )
        };
        contract.with_context(|| {
            format!(
                "{WRITABLE_GROK_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Grok adapter contract is not an immutable bounded protocol contract"
            )
        })
    }

    fn current_claude_writable_contract(&self) -> Result<ClaudeManagedLaunchContract> {
        if self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree {
            bail!(
                "writable_claude_managed_worktree_required: writable Claude is restricted to a managed child worktree"
            );
        }
        if self.workspace_access != WorkspaceAccess::ReadWrite {
            bail!(
                "{WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE}: writable Claude workspace no longer matches its supervisor-selected evidence"
            );
        }
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            format!(
                "{WRITABLE_CLAUDE_SELECTION_EVIDENCE_MISSING}: writable Claude has no supervisor-selected launch evidence"
            )
        })?;
        if !selected.matches_command(self, RuntimeId::ClaudeCode) {
            bail!(
                "{WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE}: writable Claude launch no longer matches its supervisor-selected evidence"
            );
        }
        let config = self.runtime_adapter.as_ref().with_context(|| {
            format!(
                "{WRITABLE_CLAUDE_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Claude has no adapter configuration"
            )
        })?;
        if self.invocation != ExternalAgentInvocation::ClaudeCode
            || config.binary_path() != self.program.as_path()
        {
            bail!(
                "{WRITABLE_CLAUDE_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Claude adapter executable is not bound to the selected program"
            );
        }
        config
            .claude_managed_launch_contract(&LaunchContext {
                prompt: &self.prompt,
                model: self.model.as_deref(),
                effort: self.reasoning_effort.as_deref(),
                cwd: &self.cwd,
                output: &self.output_last_message,
            })
            .with_context(|| {
                format!(
                    "{WRITABLE_CLAUDE_ADAPTER_CONFIGURATION_UNVERIFIED}: writable Claude adapter contract is not the exact fresh bare managed-Worker contract"
                )
            })
    }

    fn selected_grok_writable_workspace(&self) -> Result<&Path> {
        if self.workspace_access != WorkspaceAccess::ReadWrite {
            bail!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_STALE}: writable Grok workspace no longer matches its supervisor-selected evidence"
            );
        }
        self.current_grok_writable_contract()?;
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_SELECTION_EVIDENCE_MISSING}: writable Grok has no supervisor-selected launch evidence"
            )
        })?;
        Ok(&selected.cwd)
    }

    fn current_gemini_writable_capabilities(
        &self,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        if self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree
            || self.workspace_access != WorkspaceAccess::ReadWrite
        {
            bail!(
                "{WRITABLE_GEMINI_TERMINAL_WORKER_REQUIRED}: writable Gemini is restricted to a managed child worktree"
            );
        }
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GEMINI_SELECTION_EVIDENCE_MISSING}: writable Gemini has no supervisor-selected launch evidence"
            )
        })?;
        if !selected.matches_command(self, RuntimeId::GeminiCli)
            || self.invocation != ExternalAgentInvocation::GeminiCli
            || self
                .runtime_adapter
                .as_ref()
                .is_none_or(|config| config.binary_path() != self.program.as_path())
        {
            bail!(
                "{WRITABLE_GEMINI_SELECTION_EVIDENCE_STALE}: writable Gemini launch no longer matches its selected adapter contract"
            );
        }
        Ok(crate::runtime_adapter::RuntimeCapabilities {
            side_effect_confinement: SideEffectConfinement::Verified,
            ..crate::runtime_adapter::RuntimeCapabilities::GEMINI_CLI
        })
    }

    /// Concrete capabilities used by the supervisor while creating MACO-owned confinement
    /// evidence. Static capabilities remain authoritative for every other runtime.
    pub(crate) fn selected_writable_capabilities(
        &self,
        runtime: RuntimeId,
        expected_assignment_id: Option<&str>,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        if runtime == RuntimeId::Cursor {
            if self.invocation != ExternalAgentInvocation::Cursor
                || self.workspace_access != WorkspaceAccess::ReadWrite
                || self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree
                || self.cursor_run_account_binding.is_none()
            {
                bail!("writable Cursor requires an admitted managed-child account binding");
            }
            if expected_assignment_id.is_some_and(|expected| {
                self.writable_runtime_selection
                    .as_ref()
                    .is_none_or(|selected| {
                        selected.runtime != RuntimeId::Cursor
                            || selected.assignment_id != expected
                            || !selected.matches_command(self, RuntimeId::Cursor)
                    })
            }) {
                bail!("writable Cursor selection evidence is missing or stale");
            }
            return Ok(crate::runtime_adapter::RuntimeCapabilities::CURSOR_MANAGED);
        }
        let capabilities = match runtime {
            RuntimeId::Grok => self.current_grok_writable_contract()?.capabilities(),
            RuntimeId::ClaudeCode => self.current_claude_writable_contract()?.capabilities(),
            RuntimeId::GeminiCli => self.current_gemini_writable_capabilities()?,
            _ => return Ok(runtime.capabilities()),
        };
        if expected_assignment_id.is_some_and(|expected| {
            self.writable_runtime_selection
                .as_ref()
                .is_none_or(|selected| {
                    selected.assignment_id != expected
                        || selected.runtime != runtime
                        || !selected.matches_command(self, runtime)
                })
        }) {
            let reason = if runtime == RuntimeId::ClaudeCode {
                WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE
            } else if runtime == RuntimeId::GeminiCli {
                WRITABLE_GEMINI_SELECTION_EVIDENCE_STALE
            } else {
                WRITABLE_GROK_SELECTION_EVIDENCE_STALE
            };
            bail!("{reason}: writable native selection evidence is stale or belongs to a different assignment");
        }
        Ok(capabilities)
    }

    pub(crate) fn verify_grok_run_account_binding(&self, expected_run_id: &str) -> Result<()> {
        let lifecycle = self.agent_lifecycle.as_ref().with_context(|| {
            format!("{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: Grok launch has no lifecycle binding")
        })?;
        let carried = self.grok_run_account_binding.as_ref().with_context(|| {
            format!(
                "{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: Grok launch has no run-bound selected CAM account"
            )
        })?;
        if lifecycle.run_id != expected_run_id
            || crate::account_authority::grok_run_account_binding(expected_run_id).as_ref()
                != Some(carried)
        {
            bail!(
                "{WRITABLE_GROK_CONFINEMENT_UNVERIFIED}: Grok launch account binding differs from this run's admitted CAM selection"
            );
        }
        Ok(())
    }

    /// Concrete capabilities used at the external process boundary. Writable Grok must carry the
    /// exact MACO-owned proof produced after worktree and claim reauthentication.
    fn verified_writable_capabilities(
        &self,
        runtime: RuntimeId,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        let capabilities = self.selected_writable_capabilities(runtime, None)?;
        if !matches!(
            runtime,
            RuntimeId::Grok | RuntimeId::ClaudeCode | RuntimeId::GeminiCli | RuntimeId::Cursor
        ) {
            return Ok(capabilities);
        }
        let gemini = runtime == RuntimeId::GeminiCli;
        let selected = self.writable_runtime_selection.as_ref().with_context(|| {
            if runtime == RuntimeId::ClaudeCode {
                format!("{WRITABLE_CLAUDE_SELECTION_EVIDENCE_MISSING}: writable Claude selection evidence disappeared before confinement verification")
            } else if gemini {
                format!("{WRITABLE_GEMINI_SELECTION_EVIDENCE_MISSING}: writable Gemini selection evidence disappeared before confinement verification")
            } else {
                format!("{WRITABLE_GROK_SELECTION_EVIDENCE_MISSING}: writable Grok selection evidence disappeared before confinement verification")
            }
        })?;
        let proof = self.worktree_writable_confinement.as_ref().with_context(|| {
            if runtime == RuntimeId::ClaudeCode {
                format!("{WRITABLE_CLAUDE_CONFINEMENT_PROOF_MISSING}: writable Claude has no MACO-owned managed-worktree confinement proof")
            } else if gemini {
                format!("{WRITABLE_GEMINI_CONFINEMENT_PROOF_MISSING}: writable Gemini has no MACO-owned managed-worktree confinement proof")
            } else {
                format!("{WRITABLE_GROK_CONFINEMENT_PROOF_MISSING}: writable Grok has no MACO-owned managed-worktree confinement proof")
            }
        })?;
        let bind_assignment_process_launch = matches!(
            &proof.authority,
            WorktreeWritableConfinementAuthority::Nested(_)
        );
        if proof.selected_launch.as_ref() != Some(selected)
            || !proof
                .command
                .matches_command(self, bind_assignment_process_launch)
        {
            let reason = if runtime == RuntimeId::ClaudeCode {
                WRITABLE_CLAUDE_CONFINEMENT_PROOF_STALE
            } else if runtime == RuntimeId::GeminiCli {
                WRITABLE_GEMINI_CONFINEMENT_PROOF_STALE
            } else {
                WRITABLE_GROK_CONFINEMENT_PROOF_STALE
            };
            bail!("{reason}: writable native confinement proof does not bind the current selected launch");
        }
        if runtime == RuntimeId::ClaudeCode {
            let (resolved, current_digest) =
                resolve_claude_native_program_identity(&self.program, &self.cwd)
                    .context("failed to re-resolve Claude executable before confinement release")?;
            if !claude::admitted_native_executable(&resolved, &current_digest)
                || selected.program_sha256.as_deref() != Some(current_digest.as_str())
            {
                bail!(
                    "{WRITABLE_CLAUDE_SELECTION_EVIDENCE_STALE}: writable Claude executable bytes changed after selection"
                );
            }
        }
        let authenticated = match &proof.authority {
            WorktreeWritableConfinementAuthority::Direct(admission) => {
                admission.version == WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION
                    && admission.assignment_id == selected.assignment_id
                    && admission.target == WritableLaunchTarget::ManagedChildWorktree
                    && admission.worktree.kind == ManagedWorktreeAdmissionKind::ManagedDisposable
                    && admission.worktree.worktree_id == selected.assignment_id
                    && admission.claims.state == HeldPathClaimsAdmissionState::Held
                    && admission.native_sandbox.runtime == runtime
                    && admission.native_sandbox.workspace_access == WorkspaceAccess::ReadWrite
                    && admission.native_sandbox.side_effect_confinement
                        == SideEffectConfinement::Verified
            }
            WorktreeWritableConfinementAuthority::Nested(admission) => {
                let lifecycle = self.agent_lifecycle.as_ref();
                runtime == RuntimeId::Grok
                    && admission.worker_id == selected.assignment_id
                    && admission.resource_owner_id != admission.worker_id
                    && admission.attempt != 0
                    && admission.serial_permit_attempt == admission.attempt
                    && admission.worktree_id == admission.resource_owner_id
                    && admission.worktree_path == self.cwd
                    && !admission.lease_worktree_branch.is_empty()
                    && admission.claim_owner_id == admission.resource_owner_id
                    && admission.claim_token != 0
                    && admission.semantic_token.is_none_or(|token| token != 0)
                    && !admission.claim_paths.is_empty()
                    && !admission.worker_paths.is_empty()
                    && admission.worker_paths.iter().all(|worker_path| {
                        admission
                            .claim_paths
                            .iter()
                            .any(|claim_path| worker_path.starts_with(claim_path))
                    })
                    && admission.native_sandbox.runtime == RuntimeId::Grok
                    && admission.native_sandbox.workspace_access == WorkspaceAccess::ReadWrite
                    && admission.native_sandbox.side_effect_confinement
                        == SideEffectConfinement::Verified
                    && admission.worker_journals == self.worker_journal_artifacts
                    && admission.worker_journals.len() == 1
                    && admission.worker_journals[0].worker_id == admission.worker_id
                    && self.assignment_process_launch_attempt == Some(admission.attempt)
                    && self.assignment_messaging_launch.is_none()
                    && self
                        .verify_grok_run_account_binding(&admission.run_id)
                        .is_ok()
                    && self.runtime_adapter.as_ref().is_some_and(|adapter| {
                        adapter.grok_interaction_protocol()
                            == crate::runtime_adapter::GrokInteractionProtocol::HeadlessStreamingJson
                    })
                    && lifecycle.is_some_and(|identity| {
                        identity.run_id == admission.run_id
                            && identity.task_id == admission.worker_id
                            && identity.parent.as_deref()
                                == Some(admission.resource_owner_id.as_str())
                    })
            }
        };
        if !authenticated || self.workspace_access != WorkspaceAccess::ReadWrite {
            let reason = if runtime == RuntimeId::ClaudeCode {
                WRITABLE_CLAUDE_CONFINEMENT_UNVERIFIED
            } else if runtime == RuntimeId::GeminiCli {
                WRITABLE_GEMINI_CONFINEMENT_UNVERIFIED
            } else {
                WRITABLE_GROK_CONFINEMENT_UNVERIFIED
            };
            bail!("{reason}: writable native confinement proof does not authenticate the current bounded managed-worktree launch");
        }
        Ok(capabilities)
    }

    #[cfg(test)]
    pub(crate) fn verified_writable_capabilities_for_test(
        &self,
        runtime: RuntimeId,
    ) -> Result<crate::runtime_adapter::RuntimeCapabilities> {
        self.verified_writable_capabilities(runtime)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn cursor_managed_claimed_paths(&self) -> Result<Vec<PathBuf>> {
        if self.invocation != ExternalAgentInvocation::Cursor {
            bail!("Cursor assignment authority requested for another runtime");
        }
        if self.workspace_access == WorkspaceAccess::ReadOnly {
            return Ok(Vec::new());
        }
        self.verified_writable_capabilities(RuntimeId::Cursor)?;
        let proof = self
            .worktree_writable_confinement
            .as_ref()
            .context("writable Cursor assignment authority omitted its confinement proof")?;
        match &proof.authority {
            WorktreeWritableConfinementAuthority::Direct(admission) => {
                Ok(admission.claims.paths.clone())
            }
            WorktreeWritableConfinementAuthority::Nested(_) => {
                bail!("Cursor assignment requires direct managed-child authority")
            }
        }
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
        let run_id = run_id.into();
        if matches!(
            self.invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        ) {
            self.codex_run_account_binding =
                crate::account_authority::codex_run_account_binding(&run_id);
        }
        if self.invocation == ExternalAgentInvocation::Grok
            && self.grok_run_account_binding.is_none()
        {
            self.grok_run_account_binding =
                crate::account_authority::grok_run_account_binding(&run_id);
        }
        if self.invocation == ExternalAgentInvocation::ClaudeCode
            && self.claude_run_account_binding.is_none()
        {
            self.claude_run_account_binding =
                crate::account_authority::claude_run_account_binding(&run_id);
        }
        if self.invocation == ExternalAgentInvocation::GeminiCli
            && self.gemini_run_account_binding.is_none()
        {
            self.gemini_run_account_binding =
                crate::account_authority::gemini_run_account_binding(&run_id);
        }
        if self.invocation == ExternalAgentInvocation::Cursor
            && self.cursor_run_account_binding.is_none()
        {
            self.cursor_run_account_binding =
                crate::account_authority::cursor_run_account_binding(&run_id);
        }
        self.agent_lifecycle = Some(ExternalAgentLifecycleIdentity {
            registry_repo: registry_repo.into(),
            role: role.into(),
            run_id,
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

    /// Disable Codex native multi_agent and goals for this command only.
    /// Grants no authority or role change and has no re-enable counterpart.
    pub(crate) fn with_codex_native_delegation_disabled(mut self) -> Self {
        self.codex_native_delegation_disabled = true;
        self
    }

    /// Reads the existing private Codex native-delegation disable flag.
    /// This is not a setter and does not re-enable delegation.
    #[cfg(test)]
    pub(crate) fn codex_native_delegation_is_disabled(&self) -> bool {
        self.codex_native_delegation_disabled
    }

    #[cfg(test)]
    pub(crate) fn codex_run_account_binding_for_test(&self) -> Option<&CodexRunAccountBinding> {
        self.codex_run_account_binding.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn managed_worker_app_server_selected_for_test(&self) -> Result<bool, String> {
        classify_managed_worker_app_server(self, ExternalExecutionRuntime::Verified)
    }

    /// Pre-dispatch contract verification. Returned cgroup, cancellation, capture and usage
    /// evidence must still pass the controller's post-dispatch checks and settlement.
    pub(crate) fn managed_parent_control_transport(
        &self,
        runtime: crate::supervise::SupervisorRuntime,
    ) -> Result<crate::selection::routing_policy::ControlTransport> {
        if self.workspace_access != WorkspaceAccess::ReadOnly
            || self.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree
            || self.model.is_none()
            || self.reasoning_effort.is_none()
        {
            bail!("managed parent requires selected read-only managed-child command");
        }
        let lifecycle = self
            .agent_lifecycle
            .as_ref()
            .context("managed parent requires lifecycle binding")?;
        if lifecycle.role != AgentRole::ChildOrchestrator.as_str()
            || lifecycle.run_id.is_empty()
            || lifecycle.task_id.is_empty()
        {
            bail!("managed parent lifecycle differs from the bound child orchestrator");
        }
        let adapter = AdapterId::from_runtime(runtime);
        let (capabilities, native_off) = match adapter {
            AdapterId::Codex => {
                if self.invocation != ExternalAgentInvocation::CodexSupervisor
                    || !self.codex_managed_readonly_route_active()
                {
                    bail!("managed Codex parent requires its bound read-only app-server route");
                }
                match &self.codex_run_account_binding {
                    Some(CodexRunAccountBinding::Selected(_))
                        if crate::account_authority::codex_run_account_binding(
                            &lifecycle.run_id,
                        ) == self.codex_run_account_binding => {}
                    Some(CodexRunAccountBinding::LocalAuth)
                        if crate::account_authority::codex_run_account_binding(
                            &lifecycle.run_id,
                        ) == self.codex_run_account_binding
                            && crate::account_authority::configured_cam_authority_socket()
                                .is_none() => {}
                    _ => bail!("managed parent Codex account selection is missing or changed"),
                }
                validate_managed_readonly_execute_binding(
                    self,
                    Some(self.codex_managed_readonly_route),
                )
                .map_err(anyhow::Error::msg)?;
                (
                    adapter.capabilities(),
                    self.codex_native_delegation_disabled,
                )
            }
            AdapterId::Grok => {
                if self.invocation != ExternalAgentInvocation::Grok {
                    bail!("managed parent runtime differs from its command invocation");
                }
                self.verify_grok_run_account_binding(&lifecycle.run_id)?;
                let config = self
                    .runtime_adapter
                    .as_ref()
                    .context("managed parent needs an adapter descriptor")?;
                if config.binary_path() != self.program {
                    bail!("managed parent executable differs from descriptor");
                }
                let contract = config
                    .typed_runtime_contract_with_output_schema(
                        adapter,
                        &LaunchContext {
                            prompt: &self.prompt,
                            model: self.model.as_deref(),
                            effort: self.reasoning_effort.as_deref(),
                            cwd: &self.cwd,
                            output: &self.output_last_message,
                        },
                        self.output_schema.as_deref(),
                    )
                    .context(
                        "managed parent native confinement/delegation contract is unsupported",
                    )?;
                (contract.capabilities(), contract.subagents_disabled())
            }
            _ => bail!("managed parent lacks a verified account-bound native-off adapter contract"),
        };
        adapter
            .managed_parent_control_transport(capabilities, native_off)
            .map_err(anyhow::Error::msg)
    }

    /// Opt this command into the initial managed parent dynamic worker-request tool.
    /// Callers must already have admitted the exact read-only ChildOrchestrator shape.
    /// A later continuation opt-in replaces this; launch rejects a shape that does not match.
    pub(crate) fn with_codex_managed_worker_requests(mut self) -> Self {
        self.codex_managed_readonly_route = CodexManagedReadonlyRoute::InitialWorkerRequests;
        self
    }

    /// Opt this command into the managed parent continuation app-server.
    /// The dynamic worker tool stays absent and this does not open an inbox endpoint.
    pub(crate) fn with_codex_managed_readonly_continuation(mut self) -> Self {
        self.codex_managed_readonly_route = CodexManagedReadonlyRoute::Continuation;
        self
    }

    pub(crate) fn codex_managed_worker_requests_enabled(&self) -> bool {
        self.codex_managed_readonly_route == CodexManagedReadonlyRoute::InitialWorkerRequests
    }

    pub(crate) fn codex_managed_readonly_continuation_enabled(&self) -> bool {
        self.codex_managed_readonly_route == CodexManagedReadonlyRoute::Continuation
    }

    fn codex_managed_readonly_route_active(&self) -> bool {
        self.codex_managed_readonly_route != CodexManagedReadonlyRoute::Off
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

    /// Attach a caller-issued assignment-child, parent-auditor, Inbox
    /// independent-auditor, consult, or merge-arbiter process grant.
    ///
    /// Catalog constructors leave kind and grant absent. Consult Codex binds
    /// only CodexConsultant; consult Claude binds only ClaudeConsultant.
    /// MergeArbiter binds only a merge-shaped CodexSupervisor command. Generic
    /// CodexSupervisor constructors still leave kind absent.
    pub(crate) fn with_assignment_process_launch(
        mut self,
        kind: AssignmentProcessLaunchKind,
        grant: AssignmentProcessLaunchGrant,
    ) -> Self {
        self.assignment_process_launch_attempt = Some(grant.attempt());
        self.assignment_process_launch_duty = Some(grant.duty().to_string());
        self.assignment_mechanical_executor_duty = grant.mechanical_duty();
        self.assignment_process_launch_kind = Some(kind);
        self.assignment_process_launch_grant = Some(grant);
        self
    }

    pub(crate) fn with_assignment_messaging(mut self, launch: AssignmentMessagingLaunch) -> Self {
        self.assignment_messaging_launch = Some(launch);
        self
    }

    pub(crate) fn with_cam_authority_socket_pin(
        mut self,
        pin: Option<String>,
    ) -> ExternalAgentCommand {
        self.cam_authority_socket_pin = pin.filter(|value| !value.is_empty());
        self
    }

    /// Bind the immutable Grok account evidence admitted for this specific run.
    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn with_grok_run_account_binding(
        mut self,
        binding: Option<FrozenGrokSelectedBinding>,
    ) -> Self {
        self.grok_run_account_binding = binding;
        self
    }

    pub(crate) fn with_gemini_run_account_binding(
        mut self,
        binding: Option<FrozenGeminiSelectedBinding>,
    ) -> Self {
        self.gemini_run_account_binding = binding;
        self
    }

    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn with_claude_run_account_binding(
        mut self,
        binding: Option<FrozenClaudeSelectedBinding>,
    ) -> Self {
        self.claude_run_account_binding = binding;
        self
    }

    #[cfg(test)]
    pub(crate) fn cam_authority_socket_pin(&self) -> Option<&str> {
        self.cam_authority_socket_pin.as_deref()
    }

    /// Supervisor-held endpoint identity for binding a collected parent turn.
    pub(crate) fn assignment_messaging_launch(&self) -> Option<&AssignmentMessagingLaunch> {
        self.assignment_messaging_launch.as_ref()
    }

    /// Ensures the launch prompt matches the messaging capability this command actually has.
    pub(crate) fn verify_assignment_messaging_protocol_instructions(&self) -> Result<()> {
        match self.codex_managed_readonly_route {
            CodexManagedReadonlyRoute::Off => {
                if self.assignment_messaging_launch.is_none() {
                    return Ok(());
                }
                let existing = self.read_manifested_launch_prompt()?;
                if prompt_includes_assignment_messaging_protocol_appendix(&existing) {
                    return Ok(());
                }
                bail!(
                    "manifested launch prompt is missing assignment messaging protocol appendix at {}",
                    self.prompt.display()
                );
            }
            CodexManagedReadonlyRoute::InitialWorkerRequests => {
                if self.assignment_messaging_launch.is_none() {
                    bail!(
                        "managed initial Codex parent is missing its sealed inbox endpoint at {}",
                        self.prompt.display()
                    );
                }
                let existing = self.read_manifested_launch_prompt()?;
                if prompt_includes_assignment_messaging_protocol_appendix(&existing) {
                    bail!(
                        "managed initial Codex parent prompt must use the dynamic worker-request tool appendix, not loopback IPC, at {}",
                        self.prompt.display()
                    );
                }
                if prompt_includes_managed_worker_request_tool_appendix(&existing) {
                    return Ok(());
                }
                bail!(
                    "manifested launch prompt is missing the managed worker-request tool appendix at {}",
                    self.prompt.display()
                );
            }
            CodexManagedReadonlyRoute::Continuation => {
                let existing = self.read_manifested_launch_prompt()?;
                if prompt_includes_managed_worker_request_tool_appendix(&existing)
                    || prompt_includes_assignment_messaging_protocol_appendix(&existing)
                {
                    bail!(
                        "managed continuation prompt must not grant worker-request or loopback messaging instructions at {}",
                        self.prompt.display()
                    );
                }
                Ok(())
            }
        }
    }

    fn read_manifested_launch_prompt(&self) -> Result<Vec<u8>> {
        read_bounded_regular_file_nofollow(&self.prompt, MAX_PROMPT_BYTES).with_context(|| {
            format!(
                "failed to read manifested launch prompt for assignment messaging verification: {}",
                self.prompt.display()
            )
        })
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
    /// Exact Grok streaming-json spend observation when the trusted runner executed Grok.
    /// Absent for non-Grok runs and legacy deserialized reports.
    pub grok_stream_usage_evidence: Option<GrokStreamUsageEvidence>,
    /// Parent-owned Grok ACP stdio observation. Never accepted from child reports.
    pub grok_acp_parent_evidence: Option<GrokAcpParentEvidence>,
    /// Parent-owned managed Cursor handshake/raw-event/terminal evidence.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub cursor_managed_parent_evidence: Option<crate::runtime_adapter::CursorManagedParentEvidence>,
    /// Parent-owned Codex model, effort, and usage observation derived from the captured
    /// `codex exec --json` stream and the parent-owned Codex home rollout. Present only for
    /// supervisor launches; never accepted from child reports.
    pub codex_parent_evidence: Option<CodexParentEvidence>,
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
            .field(
                "grok_stream_usage_evidence",
                &self.grok_stream_usage_evidence,
            )
            .field("grok_acp_parent_evidence", &self.grok_acp_parent_evidence)
            .field(
                "cursor_managed_parent_evidence",
                &self.cursor_managed_parent_evidence,
            )
            .field("codex_parent_evidence", &self.codex_parent_evidence)
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

    #[cfg(test)]
    pub(crate) fn managed_grok_selection_evidence(
        &self,
    ) -> Option<&ManagedGrokAccountSelectionEvidence> {
        self.stdout.run_metadata.managed_grok_selection.as_ref()
    }

    pub(crate) fn managed_gemini_selection_evidence(
        &self,
    ) -> Option<&ManagedGeminiAccountSelectionEvidence> {
        self.stdout.run_metadata.managed_gemini_selection.as_ref()
    }

    pub fn fixed_version_probe_evidence(&self) -> Option<&EnvironmentFixedVersionProbeEvidence> {
        self.stdout
            .run_metadata
            .fixed_version_probe_evidence
            .as_ref()
    }

    #[cfg(test)]
    pub(crate) fn attach_fixed_version_probe_evidence_for_test(
        &mut self,
        evidence: EnvironmentFixedVersionProbeEvidence,
    ) {
        self.stdout.run_metadata.fixed_version_probe_evidence = Some(evidence);
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

    /// Correlated app-server notifications retained by the live host protocol driver.
    /// `None` means unavailable, not zero commands. Reject incomplete observations and check
    /// turn/process/containment success before reconciling any agent-authored command claims.
    /// Serialized runs and agent output cannot supply this private evidence.
    #[allow(dead_code)] // Consumed by the supervisor's separate reconciliation change.
    pub(crate) fn codex_command_execution_evidence(
        &self,
    ) -> Option<&codex_app_server::CommandExecutionEvidence> {
        self.stdout
            .run_metadata
            .codex_command_execution_evidence
            .as_ref()
    }

    /// Injection seam for supervisor acceptance tests; never parses an agent-authored report.
    #[cfg(test)]
    pub(crate) fn set_codex_command_execution_evidence_for_test(
        &mut self,
        evidence: codex_app_server::CommandExecutionEvidence,
    ) {
        self.stdout.run_metadata.codex_command_execution_evidence = Some(evidence);
    }

    /// The retained copy is never deserialized from reports or writable captures.
    pub(crate) fn authenticated_app_server_evidence(&self) -> Option<&CodexParentEvidence> {
        self.stdout
            .run_metadata
            .codex_app_server_parent_evidence
            .as_ref()
    }

    /// Private identity evidence captured by the parent, never restored from a report.
    pub(crate) fn authenticated_codex_evidence(&self) -> Option<&CodexParentEvidence> {
        self.authenticated_app_server_evidence().or(self
            .stdout
            .run_metadata
            .codex_cli_parent_evidence
            .as_ref())
    }

    pub(crate) fn authenticated_app_server_usage_complete(&self) -> bool {
        self.stdout.run_metadata.codex_app_server_usage_complete
    }

    pub(crate) fn authenticated_codex_usage_complete(&self) -> bool {
        if self.authenticated_app_server_evidence().is_some() {
            self.authenticated_app_server_usage_complete()
        } else {
            self.stdout.run_metadata.codex_cli_usage_complete
                && self.stdout.run_metadata.codex_cli_usage.is_some()
        }
    }

    /// Only the bound native subprocess capture can supply Grok token accounting.
    /// Public evidence, JSONL files and deserialized reports cannot recreate it.
    pub(crate) fn authenticated_grok_usage(
        &self,
        command: &ExternalAgentCommand,
    ) -> Option<(Usage, bool)> {
        let capture = self.stdout.run_metadata.grok_native_usage.as_ref()?;
        if capture.command != *command {
            return None;
        }
        let (usage, complete) = capture.observation.allocation();
        Some((usage, complete && capture.process_completed))
    }

    fn retain_grok_native_usage(
        &mut self,
        command: &ExternalAgentCommand,
        runtime: ExternalExecutionRuntime,
        stdout: &CapturedBytes,
        process_completed: bool,
    ) {
        if runtime != ExternalExecutionRuntime::Verified
            || command.invocation != ExternalAgentInvocation::Grok
            || grok_acp_stdio_protocol_selected(command)
        {
            return;
        }
        self.stdout.run_metadata.grok_native_usage =
            crate::runtime_adapter::grok::observe_grok_native_usage(
                stdout.as_bytes(),
                stdout.is_truncated(),
            )
            .map(|observation| GrokNativeUsageCapture {
                command: command.clone(),
                observation,
                process_completed,
            });
    }

    #[cfg(test)]
    pub(crate) fn retain_grok_native_usage_for_test(
        &mut self,
        command: &ExternalAgentCommand,
        stdout: &CapturedBytes,
        process_completed: bool,
    ) {
        self.retain_grok_native_usage(
            command,
            ExternalExecutionRuntime::Verified,
            stdout,
            process_completed,
        );
    }

    pub(crate) fn codex_auditor_effort_qualified(&self) -> bool {
        !self.stdout.run_metadata.codex_auditor_effort_required
            || self
                .authenticated_app_server_evidence()
                .is_some_and(|evidence| {
                    codex_app_server::observed_effort_meets(
                        evidence.requested_effort.as_deref(),
                        evidence.observed_effort.known(),
                    )
                })
    }

    fn qualify_codex_auditor_effort(&mut self, spec: &ExternalAgentCommand) {
        self.stdout.run_metadata.codex_auditor_effort_required = spec
            .agent_lifecycle
            .as_ref()
            .is_some_and(|identity| identity.role == AgentRole::Auditor.as_str());
        if !self.codex_auditor_effort_qualified() {
            self.publishable = false;
            self.error = append_external_error(
                self.error.take(),
                Some("observed Auditor effort does not meet the selected requirement".to_string()),
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn qualify_codex_auditor_effort_for_test(&mut self, spec: &ExternalAgentCommand) {
        self.qualify_codex_auditor_effort(spec);
    }

    /// Invocation-wide tokens from the same private capture as the identity.
    /// CLI final-turn usage is not the aggregate of a multi-turn invocation.
    pub(crate) fn authenticated_codex_usage(&self) -> Option<Usage> {
        if self.authenticated_app_server_evidence().is_some() {
            return self.authenticated_codex_partial_usage();
        }
        self.stdout.run_metadata.codex_cli_usage
    }

    /// Parent-private Claude raw native stream evidence. Public report fields,
    /// JSON logs, and deserialized runs cannot mint this custody.
    pub(crate) fn authenticated_claude_native_evidence(&self) -> Option<&ClaudeNativeEvidence> {
        self.stdout.run_metadata.claude_native_evidence.as_ref()
    }

    pub(crate) fn authenticated_claude_usage_complete(&self) -> bool {
        self.authenticated_claude_native_evidence()
            .is_some_and(ClaudeNativeEvidence::complete)
    }

    pub(crate) fn authenticated_claude_usage(&self) -> Option<Usage> {
        self.authenticated_claude_native_evidence()
            .and_then(ClaudeNativeEvidence::complete_usage)
    }

    pub(crate) fn authenticated_claude_usage_lower_bound(&self) -> Option<Usage> {
        self.authenticated_claude_native_evidence()
            .and_then(ClaudeNativeEvidence::usage_lower_bound)
    }

    pub(crate) fn authenticated_claude_model(&self) -> Option<&str> {
        self.authenticated_claude_native_evidence()
            .and_then(ClaudeNativeEvidence::observed_model)
    }

    #[cfg(test)]
    pub(crate) fn set_claude_native_stream_for_test(
        &mut self,
        stream: &[u8],
        truncated: bool,
        interrupted: bool,
    ) {
        let mut evidence = crate::runtime_adapter::claude::collect_native_stream(stream, truncated);
        if interrupted {
            evidence.mark_interrupted();
        }
        self.stdout.run_metadata.claude_native_evidence = Some(evidence);
    }

    /// A valid single turn is a lower bound, never a complete CLI aggregate.
    pub(crate) fn authenticated_codex_partial_usage(&self) -> Option<Usage> {
        if let Some(evidence) = self.authenticated_codex_evidence() {
            let CodexParentTurnUsage::Known {
                input_tokens,
                output_tokens,
                cached_input_tokens,
                reasoning_output_tokens,
            } = evidence.turn_usage
            else {
                return None;
            };
            if cached_input_tokens > input_tokens || reasoning_output_tokens > output_tokens {
                return None;
            }
            let input_tokens = usize::try_from(input_tokens).ok()?;
            let output_tokens = usize::try_from(output_tokens).ok()?;
            return Some(Usage {
                input_tokens,
                output_tokens,
                total_tokens: input_tokens.checked_add(output_tokens)?,
            });
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn retain_cli_parent_evidence_for_test(&mut self, stdout: &[u8]) {
        self.stdout.run_metadata.codex_cli_parent_evidence = self.codex_parent_evidence.clone();
        self.stdout.run_metadata.codex_cli_usage = codex_usage_from_jsonl(stdout).ok().flatten();
        self.stdout.run_metadata.codex_cli_usage_complete = self.publishable
            && self.exit_code == Some(0)
            && !self.timed_out
            && self.error.is_none();
    }

    #[cfg(test)]
    pub(crate) fn retain_app_server_parent_evidence_for_test(&mut self) {
        self.stdout.run_metadata.codex_app_server_parent_evidence =
            self.codex_parent_evidence.clone();
        self.stdout.run_metadata.codex_app_server_usage_complete = self.exit_code == Some(0)
            && !self.timed_out
            && self.error.is_none()
            && self
                .codex_command_execution_evidence()
                .is_some_and(|evidence| {
                    evidence.turn_status == codex_app_server::TurnTerminalStatus::Completed
                });
    }

    fn retain_codex_command_execution_evidence(
        &mut self,
        outcome: &codex_app_server::AppServerOutcome,
    ) {
        self.stdout.run_metadata.codex_command_execution_evidence =
            Some(outcome.command_execution_evidence.clone());
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
        self.safely_executed() && self.publishable && self.codex_auditor_effort_qualified()
    }

    /// Same private admission and actual held completion; never wire-restored authority.
    pub(crate) fn qualified_merge_arbiter_output<'a>(
        &'a self,
        command: &ExternalAgentCommand,
    ) -> Result<&'a [u8]> {
        let admission = command
            .selected_merge_arbiter
            .as_ref()
            .context("selected merge authority missing")?;
        validate_selected_merge_command(command)?;
        if !admission.matches_command(command)
            || !selected_merge_account_matches(command, &admission.selected)
        {
            bail!("selected merge command or principal changed");
        }
        let completion = self
            .stdout
            .run_metadata
            .selected_merge_completion
            .as_ref()
            .context("selected merge held completion missing")?;
        let output = self
            .output_last_message
            .as_deref()
            .context("selected merge held output missing")?;
        if !std::sync::Arc::ptr_eq(admission, &completion.admission)
            || sha256_hex(output) != completion.held_output_sha256
            || self.cwd != command.cwd
            || self.exit_code != Some(0)
            || self.timed_out
            || self.error.is_some()
            || !self.stdout.target_launch_attempted
            || !self.scratch_quiescence_verified()
            || command.workspace_access != WorkspaceAccess::ReadOnly
        {
            bail!("selected merge completion, settlement or output binding differs");
        }
        if !matches!(
            admission.resolved.resolution(),
            crate::selection::routing_policy::RoleExecutionEvidenceResolution::LegacyStrict
        ) {
            bail!("required role execution evidence is unsupported or unqualified before launch");
        }
        match command.invocation {
            ExternalAgentInvocation::CodexSupervisor if self.succeeded() => Ok(output),
            ExternalAgentInvocation::Grok => {
                let _descriptive_only = self.held_grok_read_only_completion_facts();
                bail!("selected merge native observed controls and source-qualified permissions are unavailable")
            }
            _ => bail!("selected merge execution qualification is unavailable"),
        }
    }

    pub(crate) fn simulation_succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.error.is_none() && !self.publishable
    }

    pub(crate) fn output_last_message(&self) -> Option<&[u8]> {
        self.output_last_message.as_deref()
    }

    /// Descriptive held completion only: no selected-account, effort, permission or merge authority.
    pub(crate) fn held_grok_read_only_completion_facts(
        &self,
    ) -> Option<&HeldGrokReadOnlyCompletionFacts> {
        self.stdout
            .run_metadata
            .grok_read_only_filesystem
            .as_ref()?;
        let facts = self
            .stdout
            .run_metadata
            .grok_read_only_completion_facts
            .as_ref()?;
        let held_output = self.output_last_message.as_deref()?;
        (sha256_hex(held_output) == facts.held_output_sha256).then_some(facts)
    }

    /// Exact bounded prefix captured from the owned stdout pipe. The bytes are
    /// private held evidence and are deliberately excluded from serialization.
    pub(crate) fn stdout_bytes(&self) -> &[u8] {
        &self.stdout.bytes
    }

    /// Scratch output may be discarded only when the main target was never
    /// released and no preflight probe started, or every launched process is
    /// proven empty with verified side-effect confinement.
    pub(crate) fn gemini_bridge_evidence(&self) -> Option<&gemini_bridge::HeldEvidence> {
        self.stdout.run_metadata.gemini_bridge.as_ref()
    }

    pub(crate) fn source_probe_confirmed_no_provider_release(&self) -> bool {
        self.stdout
            .run_metadata
            .local_source_probe_refusal_quiescent
            && !self.stdout.target_launch_attempted
            && self
                .stdout
                .run_metadata
                .environment_preflight_quiescence_verified
    }

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
    researcher_input_receipts: &'a Vec<researcher_inputs::ResearcherInputReceipt>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grok_stream_usage_evidence: &'a Option<GrokStreamUsageEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grok_acp_parent_evidence: &'a Option<GrokAcpParentEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor_managed_parent_evidence: &'a Option<crate::runtime_adapter::CursorManagedParentEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codex_parent_evidence: &'a Option<CodexParentEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_grok_selection: &'a Option<ManagedGrokAccountSelectionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_codex_selection: &'a Option<FrozenCodexSelectedBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_gemini_selection: &'a Option<ManagedGeminiAccountSelectionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_cursor_selection: &'a Option<ManagedCursorAccountSelectionEvidence>,
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
    researcher_input_receipts: Vec<researcher_inputs::ResearcherInputReceipt>,
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
    #[serde(default)]
    grok_stream_usage_evidence: Option<GrokStreamUsageEvidence>,
    #[serde(default)]
    grok_acp_parent_evidence: Option<GrokAcpParentEvidence>,
    #[serde(default)]
    cursor_managed_parent_evidence: Option<crate::runtime_adapter::CursorManagedParentEvidence>,
    #[serde(default)]
    codex_parent_evidence: Option<CodexParentEvidence>,
    #[serde(default)]
    managed_grok_selection: Option<ManagedGrokAccountSelectionEvidence>,
    #[serde(default)]
    managed_codex_selection: Option<FrozenCodexSelectedBinding>,
    #[serde(default)]
    managed_gemini_selection: Option<ManagedGeminiAccountSelectionEvidence>,
    #[serde(default)]
    managed_cursor_selection: Option<ManagedCursorAccountSelectionEvidence>,
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
            researcher_input_receipts: &self.stdout.run_metadata.researcher_input_receipts,
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
            grok_stream_usage_evidence: &self.grok_stream_usage_evidence,
            grok_acp_parent_evidence: &self.grok_acp_parent_evidence,
            cursor_managed_parent_evidence: &self.cursor_managed_parent_evidence,
            codex_parent_evidence: &self.codex_parent_evidence,
            managed_grok_selection: &self.stdout.run_metadata.managed_grok_selection,
            managed_codex_selection: &self.stdout.run_metadata.managed_codex_selection,
            managed_gemini_selection: &self.stdout.run_metadata.managed_gemini_selection,
            managed_cursor_selection: &self.stdout.run_metadata.managed_cursor_selection,
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
        stdout.run_metadata.researcher_input_receipts = wire.researcher_input_receipts;
        stdout.run_metadata.environment_failures = wire.environment_failures;
        stdout.run_metadata.environment_preflight_process_started =
            wire.environment_preflight_process_started;
        stdout.run_metadata.sandbox_denials = sandbox_denials;
        stdout.run_metadata.gate_denials = wire.gate_denials;
        stdout.run_metadata.machine_global_bypasses = wire.machine_global_bypasses;
        stdout.run_metadata.machine_global_retention_operation_id =
            wire.machine_global_retention_operation_id;
        stdout.run_metadata.pre_action_review_metrics = wire.pre_action_review_metrics;
        stdout.run_metadata.managed_grok_selection = wire.managed_grok_selection;
        stdout.run_metadata.managed_codex_selection = wire.managed_codex_selection;
        stdout.run_metadata.managed_gemini_selection = wire.managed_gemini_selection;
        stdout.run_metadata.managed_cursor_selection = wire.managed_cursor_selection;
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
            grok_stream_usage_evidence: wire.grok_stream_usage_evidence,
            grok_acp_parent_evidence: wire.grok_acp_parent_evidence,
            cursor_managed_parent_evidence: wire.cursor_managed_parent_evidence,
            codex_parent_evidence: wire.codex_parent_evidence,
        })
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ExternalAgentRunMetadata {
    selected_merge_completion: Option<SelectedMergeCompletionBinding>,
    gemini_bridge: Option<gemini_bridge::HeldEvidence>,
    read_only_input_snapshots: Vec<crate::process_runner::ReadOnlyInputSnapshot>,
    local_source_probe_refusal_quiescent: bool,
    researcher_input_receipts: Vec<researcher_inputs::ResearcherInputReceipt>,
    environment_preflight_results: Vec<EnvironmentPreflightResult>,
    environment_failures: Vec<EnvironmentFailure>,
    fixed_version_probe_evidence: Option<EnvironmentFixedVersionProbeEvidence>,
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
    codex_command_execution_evidence: Option<codex_app_server::CommandExecutionEvidence>,
    codex_app_server_parent_evidence: Option<CodexParentEvidence>,
    codex_app_server_usage_complete: bool,
    /// Parent launch role only; never serialized or restored from public reports.
    codex_auditor_effort_required: bool,
    codex_cli_parent_evidence: Option<CodexParentEvidence>,
    codex_cli_usage: Option<Usage>,
    codex_cli_usage_complete: bool,
    grok_native_usage: Option<GrokNativeUsageCapture>,
    /// Applied filesystem and settled I/O only; never reconstructed from public/wire evidence.
    grok_read_only_filesystem: Option<ReadOnlyFilesystemEvidence>,
    /// Held native completion and materialized output only; never wire-restored authority.
    grok_read_only_completion_facts: Option<HeldGrokReadOnlyCompletionFacts>,
    /// Raw Claude stream-derived identity and usage held only by the parent
    /// that owned stdout. Serialization and public logs cannot restore it.
    claude_native_evidence: Option<ClaudeNativeEvidence>,
    managed_grok_selection: Option<ManagedGrokAccountSelectionEvidence>,
    managed_codex_selection: Option<FrozenCodexSelectedBinding>,
    managed_gemini_selection: Option<ManagedGeminiAccountSelectionEvidence>,
    managed_cursor_selection: Option<ManagedCursorAccountSelectionEvidence>,
}

/// Native successful end-turn, applied read-only filesystem and materialized held-output facts.
/// Requested controls are not native observations or arbiter qualification.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HeldGrokReadOnlyCompletionFacts {
    held_output_sha256: String,
    requested_model: Option<String>,
    requested_effort: Option<String>,
    /// Descriptive settled descriptor association, not qualified source or merge authority.
    delivered_pinned_descriptor_digest: Option<String>,
}

impl std::fmt::Debug for HeldGrokReadOnlyCompletionFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "HeldGrokReadOnlyCompletionFacts { held_output: [redacted], delivered_pin: [redacted], requested_controls: [redacted], observed_model: unavailable, observed_effort: unavailable, native_permissions: unavailable }",
        )
    }
}

#[cfg(test)]
impl HeldGrokReadOnlyCompletionFacts {
    pub(crate) fn held_output_sha256(&self) -> &str {
        &self.held_output_sha256
    }

    pub(crate) fn delivered_pinned_descriptor_digest(&self) -> Option<&str> {
        self.delivered_pinned_descriptor_digest.as_deref()
    }

    pub(crate) fn requested_model(&self) -> Option<&str> {
        self.requested_model.as_deref()
    }

    pub(crate) fn requested_effort(&self) -> Option<&str> {
        self.requested_effort.as_deref()
    }

    pub(crate) fn observed_model(&self) -> Option<&str> {
        None
    }

    pub(crate) fn observed_effort(&self) -> Option<&str> {
        None
    }

    pub(crate) fn native_permission_observation(&self) -> Option<&str> {
        None
    }
}

/// Called only after the production native parser, filesystem qualifier and both owned
/// output materializations succeeded. No command, environment or output-byte copy is retained.
fn retain_held_grok_read_only_completion_facts(
    report: &mut ExternalAgentRun,
    original_spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) {
    if runtime != ExternalExecutionRuntime::Verified
        || original_spec.invocation != ExternalAgentInvocation::Grok
        || original_spec.workspace_access != WorkspaceAccess::ReadOnly
        || grok_acp_stdio_protocol_selected(original_spec)
        || report
            .stdout
            .run_metadata
            .grok_read_only_filesystem
            .is_none()
        || !grok_filesystem_original_command_matches(report, original_spec)
        || report.exit_code != Some(0)
        || report.timed_out
        || report.error.is_some()
    {
        return;
    }
    let Some(held_output) = report.output_last_message.as_deref() else {
        return;
    };
    let delivered_pinned_descriptor_digest = report
        .stdout
        .run_metadata
        .grok_read_only_filesystem
        .as_ref()
        .and_then(|evidence| evidence.pinned_descriptor_digest())
        .map(str::to_owned);
    report.stdout.run_metadata.grok_read_only_completion_facts =
        Some(HeldGrokReadOnlyCompletionFacts {
            held_output_sha256: sha256_hex(held_output),
            requested_model: original_spec.model.clone(),
            requested_effort: original_spec.reasoning_effort.clone(),
            delivered_pinned_descriptor_digest,
        });
}

/// Full command binding and original native counters are private process custody,
/// not public report assertions. No Serialize/Deserialize implementation.
#[derive(Clone, PartialEq, Eq)]
struct GrokNativeUsageCapture {
    command: ExternalAgentCommand,
    observation: crate::runtime_adapter::grok::GrokNativeUsageObservation,
    process_completed: bool,
}

#[cfg(test)]
mod grok_native_custody_tests {
    use super::*;

    fn command() -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            "grok",
            ".",
            "prompt",
            "log",
            "report",
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            crate::runtime_adapter::RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(crate::runtime_adapter::RuntimeId::Grok),
        )
    }

    #[test]
    fn read_only_target_executable_pin_defaults_absent_and_is_not_run_wire_authority() -> Result<()>
    {
        let default_command = command();
        assert!(default_command.read_only_target_executable_pin.is_none());
        assert!(capture_read_only_target_executable_pin(
            &default_command,
            ExternalExecutionRuntime::Verified,
            Path::new("/unopened/default-target"),
        )?
        .is_none());
        let run = refused_external_run_before_launch(&default_command, "test fixture".to_string());
        let mut wire = serde_json::to_value(&run)?;
        assert!(wire.get("read_only_target_executable_pin").is_none());
        wire.as_object_mut().unwrap().insert(
            "read_only_target_executable_pin".into(),
            serde_json::json!("/forged/target"),
        );
        // A closed wire reader may reject the extra field; an accepting reader cannot mint facts.
        if let Ok(restored) = serde_json::from_value::<ExternalAgentRun>(wire) {
            assert!(restored.held_grok_read_only_completion_facts().is_none());
        }
        assert!(command().read_only_target_executable_pin.is_none());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_only_target_executable_pin_refuses_writable_acp_and_changed_program_context(
    ) -> Result<()> {
        let mut readonly = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        readonly.program = PathBuf::from("/unopened/grok");
        let pinned = readonly.clone().with_read_only_target_executable_pin()?;
        validate_read_only_target_executable_pin_mode(&pinned)?;
        let mut changed = pinned;
        changed.program = PathBuf::from("/unopened/foreign");
        assert!(capture_read_only_target_executable_pin(
            &changed,
            ExternalExecutionRuntime::Verified,
            &changed.program,
        )
        .is_err());
        assert!(readonly
            .clone()
            .with_workspace_access(WorkspaceAccess::ReadWrite)
            .with_read_only_target_executable_pin()
            .is_err());
        let mut acp = readonly.clone();
        acp.runtime_adapter
            .as_mut()
            .unwrap()
            .grok_interaction_protocol = crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        assert!(acp.with_read_only_target_executable_pin().is_err());
        let mut other = readonly.clone();
        other.invocation = ExternalAgentInvocation::CodexSupervisor;
        assert!(other.with_read_only_target_executable_pin().is_err());
        let pinned = readonly.with_read_only_target_executable_pin()?;
        assert!(capture_read_only_target_executable_pin(
            &pinned,
            ExternalExecutionRuntime::NonpublishableSimulation,
            &pinned.program,
        )
        .is_err());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn read_only_target_executable_pin_refuses_unsupported_platform() {
        let mut readonly = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        readonly.program = PathBuf::from("/unopened/grok");
        assert!(readonly.with_read_only_target_executable_pin().is_err());
    }

    fn capture() -> CapturedBytes {
        CapturedBytes::from_bytes_for_test(
            b"{\"type\":\"end\",\"stopReason\":\"stop\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":12,\"output_tokens\":5,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":3,\"total_tokens\":24}}\n".to_vec(),
        )
    }

    #[test]
    fn grok_readonly_headless_mcp_deny_preserves_writable_and_acp_argv() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let schema = temp.path().join("worker.schema.json");
        std::fs::write(&schema, br#"{"type":"object"}"#)?;
        for configured in [false, true] {
            let mut writable = command()
                .with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()))
                .with_workspace_access(WorkspaceAccess::ReadWrite);
            writable.output_schema = Some(schema.clone());
            if !configured {
                writable.runtime_adapter = None;
            }
            let config = writable
                .runtime_adapter
                .clone()
                .unwrap_or_else(|| RuntimeAdapterConfig::defaults(RuntimeId::Grok));
            let context = LaunchContext {
                prompt: &writable.prompt,
                model: writable.model.as_deref(),
                effort: writable.reasoning_effort.as_deref(),
                cwd: &writable.cwd,
                output: &writable.output_last_message,
            };
            let expected = config.render_grok_os_argv(&context, Some(&schema))?;
            assert_eq!(command_argv(&writable), expected);
            assert!(expected
                .windows(2)
                .any(|pair| { pair == [OsString::from("--model"), OsString::from("grok-4.6")] }));
            assert!(expected.windows(2).any(|pair| {
                pair == [
                    OsString::from("--reasoning-effort"),
                    OsString::from("xhigh"),
                ]
            }));
            let readonly = writable
                .clone()
                .with_workspace_access(WorkspaceAccess::ReadOnly);
            assert!(!grok_acp_stdio_protocol_selected(&readonly));
            let mut readonly_expected = expected;
            readonly_expected.extend([OsString::from("--deny"), OsString::from("MCPTool")]);
            assert_eq!(command_argv(&readonly), readonly_expected);
        }
        let mut acp = command()
            .with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()))
            .with_workspace_access(WorkspaceAccess::ReadWrite);
        acp.output_schema = Some(schema);
        acp.runtime_adapter
            .as_mut()
            .unwrap()
            .grok_interaction_protocol = crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        let context = LaunchContext {
            prompt: &acp.prompt,
            model: acp.model.as_deref(),
            effort: acp.reasoning_effort.as_deref(),
            cwd: &acp.cwd,
            output: &acp.output_last_message,
        };
        let expected = acp
            .runtime_adapter
            .as_ref()
            .unwrap()
            .render_grok_os_argv(&context, acp.output_schema.as_deref())?;
        assert!(grok_acp_stdio_protocol_selected(&acp));
        assert_eq!(command_argv(&acp), expected);
        let readonly = acp.with_workspace_access(WorkspaceAccess::ReadOnly);
        assert!(grok_acp_stdio_protocol_selected(&readonly));
        assert_eq!(command_argv(&readonly), expected);
        Ok(())
    }

    fn nested_writable_command(model: &str, schema: &Path) -> Result<ExternalAgentCommand> {
        let worker = "nested-worker";
        let owner = "parent";
        let workspace = Path::new("/managed/parent");
        let incoming = Path::new("/private/incoming");
        let binding = FrozenGrokSelectedBinding {
            authority_socket: None,
            authority_id: Some("authority".into()),
            provider_id: "grok-cli".into(),
            account_id: "account".into(),
            account_incarnation: "incarnation".into(),
            selection_revision: 7,
        };
        crate::account_authority::admit_grok_run_account_binding("run", Some(binding.clone()));
        let mut command = ExternalAgentCommand::codex(
            "/pinned/grok",
            workspace,
            "/private/prompt.md",
            "/private/events.jsonl",
            "/private/report.json",
            Duration::from_secs(17),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        )
        .with_model_selection(Some(model.into()), Some("xhigh".into()))
        .with_workspace_access(WorkspaceAccess::ReadWrite)
        .with_writable_launch_target(WritableLaunchTarget::ManagedChildWorktree)
        .with_agent_lifecycle("/repo", "worker", "run", worker)
        .with_agent_parent(owner)
        .with_worker_journal_artifact(
            worker,
            incoming,
            incoming.join("worker-journals/nested-worker.jsonl"),
        )
        .with_grok_run_account_binding(Some(binding));
        command.output_schema = Some(schema.to_path_buf());
        command.assignment_process_launch_kind = Some(AssignmentProcessLaunchKind::AssignmentChild);
        command.assignment_process_launch_attempt = Some(3);
        let command = command.with_writable_runtime_selection(worker, RuntimeId::Grok, true)?;
        let nested = NestedWorktreeWritableAdmission::from_live_assignment_authority(
            worker,
            owner,
            "run",
            3,
            3,
            owner,
            workspace,
            "maco/parent",
            owner,
            41,
            &[PathBuf::from("src")],
            &[PathBuf::from("src/worker.rs")],
            Some(19),
            NativeSandboxAdmission {
                runtime: RuntimeId::Grok,
                workspace_access: WorkspaceAccess::ReadWrite,
                side_effect_confinement: SideEffectConfinement::Verified,
            },
            &command.worker_journal_artifacts,
        )?;
        command.with_nested_worktree_writable_confinement(nested)
    }

    fn direct_writable_command_with_late_process_grant() -> Result<ExternalAgentCommand> {
        let worker = "ordinary-worker";
        let workspace = Path::new("/managed/ordinary-worker");
        let command = ExternalAgentCommand::codex(
            "/pinned/grok",
            workspace,
            "/private/prompt.md",
            "/private/events.jsonl",
            "/private/report.json",
            Duration::from_secs(17),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        )
        .with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()))
        .with_workspace_access(WorkspaceAccess::ReadWrite)
        .with_writable_launch_target(WritableLaunchTarget::ManagedChildWorktree)
        .with_agent_lifecycle("/repo", "worker", "run-direct", worker)
        .with_agent_parent("parent")
        .with_writable_runtime_selection(worker, RuntimeId::Grok, true)?
        .with_worktree_writable_confinement(direct_writable_admission(worker));
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            "run-direct",
            worker,
            3,
            Path::new("codex"),
            Some("grok-4.6"),
            crate::mutation_taxonomy::ASSIGNMENT_CHILD_PROCESS_DUTY,
        )?;
        Ok(command
            .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant))
    }

    fn direct_writable_admission(worker: &str) -> WorktreeWritableAdmission {
        WorktreeWritableAdmission {
            version: WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION,
            assignment_id: worker.into(),
            attempt: 3,
            target: WritableLaunchTarget::ManagedChildWorktree,
            worktree: ManagedWorktreeAdmission {
                kind: ManagedWorktreeAdmissionKind::ManagedDisposable,
                worktree_id: worker.into(),
            },
            claims: HeldPathClaimsAdmission {
                state: HeldPathClaimsAdmissionState::Held,
                token: 41,
                paths: vec![PathBuf::from("src")],
            },
            native_sandbox: NativeSandboxAdmission {
                runtime: RuntimeId::Grok,
                workspace_access: WorkspaceAccess::ReadWrite,
                side_effect_confinement: SideEffectConfinement::Verified,
            },
        }
    }

    fn direct_writable_command_with_finalized_messaging_then_proof_and_late_grant(
    ) -> Result<ExternalAgentCommand> {
        let worker = "ordinary-worker";
        let workspace = Path::new("/managed/ordinary-worker");
        let mut command = ExternalAgentCommand::codex(
            "/pinned/grok",
            workspace,
            "/private/prompt.md",
            "/private/events.jsonl",
            "/private/report.json",
            Duration::from_secs(17),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        )
        .with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()))
        .with_workspace_access(WorkspaceAccess::ReadWrite)
        .with_writable_launch_target(WritableLaunchTarget::ManagedChildWorktree)
        .with_agent_lifecycle("/repo", "worker", "run-direct", worker)
        .with_agent_parent("parent")
        .with_writable_runtime_selection(worker, RuntimeId::Grok, true)?;
        command.timeout = command.timeout.min(Duration::from_secs(9));
        let server = crate::messaging::transport::AssignmentMessagingServer::start(
            "run-direct",
            worker,
            |_| Ok(serde_json::json!({})),
        )?;
        let command = command
            .with_assignment_messaging(server.launch())
            .with_worktree_writable_confinement(direct_writable_admission(worker));
        drop(server);
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            "run-direct",
            worker,
            3,
            Path::new("codex"),
            Some("grok-4.6"),
            crate::mutation_taxonomy::ASSIGNMENT_CHILD_PROCESS_DUTY,
        )?;
        Ok(command
            .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant))
    }

    #[test]
    fn grok_filesystem_original_command_association_refuses_drift_without_usage_gate() {
        let original = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        let mut run = refused_external_run_before_launch(&original, "test refusal".into());
        // Absent usage does not invent an additional billing requirement for live custody.
        assert!(grok_filesystem_original_command_matches(&run, &original));
        run.retain_grok_native_usage_for_test(&original, &capture(), false);
        assert!(!run.authenticated_grok_usage(&original).unwrap().1);
        assert!(grok_filesystem_original_command_matches(&run, &original));
        let mut foreign = original.clone();
        foreign.output_last_message = "foreign-report".into();
        assert!(!grok_filesystem_original_command_matches(&run, &foreign));
        assert!(run.stdout.run_metadata.grok_read_only_filesystem.is_none());
    }

    #[test]
    fn readonly_grok_capture_refuses_public_and_wire_flags_without_losing_native_usage() {
        let command = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        let bytes = String::from_utf8(capture().as_bytes().to_vec())
            .unwrap()
            .replace(r#""stop""#, r#""end_turn""#)
            .into_bytes();
        let captured = CapturedBytes::from_bytes_for_test(bytes);
        let mut run = refused_external_run_before_launch(&command, "test refusal".into());
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::TrustedCompatibility,
        ));
        run.retain_grok_native_usage_for_test(&command, &captured, true);
        let parsed =
            runtime_adapter_captured_output(&command, captured.as_bytes(), b"", true).unwrap();
        assert!(matches!(parsed, RuntimeAdapterCapturedOutput::Captured(_)));
        assert_eq!(
            qualify_grok_read_only_capture(&command, &run, parsed)
                .unwrap_err()
                .to_string(),
            "Grok read-only captured output lacks matching settled filesystem evidence"
        );
        assert_eq!(
            run.authenticated_grok_usage(&command)
                .unwrap()
                .0
                .total_tokens,
            24
        );
        assert!(run.authenticated_grok_usage(&command).unwrap().1);
        replace_report_stdout(&mut run, CapturedOutput::default());
        assert!(run.stdout.run_metadata.grok_read_only_filesystem.is_none());
        assert_eq!(
            run.authenticated_grok_usage(&command)
                .unwrap()
                .0
                .total_tokens,
            24
        );
        let restored: ExternalAgentRun =
            serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert!(restored
            .stdout
            .run_metadata
            .grok_read_only_filesystem
            .is_none());
        assert!(qualify_grok_read_only_capture(
            &command,
            &restored,
            RuntimeAdapterCapturedOutput::Captured(b"done".to_vec()),
        )
        .is_err());
        assert!(!run.publishable);
    }

    #[test]
    fn filesystem_capture_gate_preserves_writable_acp_and_native_failure_accounting() {
        let writable = command().with_workspace_access(WorkspaceAccess::ReadWrite);
        let mut run = refused_external_run_before_launch(&writable, "test refusal".into());
        assert_eq!(
            qualify_grok_read_only_capture(
                &writable,
                &run,
                RuntimeAdapterCapturedOutput::Captured(b"done".to_vec()),
            )
            .unwrap(),
            RuntimeAdapterCapturedOutput::Captured(b"done".to_vec()),
        );
        let mut acp = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        acp.runtime_adapter
            .as_mut()
            .unwrap()
            .grok_interaction_protocol = crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        let parsed = runtime_adapter_captured_output(&acp, b"", b"", true).unwrap();
        assert_eq!(
            qualify_grok_read_only_capture(&acp, &run, parsed).unwrap(),
            RuntimeAdapterCapturedOutput::ExistingStagedOutput,
        );
        let readonly = command().with_workspace_access(WorkspaceAccess::ReadOnly);
        let bytes = String::from_utf8(capture().as_bytes().to_vec())
            .unwrap()
            .replace(r#""stop""#, r#""refusal""#)
            .into_bytes();
        let captured = CapturedBytes::from_bytes_for_test(bytes);
        run.retain_grok_native_usage_for_test(&readonly, &captured, true);
        let result = runtime_adapter_captured_output(&readonly, captured.as_bytes(), b"", true)
            .and_then(|parsed| qualify_grok_read_only_capture(&readonly, &run, parsed));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Grok runtime returned a non-success terminal streaming-json end event",
        );
        assert_eq!(
            run.authenticated_grok_usage(&readonly)
                .unwrap()
                .0
                .total_tokens,
            24
        );
        assert!(run.authenticated_grok_usage(&readonly).unwrap().1);
        assert!(!run.publishable);
    }

    #[test]
    fn grok_native_custody_survives_redaction_but_not_wire_roundtrip_or_command_drift() {
        let command = command();
        let mut run =
            refused_external_run_before_launch(&command, "test materialization failure".into());
        run.retain_grok_native_usage_for_test(&command, &capture(), true);
        replace_report_stdout(&mut run, CapturedOutput::default());
        assert_eq!(
            run.authenticated_grok_usage(&command)
                .unwrap()
                .0
                .total_tokens,
            24
        );
        assert!(!run.publishable, "accounting cannot promote publication");
        assert!(run.error.is_some());
        let restored: ExternalAgentRun =
            serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert!(restored.authenticated_grok_usage(&command).is_none());
        let mut rebound = command.clone();
        rebound.json_log = "other-log".into();
        assert!(run.authenticated_grok_usage(&rebound).is_none());
        rebound = command.clone();
        rebound.model = Some("different-request".into());
        assert!(run.authenticated_grok_usage(&rebound).is_none());
        rebound = command.clone();
        rebound.timeout += Duration::from_secs(1);
        assert!(run.authenticated_grok_usage(&rebound).is_none());
    }

    #[test]
    fn grok_native_custody_refuses_simulation_acp_and_foreign_invocations() {
        let command = command();
        let mut run = refused_external_run_before_launch(&command, "test".into());
        run.retain_grok_native_usage(
            &command,
            ExternalExecutionRuntime::NonpublishableSimulation,
            &capture(),
            true,
        );
        assert!(run.authenticated_grok_usage(&command).is_none());
        let mut acp = command.clone();
        acp.runtime_adapter
            .as_mut()
            .unwrap()
            .grok_interaction_protocol = crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        run.retain_grok_native_usage_for_test(&acp, &capture(), true);
        assert!(run.authenticated_grok_usage(&acp).is_none());
        let mut codex = command.clone();
        codex.invocation = ExternalAgentInvocation::CodexSupervisor;
        run.retain_grok_native_usage_for_test(&codex, &capture(), true);
        assert!(run.authenticated_grok_usage(&codex).is_none());
    }

    #[test]
    fn grok_stop_reason_gates_captured_reports_without_downgrading_native_accounting() {
        for reason in [
            "end_turn",
            "EndTurn",
            "max_tokens",
            "max_turn_requests",
            "refusal",
            "cancelled",
            "unknown_reason",
        ] {
            for structured in [false, true] {
                let mut command = command();
                if structured {
                    command.output_schema = Some("worker.schema.json".into());
                }
                let report = serde_json::json!({"status": "completed", "summary": "done"});
                let mut terminal = serde_json::json!({
                    "type": "end", "stopReason": reason, "sessionId": "s", "requestId": "r",
                    "usage": {"input_tokens": 12, "output_tokens": 5,
                        "cache_read_input_tokens": 4, "cache_creation_input_tokens": 3,
                        "total_tokens": 24}
                });
                if structured {
                    terminal["structuredOutput"] = report.clone();
                }
                let mut bytes = b"{\"type\":\"text\",\"data\":\"done\"}\n".to_vec();
                bytes.extend(serde_json::to_vec(&terminal).unwrap());
                bytes.push(b'\n');
                // true exercises the successful-process/exit-zero admission path.
                let captured = runtime_adapter_captured_output(&command, &bytes, b"", true);
                let expected_success = matches!(reason, "end_turn" | "EndTurn");
                if expected_success {
                    let RuntimeAdapterCapturedOutput::Captured(output) = captured.unwrap() else {
                        panic!("successful turn must supply captured output");
                    };
                    if structured {
                        assert_eq!(
                            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
                            report
                        );
                    } else {
                        assert_eq!(output, b"done");
                    }
                } else {
                    assert_eq!(
                        captured.unwrap_err().to_string(),
                        "Grok runtime returned a non-success terminal streaming-json end event"
                    );
                }
                let capture = CapturedBytes::from_bytes_for_test(bytes);
                let mut run = refused_external_run_before_launch(&command, "test refusal".into());
                run.retain_grok_native_usage_for_test(&command, &capture, true);
                let (usage, complete) = run.authenticated_grok_usage(&command).unwrap();
                assert_eq!(usage.total_tokens, 24);
                assert!(complete, "fully captured charged usage remains complete");
                assert!(!run.publishable, "accounting must not promote publication");
            }
        }
    }

    #[test]
    fn grok_native_custody_retains_cancelled_and_truncated_floors_without_completion() {
        let command = command();
        for (capture, process_completed) in [
            (capture(), false),
            (
                CapturedBytes::from_bytes_with_truncation_for_test(
                    capture().as_bytes().to_vec(),
                    true,
                ),
                true,
            ),
        ] {
            let mut run =
                refused_external_run_before_launch(&command, "cancelled or truncated".into());
            run.retain_grok_native_usage_for_test(&command, &capture, process_completed);
            let (usage, complete) = run.authenticated_grok_usage(&command).unwrap();
            assert_eq!(usage.total_tokens, 24);
            assert!(!complete);
            assert!(!run.publishable);
        }
    }

    #[test]
    fn nested_grok_confinement_binds_worker_parent_permit_cam_and_final_command() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let schema = temp.path().join("worker.schema.json");
        std::fs::write(&schema, br#"{"type":"object"}"#)?;
        for model in ["grok-4.6", "grok-4.7"] {
            let command = nested_writable_command(model, &schema)?;
            assert!(command
                .verified_writable_capabilities(RuntimeId::Grok)?
                .admits_worktree_writable());
        }

        let command = nested_writable_command("grok-4.6", &schema)?;

        for mutation in ["timeout", "journal", "cam", "worker", "protocol"] {
            let mut changed = command.clone();
            match mutation {
                "timeout" => changed.timeout += Duration::from_secs(1),
                "journal" => changed.worker_journal_artifacts[0].path = "/other/journal".into(),
                "cam" => changed.grok_run_account_binding = None,
                "worker" => changed.agent_lifecycle.as_mut().unwrap().task_id = "sibling".into(),
                "protocol" => {
                    changed
                        .runtime_adapter
                        .as_mut()
                        .unwrap()
                        .grok_interaction_protocol =
                        crate::runtime_adapter::GrokInteractionProtocol::AcpStdio
                }
                _ => unreachable!(),
            }
            assert!(
                changed
                    .verified_writable_capabilities(RuntimeId::Grok)
                    .is_err(),
                "nested proof accepted {mutation} substitution"
            );
        }

        let mut acp = command.clone();
        let nested = match acp.worktree_writable_confinement.take().unwrap().authority {
            WorktreeWritableConfinementAuthority::Nested(nested) => *nested,
            WorktreeWritableConfinementAuthority::Direct(_) => unreachable!(),
        };
        acp.runtime_adapter
            .as_mut()
            .unwrap()
            .grok_interaction_protocol = crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        let acp = acp.with_writable_runtime_selection("nested-worker", RuntimeId::Grok, true)?;
        assert!(acp
            .with_nested_worktree_writable_confinement(nested)
            .is_err());
        crate::account_authority::admit_grok_run_account_binding("run", None);
        Ok(())
    }

    #[test]
    fn direct_grok_confinement_accepts_late_sealed_process_grant_and_rejects_drift() -> Result<()> {
        let command = direct_writable_command_with_late_process_grant()?;
        assert!(command
            .verified_writable_capabilities(RuntimeId::Grok)?
            .admits_worktree_writable());
        command.verify_assignment_child_admission_identity()?;

        let mut changed = command.clone();
        changed.timeout += Duration::from_secs(1);
        assert!(changed
            .verified_writable_capabilities(RuntimeId::Grok)
            .is_err());

        let mut forged_grant = command;
        forged_grant.assignment_process_launch_duty = Some("forged-duty".into());
        assert!(forged_grant
            .verify_assignment_child_admission_identity()
            .is_err());
        Ok(())
    }

    #[test]
    fn direct_grok_confinement_accepts_finalized_messaging_timeout_then_proof_and_rejects_post_seal_drift(
    ) -> Result<()> {
        let command = direct_writable_command_with_finalized_messaging_then_proof_and_late_grant()?;
        assert!(command
            .verified_writable_capabilities(RuntimeId::Grok)?
            .admits_worktree_writable());
        command.verify_assignment_child_admission_identity()?;

        for mutation in [
            "messaging",
            "timeout",
            "lifecycle",
            "account",
            "socket",
            "prompt",
            "output",
            "protocol",
        ] {
            let mut changed = command.clone();
            match mutation {
                "messaging" => {
                    let drifted = crate::messaging::transport::AssignmentMessagingServer::start(
                        "run-direct",
                        "ordinary-worker",
                        |_| Ok(serde_json::json!({})),
                    )?;
                    changed = changed.with_assignment_messaging(drifted.launch());
                }
                "timeout" => changed.timeout += Duration::from_secs(1),
                "lifecycle" => changed.agent_lifecycle.as_mut().unwrap().task_id = "sibling".into(),
                "account" => {
                    changed.grok_run_account_binding = Some(FrozenGrokSelectedBinding {
                        authority_socket: None,
                        authority_id: Some("authority".into()),
                        provider_id: "grok-cli".into(),
                        account_id: "account".into(),
                        account_incarnation: "incarnation".into(),
                        selection_revision: 7,
                    })
                }
                "socket" => {
                    changed = changed
                        .with_cam_authority_socket_pin(Some("/tmp/maco-authority.sock".into()))
                }
                "prompt" => changed.prompt = "/private/other-prompt.md".into(),
                "output" => changed.output_last_message = "/private/other-report.json".into(),
                "protocol" => {
                    changed
                        .runtime_adapter
                        .as_mut()
                        .unwrap()
                        .grok_interaction_protocol =
                        crate::runtime_adapter::GrokInteractionProtocol::AcpStdio
                }
                _ => unreachable!(),
            }
            assert!(
                changed
                    .verified_writable_capabilities(RuntimeId::Grok)
                    .is_err(),
                "direct proof accepted {mutation} substitution"
            );
        }
        Ok(())
    }

    #[test]
    fn nested_grok_confinement_refuses_relabelled_parent_and_widened_worker() {
        let journal = WorkerJournalArtifactSpec {
            worker_id: "worker".into(),
            incoming_root: "/incoming".into(),
            path: "/incoming/worker.jsonl".into(),
        };
        for (owner, worker_paths) in [
            ("worker", vec![PathBuf::from("src/worker.rs")]),
            ("parent", vec![PathBuf::from("outside.rs")]),
        ] {
            assert!(
                NestedWorktreeWritableAdmission::from_live_assignment_authority(
                    "worker",
                    owner,
                    "run",
                    1,
                    1,
                    owner,
                    Path::new("/managed/parent"),
                    "maco/parent",
                    owner,
                    1,
                    &[PathBuf::from("src")],
                    &worker_paths,
                    None,
                    NativeSandboxAdmission {
                        runtime: RuntimeId::Grok,
                        workspace_access: WorkspaceAccess::ReadWrite,
                        side_effect_confinement: SideEffectConfinement::Verified,
                    },
                    std::slice::from_ref(&journal),
                )
                .is_err()
            );
        }
    }
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
    /// Process-capture loss, independent of the shorter public display text.
    /// Only the live capture path can attest to this private provenance.
    #[serde(skip, default)]
    raw_truncated: Option<bool>,
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "default_target_launch_attempted"
    )]
    pub(crate) target_launch_attempted: bool,
    /// Private held metadata for the enclosing run. It is serialized only by
    /// `ExternalAgentRun` as the top-level `sandbox_denials` wire field.
    #[serde(skip, default)]
    run_metadata: Box<ExternalAgentRunMetadata>,
}

impl CapturedOutput {
    pub(crate) fn raw_capture_truncated(&self) -> bool {
        // Deserialized and legacy captures lack private provenance. Preserve
        // their conservative interpretation of the public truncation flag.
        self.raw_truncated.unwrap_or(self.truncated)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn from_captured_bytes_for_test(output: &CapturedBytes) -> Self {
        summarize_redacted_output(output, &CredentialRedactor::default())
    }
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

struct AdmittedGrokCredentials {
    #[cfg(target_os = "linux")]
    source: GrokCredentialSource,
}

/// Retains the admitted source and the exact profile produced by its successful binding.
/// Neither a pathname nor a profile kind alone proves that the child receives Grok auth.
struct BoundGrokCredentials<'a> {
    credentials: &'a AdmittedGrokCredentials,
    profile: ExternalGrokProfile,
}

impl<'a> BoundGrokCredentials<'a> {
    fn new(credentials: &'a AdmittedGrokCredentials, profile: ExternalGrokProfile) -> Result<Self> {
        Ok(Self {
            credentials,
            profile: credentials.bind_to_profile(profile)?,
        })
    }

    fn present_in(&self, profile: &SideEffectConfinementProfile) -> bool {
        let SideEffectConfinementProfile::ExternalGrok(profile) = profile else {
            return false;
        };
        // Binding revalidates the held descriptors against their original path identities.
        // Discard the new profile: preflight must not add access to the actual launch profile.
        *profile == self.profile && self.credentials.bind_to_profile(profile.clone()).is_ok()
    }
}

impl AdmittedGrokCredentials {
    #[cfg(target_os = "linux")]
    fn from_managed_grok_home(grok_home: &Path) -> Result<Self> {
        Ok(Self {
            source: GrokCredentialSource::from_environment(None, Some(grok_home.as_os_str()))?,
        })
    }

    fn grok_home_environment(&self) -> Result<&str> {
        #[cfg(target_os = "linux")]
        {
            Ok(self.source.grok_home_environment())
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("Grok credential capability confinement requires Linux");
        }
    }

    fn bind_to_profile(&self, profile: ExternalGrokProfile) -> Result<ExternalGrokProfile> {
        #[cfg(target_os = "linux")]
        {
            self.source.bind_to_profile(profile)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = profile;
            bail!("Grok credential capability confinement requires Linux");
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    fn from_environment(
        ambient_home: Option<&OsStr>,
        ambient_grok_home: Option<&OsStr>,
    ) -> Result<Self> {
        Ok(Self {
            source: GrokCredentialSource::from_environment(ambient_home, ambient_grok_home)?,
        })
    }
}

#[cfg(target_os = "linux")]
struct GrokVerifiedAccountSession {
    authority: crate::account_authority::GrokLaunchAuthority,
    credentials: AdmittedGrokCredentials,
}

#[cfg(target_os = "linux")]
struct ClaudeVerifiedAccountSession {
    authority: crate::account_authority::ClaudeLaunchAuthority,
    deadline_unix_millis: u64,
    helper_registration_nonce: String,
    containment_owner: ClaudeContainmentOwnerBinding,
}

#[cfg(target_os = "linux")]
fn prepare_verified_grok_account_session(
    spec: &ExternalAgentCommand,
) -> Result<GrokVerifiedAccountSession> {
    let frozen = spec.grok_run_account_binding.as_ref();
    let authority = crate::account_authority::grok::acquire_grok_launch_authority(frozen)?;
    if let Some(frozen) = frozen {
        let evidence = authority.selection_evidence();
        if !frozen.matches_selection_evidence(&evidence) {
            bail!(
                "managed Grok selection does not match the frozen selected binding used for selection"
            );
        }
        if frozen.authority_id.is_some() && evidence.authority_id != frozen.authority_id {
            bail!(
                "managed Grok selection authority does not match the frozen selected authority used for selection"
            );
        }
    }
    let credentials =
        AdmittedGrokCredentials::from_managed_grok_home(authority.managed_grok_home())?;
    Ok(GrokVerifiedAccountSession {
        authority,
        credentials,
    })
}

#[cfg(target_os = "linux")]
fn prepare_verified_claude_account_session(
    spec: &ExternalAgentCommand,
    remaining: Duration,
) -> Result<ClaudeVerifiedAccountSession> {
    let deadline_unix_millis = unix_deadline_millis(remaining)?;
    let frozen = spec.claude_run_account_binding.as_ref();
    let authority = crate::account_authority::claude::acquire_claude_launch_authority(
        frozen,
        deadline_unix_millis,
    )?;
    if let Some(frozen) = frozen {
        let evidence = authority.selection_evidence();
        if evidence.provider_id != frozen.provider_id
            || evidence.account_id != frozen.account_id
            || evidence.account_incarnation != frozen.account_incarnation
            || evidence.selection_revision != frozen.selection_revision
            || (frozen.authority_id.is_some() && evidence.authority_id != frozen.authority_id)
        {
            bail!("managed Claude selection does not match the frozen selected binding");
        }
    }
    Ok(ClaudeVerifiedAccountSession {
        authority,
        deadline_unix_millis,
        helper_registration_nonce: private_parent_nonce()?,
        containment_owner: ClaudeContainmentOwnerBinding::new(),
    })
}

#[cfg(target_os = "linux")]
fn unix_deadline_millis(remaining: Duration) -> Result<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?;
    let deadline = now
        .checked_add(remaining)
        .context("Claude launch deadline overflowed")?;
    u64::try_from(deadline.as_millis()).context("Claude launch deadline does not fit u64")
}

#[cfg(target_os = "linux")]
fn private_parent_nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .context("failed to open the kernel random source for Claude relay binding")?
        .read_exact(&mut bytes)
        .context("failed to read the Claude relay parent nonce")?;
    Ok(sha256_hex(&bytes))
}

#[cfg(target_os = "linux")]
struct CursorVerifiedAccountSession {
    authority: crate::account_authority::CursorLaunchAuthority,
}

#[cfg(target_os = "linux")]
fn prepare_verified_cursor_account_session(
    spec: &ExternalAgentCommand,
) -> Result<CursorVerifiedAccountSession> {
    let frozen = spec.cursor_run_account_binding.as_ref();
    let authority = crate::account_authority::cursor::acquire_cursor_launch_authority(frozen)?;
    if let Some(frozen) = frozen {
        let evidence = authority.selection_evidence();
        if !frozen.matches_selection_evidence(&evidence) {
            bail!(
                "managed Cursor selection does not match the frozen selected binding used for selection"
            );
        }
    }
    Ok(CursorVerifiedAccountSession { authority })
}

pub fn run_external_agent(spec: &ExternalAgentCommand) -> ExternalAgentRun {
    run_external_agent_cancellable(spec, &ProcessCancellation::new())
}

/// Run one verified external-agent invocation against an isolated CAM Grok registry.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn run_external_agent_with_cam_grok_test_harness(
    harness: crate::account_authority::CamGrokTestHarness,
    spec: &ExternalAgentCommand,
) -> ExternalAgentRun {
    let guard = crate::account_authority::activate_cam_grok_test_harness(harness);
    let report = run_external_agent(spec);
    drop(guard);
    report
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

fn assignment_process_launch_refusal(error: AssignmentProcessLaunchGrantError) -> String {
    format!("assignment process launch grant failed closed: {error}")
}

fn consult_consultant_invocation_requires_process_grant(
    invocation: ExternalAgentInvocation,
) -> bool {
    matches!(
        invocation,
        ExternalAgentInvocation::CodexConsultant | ExternalAgentInvocation::ClaudeConsultant
    )
}

fn assignment_process_launch_kind_allowed_for_invocation(
    kind: AssignmentProcessLaunchKind,
    spec: &ExternalAgentCommand,
) -> bool {
    match kind {
        AssignmentProcessLaunchKind::ConsultCodex => {
            matches!(spec.invocation, ExternalAgentInvocation::CodexConsultant)
        }
        AssignmentProcessLaunchKind::ConsultClaude => {
            matches!(spec.invocation, ExternalAgentInvocation::ClaudeConsultant)
        }
        AssignmentProcessLaunchKind::ConsultGemini => {
            spec.uses_gemini_bridge()
                && spec.workspace_access == WorkspaceAccess::ReadOnly
                && spec
                    .agent_lifecycle
                    .as_ref()
                    .is_some_and(|identity| identity.role == "researcher")
        }
        AssignmentProcessLaunchKind::InboxIndependentAuditor => matches!(
            spec.invocation,
            ExternalAgentInvocation::CodexConsultant | ExternalAgentInvocation::CodexSupervisor
        ),
        AssignmentProcessLaunchKind::AssignmentChild
        | AssignmentProcessLaunchKind::ParentAuditor => match spec.invocation {
            ExternalAgentInvocation::CodexSupervisor
            | ExternalAgentInvocation::Grok
            | ExternalAgentInvocation::Cursor
            | ExternalAgentInvocation::ClaudeCode
            | ExternalAgentInvocation::GeminiCli => true,
            ExternalAgentInvocation::CodexConsultant
            | ExternalAgentInvocation::ClaudeConsultant => false,
        },
        AssignmentProcessLaunchKind::MergeArbiter => {
            if spec.selected_merge_arbiter.is_some() {
                validate_selected_merge_command(spec).is_ok()
            } else {
                matches!(spec.invocation, ExternalAgentInvocation::CodexSupervisor)
                    && merge_arbiter_command_is_merge_shaped(spec)
            }
        }
    }
}

fn merge_arbiter_command_is_merge_shaped(spec: &ExternalAgentCommand) -> bool {
    spec.workspace_access == WorkspaceAccess::ReadOnly
        && spec
            .hidden_roots
            .iter()
            .any(|root| !root.as_os_str().is_empty())
        && spec.agent_lifecycle.as_ref().is_some_and(|identity| {
            identity.role == AgentRole::Auditor.as_str()
                && !identity.run_id.is_empty()
                && !identity.task_id.is_empty()
        })
}

fn refuse_assignment_process_launch_before_preflight(
    spec: &ExternalAgentCommand,
) -> Result<(), AssignmentProcessLaunchGrantError> {
    let kind = match spec.assignment_process_launch_kind {
        Some(kind) => kind,
        None => {
            if consult_consultant_invocation_requires_process_grant(spec.invocation) {
                return Err(AssignmentProcessLaunchGrantError::MissingGrant);
            }
            return Ok(());
        }
    };
    if !assignment_process_launch_kind_allowed_for_invocation(kind, spec) {
        return Err(AssignmentProcessLaunchGrantError::KindMismatch);
    }
    let Some(grant) = spec.assignment_process_launch_grant.as_ref() else {
        return Err(AssignmentProcessLaunchGrantError::MissingGrant);
    };
    if grant.kind() != kind {
        return Err(AssignmentProcessLaunchGrantError::KindMismatch);
    }
    let run_id = spec
        .agent_lifecycle
        .as_ref()
        .map(|identity| identity.run_id.as_str())
        .unwrap_or("");
    let subject = spec
        .agent_lifecycle
        .as_ref()
        .map(|identity| identity.task_id.as_str())
        .unwrap_or("");
    let attempt = spec.assignment_process_launch_attempt.unwrap_or(usize::MAX);
    let duty = spec.assignment_process_launch_duty.as_deref().unwrap_or("");
    if grant.run_id() != run_id
        || grant.subject() != subject
        || grant.attempt() != attempt
        || grant.model() != spec.model.as_deref()
        || grant.duty() != duty
    {
        return Err(AssignmentProcessLaunchGrantError::IdentityMismatch);
    }
    Ok(())
}

fn seal_assignment_process_launch_grant(
    spec: &ExternalAgentCommand,
    resolved_program: &Path,
    argv: &[OsString],
    output_staging: &Path,
    cwd: &Path,
) -> Result<Option<AssignmentProcessLaunchGrant>, AssignmentProcessLaunchGrantError> {
    if spec.assignment_process_launch_kind.is_none() {
        return Ok(None);
    }
    let Some(grant) = spec.assignment_process_launch_grant.clone() else {
        return Err(AssignmentProcessLaunchGrantError::MissingGrant);
    };
    if let Some(admission) = &spec.selected_merge_arbiter {
        validate_selected_merge_command(spec)
            .map_err(|_| AssignmentProcessLaunchGrantError::IdentityMismatch)?;
        return Ok(Some(grant.seal_selected_merge_canonical_binding(
            admission,
            resolved_program,
            argv.iter(),
            output_staging,
            cwd,
        )?));
    }
    Ok(Some(grant.seal_independently_verified_canonical_binding(
        resolved_program,
        argv.iter(),
        output_staging,
        cwd,
    )?))
}

fn consume_assignment_process_launch_grant(
    spec: &ExternalAgentCommand,
    grant: AssignmentProcessLaunchGrant,
    process_spec: &mut ProcessSpec,
    output_staging: &Path,
) -> Result<(), AssignmentProcessLaunchGrantError> {
    let Some(kind) = spec.assignment_process_launch_kind else {
        return Ok(());
    };
    if spec.selected_merge_arbiter.is_some() {
        validate_selected_merge_command(spec)
            .map_err(|_| AssignmentProcessLaunchGrantError::IdentityMismatch)?;
    }
    let ProcessCommand::Direct { program, args } = &process_spec.command else {
        return Err(AssignmentProcessLaunchGrantError::ProgramMismatch);
    };
    let program = program.clone();
    let args = args.clone();
    let current_dir = process_spec.current_dir.clone();
    let run_id = spec
        .agent_lifecycle
        .as_ref()
        .map(|identity| identity.run_id.as_str())
        .unwrap_or("");
    let subject = spec
        .agent_lifecycle
        .as_ref()
        .map(|identity| identity.task_id.as_str())
        .unwrap_or("");
    let attempt = spec.assignment_process_launch_attempt.unwrap_or(usize::MAX);
    let duty = spec.assignment_process_launch_duty.as_deref().unwrap_or("");
    let lifecycle_role = spec
        .agent_lifecycle
        .as_ref()
        .map(|identity| identity.role.as_str())
        .unwrap_or("");
    if spec
        .model
        .as_deref()
        .is_some_and(crate::agent_lifecycle::model_requires_mechanical_executor_proof)
        && grant.mechanical_executor().is_none()
    {
        return Err(AssignmentProcessLaunchGrantError::MechanicalExecutorMissing);
    }
    if grant.mechanical_executor().is_some() {
        if lifecycle_role != "worker" {
            return Err(AssignmentProcessLaunchGrantError::MechanicalExecutorMismatch);
        }
        if grant.mechanical_duty() != spec.assignment_mechanical_executor_duty {
            return Err(AssignmentProcessLaunchGrantError::MechanicalExecutorMismatch);
        }
    }
    let actual_mechanical = spec
        .assignment_mechanical_executor_duty
        .map(|mechanical_duty| {
            AssignmentProcessMechanicalBinding::worker(mechanical_duty, lifecycle_role)
        });
    let proof = grant.consume_for_process_binding(
        &program,
        &current_dir,
        &args,
        output_staging,
        run_id,
        subject,
        attempt,
        kind,
        spec.model.as_deref(),
        duty,
        actual_mechanical,
    )?;
    if let Some(proof) = proof {
        process_spec.attach_consumed_mechanical_executor_proof(proof);
    }
    Ok(())
}

fn validate_role_execution_evidence_before_launch(
    policy: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
    role: Option<&str>,
) -> std::result::Result<(), &'static str> {
    use crate::selection::routing_policy::RoleExecutionEvidenceResolution;
    let Some(policy) = policy else {
        return Ok(());
    };
    let explicit = policy
        .policy
        .default_role
        .execution_evidence_requirements
        .is_some()
        || policy
            .policy
            .role_preferences
            .values()
            .any(|preference| preference.execution_evidence_requirements.is_some());
    let Some(role) = role.filter(|role| !role.trim().is_empty()) else {
        return if explicit {
            Err("explicit role execution evidence requires an exact lifecycle role binding")
        } else {
            Ok(())
        };
    };
    let resolved = policy
        .resolve_role_execution_evidence(role)
        .map_err(|_| "role execution evidence policy binding is invalid")?;
    match resolved.resolution() {
        RoleExecutionEvidenceResolution::LegacyStrict => Ok(()),
        RoleExecutionEvidenceResolution::Required(_) => {
            Err("required role execution evidence is unsupported or unqualified before launch")
        }
    }
}

fn run_external_agent_runtime(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
    cancellation: &ProcessCancellation,
    mut review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    let started = Instant::now();
    let reservation_check = if spec.uses_live_claude_managed_worker_budget() {
        spec.verified_claude_managed_reservation()
    } else {
        spec.verified_live_token_grant()
    };
    if let Err(error) = reservation_check {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            error,
        );
    }
    if cancellation.is_cancelled() {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            "external agent was cancelled before executable preflight".to_string(),
        );
    }
    if spec.selected_merge_arbiter.is_some() {
        let qualification = validate_selected_merge_command(spec).and_then(|()| {
            if spec.invocation != ExternalAgentInvocation::CodexSupervisor {
                bail!("selected merge native observed controls and source-qualified permissions are unavailable");
            }
            Ok(())
        });
        if let Err(error) = qualification {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                EnvironmentFailureCategory::SandboxUnavailable,
                None,
                error.to_string(),
            );
        }
    }
    let active_policy = crate::selection::routing_policy::current_routing_policy();
    if let Err(error) = validate_role_execution_evidence_before_launch(
        active_policy.as_ref(),
        spec.agent_lifecycle
            .as_ref()
            .map(|identity| identity.role.as_str()),
    ) {
        return failed_external_environment_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            EnvironmentFailureCategory::SandboxUnavailable,
            None,
            error.to_string(),
        );
    }
    if let Err(error) = researcher_inputs::validate_command(spec) {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            format!("Researcher source input preparation refused: {error:#}"),
        );
    }
    if let Err(error) = refuse_assignment_process_launch_before_preflight(spec) {
        return failed_external_run(
            spec,
            started,
            command_display(&spec.program, &[]),
            false,
            assignment_process_launch_refusal(error),
        );
    }
    if spec.workspace_access == WorkspaceAccess::ReadWrite {
        if let Some(adapter) = spec.invocation.adapter_id() {
            let managed_native_runtime = match adapter {
                AdapterId::Grok => Some(RuntimeId::Grok),
                AdapterId::ClaudeCode => Some(RuntimeId::ClaudeCode),
                AdapterId::GeminiCli => Some(RuntimeId::GeminiCli),
                AdapterId::Cursor => Some(RuntimeId::Cursor),
                _ => None,
            };
            let capabilities =
                if spec.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree {
                    match managed_native_runtime
                        .map(|runtime| spec.verified_writable_capabilities(runtime))
                        .transpose()
                    {
                        Ok(Some(capabilities)) => capabilities,
                        Ok(None) => adapter.capabilities(),
                        Err(error) => {
                            return failed_external_environment_run(
                                spec,
                                started,
                                command_display(&spec.program, &[]),
                                false,
                                EnvironmentFailureCategory::SandboxUnavailable,
                                Some(external_sandbox_requirement(spec.invocation)),
                                format!(
                                    "writable {} failed closed before launch: {error:#}",
                                    adapter.as_str()
                                ),
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
                    Some(external_sandbox_requirement(spec.invocation)),
                    format!(
                        "writable {} failed closed before launch: {capability}",
                        adapter.as_str()
                    ),
                );
            }
        }
    }
    if spec.uses_gemini_bridge() && runtime == ExternalExecutionRuntime::Verified {
        return gemini_bridge::run(spec, cancellation, started);
    }
    // Hosted duplex review is optional defense-in-depth. Isolated worktree
    // children launch with native permission/sandbox mode; they are not
    // blocked on a parent All-callback or a missing reviewer.
    let duplex_review_required = should_use_duplex_review(spec, runtime, review_runtime.is_some());
    let managed_readonly_app_server = match classify_managed_readonly_app_server(spec, runtime) {
        Ok(route) => route,
        Err(error) => {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(external_sandbox_requirement(spec.invocation)),
                error,
            );
        }
    };
    let read_only_terminal_app_server = managed_readonly_app_server.is_none()
        && should_use_read_only_terminal_app_server(spec, runtime);
    let read_only_codex_app_server =
        read_only_terminal_app_server || managed_readonly_app_server.is_some();
    let managed_worker_app_server = match classify_managed_worker_app_server(spec, runtime) {
        Ok(selected) => selected,
        Err(error) => {
            return failed_external_environment_run(
                spec,
                started,
                command_display(&spec.program, &[]),
                false,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(external_sandbox_requirement(spec.invocation)),
                error,
            );
        }
    };
    let app_server_required =
        duplex_review_required || read_only_codex_app_server || managed_worker_app_server;
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
                Some(external_sandbox_requirement(spec.invocation)),
                error.to_string(),
            );
        }
    }
    let selected_program = match resolve_external_program(&spec.program, &spec.cwd) {
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
    #[cfg(target_os = "linux")]
    let cursor_install = if spec.invocation == ExternalAgentInvocation::Cursor {
        match crate::runtime_adapter::cursor_managed_parent::CursorManagedInstall::bind(
            &selected_program,
        ) {
            Ok(binding) => Some(binding),
            Err(error) => {
                return failed_external_environment_run(
                    spec,
                    started,
                    command_display(&selected_program, &[]),
                    false,
                    EnvironmentFailureCategory::SandboxUnavailable,
                    Some(external_sandbox_requirement(spec.invocation)),
                    format!("managed Cursor source binding failed closed: {error:#}"),
                );
            }
        }
    } else {
        None
    };
    let resolved_program = {
        #[cfg(target_os = "linux")]
        {
            cursor_install.as_ref().map_or_else(
                || selected_program.clone(),
                |install| install.node().to_path_buf(),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            selected_program.clone()
        }
    };
    let program_trust = external_program_trust_for_resolved_executable(spec, &resolved_program);
    if (read_only_codex_app_server || managed_worker_app_server)
        && program_trust != ExternalProgramTrust::TrustedSystemCodex
    {
        let route = if read_only_terminal_app_server {
            "read-only terminal Codex app-server"
        } else if managed_worker_app_server {
            "managed writable Worker Codex app-server"
        } else {
            "managed read-only Codex app-server"
        };
        return failed_external_environment_run(
            spec, started, command_display(&resolved_program, &[]), false,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(external_sandbox_requirement(spec.invocation)),
            format!("{route} requires a verified TrustedSystemCodex executable; custom transcripts cannot confer command evidence"),
        );
    }
    if let Err(error) = validate_managed_readonly_execute_binding(spec, managed_readonly_app_server)
    {
        return failed_external_environment_run(
            spec,
            started,
            command_display(&resolved_program, &[]),
            false,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(external_sandbox_requirement(spec.invocation)),
            error,
        );
    }
    let read_only_target_executable_pin =
        match capture_read_only_target_executable_pin(spec, runtime, &resolved_program) {
            Ok(pin) => pin,
            Err(error) => {
                return failed_external_environment_run(
                    spec,
                    started,
                    command_display(&resolved_program, &[]),
                    false,
                    EnvironmentFailureCategory::ProbeFailed,
                    None,
                    format!("read-only target executable pin preparation refused: {error}"),
                );
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
                Some(external_sandbox_requirement(spec.invocation)),
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
    // Supervisor launches keep their Codex session state in a parent-owned home below the
    // staging root so model, effort, and usage evidence survives unit teardown. Consultants
    // stay on `--ephemeral` and the RuntimeDirectory home: they intentionally yield no rollout.
    let staged_codex_home = if spec.invocation == ExternalAgentInvocation::CodexSupervisor {
        match output_staging.stage_codex_home() {
            Ok(path) => Some(path.to_path_buf()),
            Err(error) => {
                return failed_external_run(
                    spec,
                    started,
                    command_display(&resolved_program, &[]),
                    false,
                    format!("failed to prepare the parent-owned Codex home: {error:#}"),
                );
            }
        }
    } else {
        None
    };
    // App-server argv stays empty until the contained version probe matches the audited
    // app-server protocol. This remains a mandatory latent release gate even if
    // universal pre-action coverage becomes available in a future Codex protocol.
    let mut argv = if app_server_required {
        Vec::new()
    } else {
        match if target_spec.invocation == ExternalAgentInvocation::Cursor {
            #[cfg(target_os = "linux")]
            {
                cursor_managed_argv(
                    &target_spec,
                    cursor_install
                        .as_ref()
                        .expect("Cursor install bound before output staging"),
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(anyhow::anyhow!("managed Cursor launch requires Linux"))
            }
        } else {
            command_argv_with_controls(&target_spec, &target_controls)
        } {
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
    let mut bound_argv_digest = if app_server_required {
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
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        cursor_managed_parent_evidence: None,
        codex_parent_evidence: None,
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
    let grok_acp_prompt = if grok_acp_stdio_protocol_selected(&target_spec) {
        match String::from_utf8(prompt.clone()) {
            Ok(prompt) => Some(prompt),
            Err(_) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "Grok ACP stdio prompt is not valid UTF-8".to_string(),
                );
                return report;
            }
        }
    } else {
        None
    };

    if runtime == ExternalExecutionRuntime::Verified
        && spec.codex_run_account_binding.is_some()
        && program_trust != ExternalProgramTrust::TrustedSystemCodex
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "selected managed Codex execution requires the validated trusted Codex program"
                .to_string(),
        );
        return report;
    }
    let codex_auth = if runtime == ExternalExecutionRuntime::Verified
        && program_trust == ExternalProgramTrust::TrustedSystemCodex
    {
        match ValidatedCodexAuth::load_for_command(spec) {
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

    #[cfg(target_os = "linux")]
    if let Some(authority) = codex_auth
        .as_ref()
        .and_then(|auth| auth.managed_authority.as_ref())
    {
        report.stdout.run_metadata.managed_codex_selection = Some(authority.selection_evidence());
    }

    #[cfg(target_os = "linux")]
    let grok_session = if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Grok
    {
        match prepare_verified_grok_account_session(spec) {
            Ok(session) => {
                report.stdout.run_metadata.managed_grok_selection =
                    Some(session.authority.selection_evidence());
                Some(session)
            }
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_grok_credential_environment_failure(&mut report, &error);
                return report;
            }
        }
    } else {
        None
    };
    if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Grok
    {
        #[cfg(not(target_os = "linux"))]
        {
            report.duration_ms = duration_millis(started.elapsed());
            record_grok_credential_environment_failure(
                &mut report,
                &anyhow::anyhow!("Grok credential capability confinement requires Linux"),
            );
            return report;
        }
    }
    #[cfg(target_os = "linux")]
    let grok_credentials = grok_session.as_ref().map(|session| &session.credentials);
    #[cfg(not(target_os = "linux"))]
    let grok_credentials: Option<&AdmittedGrokCredentials> = None;

    #[cfg(target_os = "linux")]
    let mut claude_session = if runtime == ExternalExecutionRuntime::Verified
        && spec.uses_live_claude_managed_worker_budget()
    {
        match prepare_verified_claude_account_session(
            spec,
            spec.timeout.saturating_sub(started.elapsed()),
        ) {
            Ok(session) => Some(session),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_environment_failure(
                    &mut report,
                    EnvironmentFailureCategory::MissingCredential,
                    Some(EnvironmentRequirement::credential(
                        EnvironmentCredential::ClaudeManagedOAuth,
                    )),
                    format!("managed Claude OAuth authority failed closed: {error:#}"),
                );
                return report;
            }
        }
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let mut claude_session: Option<()> = None;
    if runtime == ExternalExecutionRuntime::Verified
        && spec.uses_live_claude_managed_worker_budget()
        && !cfg!(target_os = "linux")
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(external_sandbox_requirement(spec.invocation)),
            "managed Claude OAuth relay requires Linux".to_string(),
        );
        return report;
    }

    #[cfg(target_os = "linux")]
    let claude_relay_directory = if claude_session.is_some() {
        match tempfile::Builder::new()
            .prefix("maco-claude-parent-relay-")
            .tempdir()
        {
            Ok(directory) => Some(directory),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("managed Claude parent relay directory failed: {error}"),
                );
                return report;
            }
        }
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let claude_parent_socket = claude_relay_directory
        .as_ref()
        .map(|directory| directory.path().join("relay.sock"));
    #[cfg(not(target_os = "linux"))]
    let claude_parent_socket: Option<PathBuf> = None;
    #[cfg(target_os = "linux")]
    let claude_deadline_unix_millis = claude_session
        .as_ref()
        .map(|session| session.deadline_unix_millis);
    #[cfg(not(target_os = "linux"))]
    let claude_deadline_unix_millis: Option<u64> = None;

    #[cfg(target_os = "linux")]
    let cursor_session = if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Cursor
    {
        match prepare_verified_cursor_account_session(spec) {
            Ok(session) => {
                report.stdout.run_metadata.managed_cursor_selection =
                    Some(session.authority.selection_evidence());
                Some(session)
            }
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_environment_failure(
                    &mut report,
                    EnvironmentFailureCategory::MissingCredential,
                    None,
                    format!("Cursor managed account preflight failed closed: {error:#}"),
                );
                return report;
            }
        }
    } else {
        None
    };
    let cursor_acp_prompt = if target_spec.invocation == ExternalAgentInvocation::Cursor {
        match String::from_utf8(prompt.clone()) {
            Ok(prompt) => Some(prompt),
            Err(_) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "Cursor ACP stdio prompt is not valid UTF-8".to_string(),
                );
                return report;
            }
        }
    } else {
        None
    };
    if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Cursor
    {
        #[cfg(not(target_os = "linux"))]
        {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                None,
                "managed Cursor confinement requires Linux".to_string(),
            );
            return report;
        }
    }

    let side_effect_profile = if runtime == ExternalExecutionRuntime::Verified
        && (program_trust == ExternalProgramTrust::TrustedSystemCodex
            || spec.invocation.is_adapter_subprocess())
    {
        match external_side_effect_profile_with_claude_relay(
            &target_spec,
            &resolved_program,
            program_trust,
            &target_controls,
            ClaudeProfileBinding {
                #[cfg(target_os = "linux")]
                child_config_home: claude_session
                    .as_ref()
                    .map(|session| session.authority.child_config_home()),
                #[cfg(not(target_os = "linux"))]
                child_config_home: None,
                #[cfg(target_os = "linux")]
                managed_data_root: claude_session
                    .as_ref()
                    .map(|session| session.authority.managed_data_root()),
                #[cfg(not(target_os = "linux"))]
                managed_data_root: None,
                #[cfg(target_os = "linux")]
                helper_registration_nonce: claude_session
                    .as_ref()
                    .map(|session| session.helper_registration_nonce.as_str()),
                #[cfg(not(target_os = "linux"))]
                helper_registration_nonce: None,
                #[cfg(target_os = "linux")]
                containment_owner: claude_session
                    .as_ref()
                    .map(|session| &session.containment_owner),
                #[cfg(not(target_os = "linux"))]
                containment_owner: None,
                parent_socket: claude_parent_socket.as_deref(),
                deadline_unix_millis: claude_deadline_unix_millis,
            },
        ) {
            Ok(profile) => Some(profile),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                report.error = Some(format!("failed to prepare external-agent sandbox: {error}"));
                let requirement = external_sandbox_requirement(spec.invocation);
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
                        if spec.invocation == ExternalAgentInvocation::Grok {
                            format!("failed to prepare the fixed ExternalGrok sandbox: {error}")
                        } else {
                            format!("failed to prepare the fixed ExternalCodex sandbox: {error}")
                        },
                    ));
                return report;
            }
        }
    } else {
        None
    };
    // Grok reads the prompt by pathname. Prepare its helper and held effective
    // prompt before credential-profile binding and the actual sandbox preflight.
    #[cfg(target_os = "linux")]
    let (prompt, side_effect_profile, mut grok_worker_journal) = {
        let mut prompt = prompt;
        let mut profile = side_effect_profile;
        let prepared = if runtime == ExternalExecutionRuntime::Verified {
            prepare_grok_worker_journal_launch(
                spec,
                &mut target_spec,
                &target_controls,
                &mut prompt,
                &mut profile,
                &mut argv,
                &mut output_staging,
            )
        } else {
            Ok(None)
        };
        let binding = match prepared {
            Ok(binding) => binding,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("Grok worker journal launch binding refused: {error:#}"),
                );
                return report;
            }
        };
        if binding.is_some() {
            bound_argv_digest = match argv_digest(&argv) {
                Ok(digest) => Some(digest),
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!("Grok journal argv binding failed: {error:#}"),
                    );
                    return report;
                }
            };
            report.command = command_display(&resolved_program, &argv);
        }
        (prompt, profile, binding)
    };
    let mut bound_grok_credentials = None;
    let side_effect_profile = match (grok_credentials.as_ref(), side_effect_profile) {
        (Some(credentials), Some(SideEffectConfinementProfile::ExternalGrok(profile))) => {
            match BoundGrokCredentials::new(credentials, profile) {
                Ok(bound) => {
                    let profile = bound.profile.clone();
                    bound_grok_credentials = Some(bound);
                    Some(SideEffectConfinementProfile::ExternalGrok(profile))
                }
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_grok_credential_environment_failure(&mut report, &error);
                    return report;
                }
            }
        }
        (Some(_), Some(_)) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(external_sandbox_requirement(spec.invocation)),
                "Grok credential capability was not paired with an ExternalGrok profile"
                    .to_string(),
            );
            return report;
        }
        (Some(_), None) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(EnvironmentRequirement::sandbox(
                    EnvironmentSandboxCapability::VerifiedExternalGrok,
                )),
                "Grok credential capability was not paired with an ExternalGrok profile"
                    .to_string(),
            );
            return report;
        }
        (None, profile) => profile,
    };
    #[cfg(target_os = "linux")]
    if let Some(binding) = grok_worker_journal.as_mut() {
        let sealed = match (
            side_effect_profile.as_ref(),
            bound_grok_credentials.as_ref(),
        ) {
            (Some(profile), Some(credentials)) => {
                binding.seal_credential_profile(profile, credentials)
            }
            _ => Err(anyhow::anyhow!(
                "Grok journal launch lacks held credential/profile custody"
            )),
        };
        if let Err(error) = sealed {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("Grok journal credential binding refused: {error:#}"),
            );
            return report;
        }
    }
    #[cfg(target_os = "linux")]
    let side_effect_profile = match (cursor_session.as_ref(), side_effect_profile) {
        (Some(session), Some(SideEffectConfinementProfile::ExternalCursor(profile))) => {
            let profile = match profile
                .with_hidden_root(session.authority.managed_home())
                .with_private_cursor_auth_file_capability(
                    session.authority.auth_path(),
                    session.authority.held_auth_file(),
                ) {
                Ok(profile) => profile,
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_environment_failure(
                        &mut report,
                        EnvironmentFailureCategory::SandboxUnavailable,
                        None,
                        format!("Cursor auth projection failed closed: {error}"),
                    );
                    return report;
                }
            };
            Some(SideEffectConfinementProfile::ExternalCursor(profile))
        }
        (Some(_), Some(_)) | (Some(_), None) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::SandboxUnavailable,
                None,
                "Cursor managed account was not paired with ExternalCursor confinement".to_string(),
            );
            return report;
        }
        (None, profile) => profile,
    };
    let mut external_environment =
        external_environment_for_command(spec, target_spec.runtime_adapter.as_ref(), program_trust);
    #[cfg(target_os = "linux")]
    if let Some(session) = grok_session.as_ref() {
        if let Err(error) =
            insert_admitted_grok_home_environment(&mut external_environment, &session.credentials)
        {
            report.duration_ms = duration_millis(started.elapsed());
            record_grok_credential_environment_failure(&mut report, &error);
            return report;
        }
        session
            .authority
            .apply_launch_environment(&mut external_environment);
    }
    #[cfg(target_os = "linux")]
    if let Some(session) = claude_session.as_mut() {
        if let Err(error) = session.authority.verify_binding_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::MissingCredential,
                Some(EnvironmentRequirement::credential(
                    EnvironmentCredential::ClaudeManagedOAuth,
                )),
                format!("managed Claude OAuth authority changed before child release: {error:#}"),
            );
            return report;
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(session) = claude_session.as_ref() {
        session
            .authority
            .apply_launch_environment(&mut external_environment);
    }
    #[cfg(target_os = "linux")]
    if let Some(session) = cursor_session.as_ref() {
        session
            .authority
            .apply_launch_environment(&mut external_environment);
        let install = cursor_install
            .as_ref()
            .expect("Cursor install bound before account projection");
        external_environment.insert(
            "MACO_CURSOR_PINNED_ROOT".to_string(),
            install.root().to_string_lossy().into_owned(),
        );
        let deadline =
            match crate::runtime_adapter::cursor_managed_parent::operation_deadline_unix_millis(
                spec.timeout.saturating_sub(started.elapsed()),
            ) {
                Ok(deadline) => deadline,
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!("failed to bind managed Cursor operation deadline: {error:#}"),
                    );
                    return report;
                }
            };
        external_environment.insert(
            "MACO_CURSOR_OPERATION_DEADLINE_UNIX_MILLIS".to_string(),
            deadline.to_string(),
        );
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
    if let Err(error) =
        extend_common_runtime_environment_with_assignment_messaging(spec, &mut external_environment)
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            format!("failed to prepare assignment messaging runtime environment: {error:#}"),
        );
        return report;
    }
    crate::supervise::cam_authority_child_env::insert_cam_authority_socket_into_launch_environment(
        &mut external_environment,
        spec.cam_authority_socket_pin.as_deref(),
    );
    #[cfg(target_os = "linux")]
    let claude_oauth_redaction = match claude_session.as_ref() {
        Some(session) => match session.authority.oauth_grant_bytes() {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("managed Claude OAuth redaction binding failed: {error:#}"),
                );
                return report;
            }
        },
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let claude_oauth_redaction: Option<&[u8]> = None;
    let credential_redactor = match CredentialRedactor::from_runtime(
        &external_environment,
        codex_auth.as_ref(),
        claude_oauth_redaction,
    ) {
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
        && spec.uses_live_claude_managed_worker_budget()
        && claude_session.is_none()
    {
        report.duration_ms = duration_millis(started.elapsed());
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::MissingCredential,
            Some(EnvironmentRequirement::credential(
                EnvironmentCredential::ClaudeManagedOAuth,
            )),
            "managed Claude worker requires a selected CAM OAuth account before provider release"
                .to_string(),
        );
        return report;
    }
    if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Grok
    {
        #[cfg(test)]
        tests::run_grok_preflight_hook();
        let mut preflight = run_grok_environment_preflight(
            &target_spec,
            spec.timeout.saturating_sub(started.elapsed()),
            cancellation,
            &external_environment,
            side_effect_profile
                .as_ref()
                .expect("verified Grok profile admitted above"),
            bound_grok_credentials.as_ref(),
            agent_lifecycle.as_ref(),
            &credential_redactor,
        );
        for failure in &mut preflight.failures {
            failure.summary = credential_redactor.redact_string(&failure.summary);
        }
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
    #[cfg(target_os = "linux")]
    if let Some(session) = cursor_session.as_ref() {
        if let Err(error) = session.authority.verify_binding_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::MissingCredential,
                None,
                format!("Cursor managed account changed before target release: {error:#}"),
            );
            return report;
        }
    }
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
            bound_grok_credentials.as_ref(),
            agent_lifecycle.as_ref(),
            Some(&credential_redactor),
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
    if app_server_required {
        let Some(version) =
            codex_version.map(|(major, minor, patch)| EnvironmentVersion::new(major, minor, patch))
        else {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::ProbeFailed,
                Some(codex_environment_requirement()),
                "Codex app-server version was unavailable after mandatory preflight".to_string(),
            );
            return report;
        };
        argv = match audited_codex_app_server_argv(&target_spec, &target_controls, version) {
            Ok(argv) => argv,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_environment_failure(
                    &mut report,
                    EnvironmentFailureCategory::VersionMismatch,
                    Some(codex_environment_requirement()),
                    error.to_string(),
                );
                return report;
            }
        };
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
    #[cfg(target_os = "linux")]
    let (prompt, side_effect_profile, worker_journal_append) = {
        let mut prompt = prompt;
        let mut profile = side_effect_profile;
        let bound = if spec.invocation == ExternalAgentInvocation::Grok {
            // Already sealed with its effective pathname prompt and credential
            // profile before Grok preflight. Never augment it a second time.
            Ok(None)
        } else {
            bind_worker_journal_append_operation(
                &target_spec,
                &target_controls,
                runtime,
                program_trust,
                &mut prompt,
                &mut profile,
                &mut argv,
            )
        };
        let binding = match bound {
            Ok(binding) => binding,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("worker journal append binding refused: {error:#}"),
                );
                return report;
            }
        };
        if binding.is_some() {
            bound_argv_digest = match argv_digest(&argv) {
                Ok(digest) => Some(digest),
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!("worker journal argv binding failed: {error:#}"),
                    );
                    return report;
                }
            };
            report.command = command_display(&resolved_program, &argv);
        }
        (prompt, profile, binding)
    };
    let app_server_prompt = if app_server_required {
        match String::from_utf8(prompt.clone()) {
            Ok(prompt) => Some(prompt),
            Err(_) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "Codex app-server prompt is not valid UTF-8".to_string(),
                );
                return report;
            }
        }
    } else {
        None
    };
    let Some(argv_digest) = bound_argv_digest else {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "external-agent argv was not bound before target release".to_string(),
        );
        return report;
    };
    if let Err(error) = validate_external_program_identity(
        &resolved_program,
        program_trust == ExternalProgramTrust::TrustedSystemCodex,
    )
    .and_then(|()| {
        let current = external_program_identity(&resolved_program)?;
        if current == program_identity {
            Ok(())
        } else {
            bail!("external executable identity changed after version preflight")
        }
    }) {
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
    if let Err(error) = researcher_inputs::prepare_source_inputs(
        &target_spec,
        side_effect_profile.as_ref(),
        spec.timeout.saturating_sub(started.elapsed()),
        cancellation,
        &mut report,
    ) {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            format!("Researcher source input preflight refused: {error:#}"),
        );
        return report;
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
    let staging_path = match output_staging.path() {
        Ok(path) => path.to_path_buf(),
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("private external-agent output staging became unavailable: {error:#}"),
            );
            return report;
        }
    };
    let sealed_assignment_process_grant = match seal_assignment_process_launch_grant(
        spec,
        &resolved_program,
        &argv,
        &staging_path,
        &target_spec.cwd,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(&mut report, assignment_process_launch_refusal(error));
            return report;
        }
    };
    #[cfg(target_os = "linux")]
    let mut claude_relay = if let Some(session) = claude_session.as_mut() {
        let (reservation_id, auth_mode) = match target_spec.claude_managed_binding() {
            Ok(binding) => binding,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(&mut report, error);
                return report;
            }
        };
        if auth_mode != ClaudeAuthMode::ManagedOAuth {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "managed Claude account was paired with the bare API-key route".to_string(),
            );
            return report;
        }
        let launch_digest = sha256_hex(
            format!(
                "{}\n{}\n{}\n{}",
                program_identity.display(),
                argv_digest,
                target_spec.cwd.display(),
                reservation_id
            )
            .as_bytes(),
        );
        let binding = match ClaudeBrokerBinding::new(
            match private_parent_nonce() {
                Ok(nonce) => nonce,
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(&mut report, format!("{error:#}"));
                    return report;
                }
            },
            launch_digest,
            session.authority.account_binding_string(),
            reservation_id,
            session.deadline_unix_millis,
            ClaudeTransportAuthMode::OAuthBearer,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(&mut report, error);
                return report;
            }
        };
        let upstream_oauth_grant = match session.authority.take_oauth_grant() {
            Ok(grant) => grant,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(&mut report, format!("{error:#}"));
                return report;
            }
        };
        let child_oauth_grant = match session.authority.take_child_oauth_grant() {
            Ok(grant) => grant,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(&mut report, format!("{error:#}"));
                return report;
            }
        };
        let Some(parent_socket) = claude_parent_socket.as_deref() else {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "managed Claude parent relay socket binding was unavailable".to_string(),
            );
            return report;
        };
        match ClaudeManagedRelay::start(
            binding,
            child_oauth_grant,
            upstream_oauth_grant,
            session.helper_registration_nonce.clone(),
            session.containment_owner.clone(),
            parent_socket,
        ) {
            Ok(relay) => {
                external_environment.insert(
                    "ANTHROPIC_BASE_URL".to_string(),
                    relay.base_url().to_string(),
                );
                Some(relay)
            }
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("managed Claude parent relay failed to start: {error}"),
                );
                return report;
            }
        }
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let mut claude_relay: Option<()> = None;
    if grok_acp_stdio_protocol_selected(&target_spec) {
        // Override any inherited/configured enablement before ClearAndSet is
        // sealed into the actual ProcessSpec. Never rely on pager-only flags.
        crate::runtime_adapter::grok::GROK_ACP_RUNTIME_DESCRIPTOR
            .apply_required_environment(&mut external_environment);
    }
    let process_spec = ProcessSpec::direct(
        "external agent",
        &resolved_program,
        argv.clone(),
        &target_spec.cwd,
        OUTPUT_TEE_LIMIT_BYTES,
    )
    .with_stdin(external_agent_stdin_mode(
        &target_spec,
        app_server_required,
        prompt,
    ))
    .with_stdin_limit(MAX_PROMPT_BYTES)
    .with_timeout(Some(timeout))
    .with_stdout(StreamCapture::bounded(OUTPUT_TEE_LIMIT_BYTES));
    let mut process_spec = match runtime {
        ExternalExecutionRuntime::Verified => {
            let Some(side_effect_profile) = side_effect_profile else {
                report.duration_ms = duration_millis(started.elapsed());
                record_environment_failure(
                    &mut report,
                    EnvironmentFailureCategory::SandboxUnavailable,
                    Some(external_sandbox_requirement(target_spec.invocation)),
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
                staged_codex_home.as_deref(),
            )
        }
        #[cfg(test)]
        ExternalExecutionRuntime::NonpublishableSimulation => {
            let mut process_spec = process_spec
                .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort);
            if let Some(metadata) = agent_lifecycle.as_ref() {
                process_spec = process_spec.with_agent_lifecycle(metadata.clone());
            }
            match assignment_messaging_launch_environment_overlay(spec) {
                Ok(mut overlay) => {
                    // The simulation has no transient unit, so the staged home is exposed
                    // through the inherited environment exactly where the unit would see it.
                    if let Some(home) = staged_codex_home.as_deref() {
                        overlay.insert(
                            "CODEX_HOME".to_string(),
                            home.to_string_lossy().into_owned(),
                        );
                    }
                    crate::supervise::cam_authority_child_env::insert_cam_authority_socket_into_launch_environment(
                        &mut overlay,
                        spec.cam_authority_socket_pin.as_deref(),
                    );
                    if overlay.is_empty() {
                        process_spec
                    } else {
                        process_spec.with_environment(EnvironmentMode::InheritAndSet(overlay))
                    }
                }
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!(
                            "failed to prepare sealed assignment messaging simulation environment: {error:#}"
                        ),
                    );
                    return report;
                }
            }
        }
    };

    if let Some(pin) = read_only_target_executable_pin {
        process_spec = match process_spec.with_pinned_direct_executable(pin) {
            Ok(prepared) => prepared,
            Err(error) => {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    format!("read-only target executable pin delivery refused: {error}"),
                );
                return report;
            }
        };
    }
    process_spec.read_only_input_snapshots =
        report.stdout.run_metadata.read_only_input_snapshots.clone();

    if cancellation.is_cancelled() {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            "external agent was cancelled before target start".to_string(),
        );
        return report;
    }

    #[cfg(target_os = "linux")]
    if let Some(binding) = &worker_journal_append {
        if let Err(error) = binding.revalidate() {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("worker journal append binding changed before release: {error:#}"),
            );
            return report;
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(binding) = &grok_worker_journal {
        let checked = match &process_spec.command {
            ProcessCommand::Direct { args, .. } => {
                binding.revalidate(spec, &target_spec, args, &process_spec.side_effects)
            }
            _ => Err(anyhow::anyhow!(
                "Grok journal launch must retain direct native argv"
            )),
        };
        if let Err(error) = checked {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("Grok journal binding changed before release: {error:#}"),
            );
            return report;
        }
        if !bound_grok_credentials
            .as_ref()
            .is_some_and(|credentials| credentials.present_in(&process_spec.side_effects))
        {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "Grok journal launch credential profile changed before release".into(),
            );
            return report;
        }
    }

    if let Err(error) = spec.verified_live_token_grant() {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(&mut report, error);
        return report;
    }

    let mut selected_merge_grant_consumed = false;
    if let Some(grant) = sealed_assignment_process_grant {
        if let Err(error) =
            consume_assignment_process_launch_grant(spec, grant, &mut process_spec, &staging_path)
        {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(&mut report, assignment_process_launch_refusal(error));
            return report;
        }
        selected_merge_grant_consumed = spec.selected_merge_arbiter.is_some()
            && spec.assignment_process_launch_kind
                == Some(AssignmentProcessLaunchKind::MergeArbiter);
    }

    #[cfg(target_os = "linux")]
    if let Some(session) = grok_session.as_ref() {
        if let Err(error) = session.authority.verify_binding_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            record_grok_credential_environment_failure(&mut report, &error);
            return report;
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(session) = claude_session.as_mut() {
        if let Err(error) = session.authority.verify_binding_unchanged() {
            report.duration_ms = duration_millis(started.elapsed());
            record_environment_failure(
                &mut report,
                EnvironmentFailureCategory::MissingCredential,
                Some(EnvironmentRequirement::credential(
                    EnvironmentCredential::ClaudeManagedOAuth,
                )),
                format!(
                    "managed Claude account/credential source changed before target release: {error:#}"
                ),
            );
            return report;
        }
    }

    if let Err(error) = researcher_inputs::revalidate_source_inputs(
        &target_spec,
        &report.stdout.run_metadata.researcher_input_receipts,
    ) {
        report.duration_ms = duration_millis(started.elapsed());
        record_external_error(
            &mut report,
            format!("Researcher source input changed before target release: {error:#}"),
        );
        return report;
    }

    if target_spec.uses_live_claude_managed_worker_budget() {
        if let Err(error) = target_spec.verified_writable_capabilities(RuntimeId::ClaudeCode) {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!(
                    "Claude managed-Worker executable/claim confinement changed before target release: {error:#}"
                ),
            );
            return report;
        }
        if let Err(error) = target_spec.verified_claude_managed_reservation() {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                format!("Claude managed-Worker reservation stopped before target release: {error}"),
            );
            return report;
        }
    }

    // Preflight evidence describes only the bounded probes. Once the main target is released it
    // must earn fresh process-tree and side-effect evidence of its own; otherwise a target wait
    // or cancellation failure could appear quiescent because an earlier probe was clean.
    report.process_tree = None;
    report.side_effects = None;
    report
        .stdout
        .run_metadata
        .local_source_probe_refusal_quiescent = false;
    report.stdout.target_launch_attempted = true;
    let completed_context = CompletedTargetContext {
        runtime,
        codex_version,
        spec: &target_spec,
        original_spec: spec,
        protected_controls: &target_controls,
        argv_digest: &argv_digest,
        program_identity: &program_identity,
        grok_acp_parent_evidence: None,
        grok_acp_launch_schema_identity: None,
        claude_broker_witness: None,
    };
    let mut retained_gate_denials = Vec::new();
    let mut retained_review_metrics = None;
    let mut failed_claude_broker_witness: Option<(ClaudeWholeCallWitness, ClaudeBrokerBinding)> =
        None;
    let process_result = if app_server_required {
        let Some(prompt) = app_server_prompt else {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "Codex app-server prompt was unavailable".to_string(),
            );
            return report;
        };
        let process = if read_only_codex_app_server {
            run_read_only_terminal_app_server_process_with_auth(
                process_spec,
                cancellation,
                spec,
                prompt,
                codex_auth.as_ref(),
            )
        } else if managed_worker_app_server {
            run_managed_worker_app_server_process_with_auth(
                process_spec,
                cancellation,
                spec,
                prompt,
                codex_auth.as_ref(),
            )
        } else {
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
            let attempt = run_duplex_app_server_process_with_auth(
                process_spec,
                cancellation,
                spec,
                prompt,
                review_runtime,
                codex_auth.as_ref(),
            );
            retained_gate_denials = attempt.gate_denials;
            retained_review_metrics = Some(attempt.metrics);
            attempt.process
        };
        match process {
            Ok(interactive) => {
                record_completed_app_server_target(
                    &mut report,
                    interactive,
                    &mut output_staging,
                    &mut output_reservation,
                    &mut json_log_reservation,
                    &credential_redactor,
                    completed_context,
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    } else if target_spec.uses_live_claude_managed_worker_budget() {
        match run_process_cancellable(process_spec, cancellation) {
            Ok(output) => {
                #[cfg(target_os = "linux")]
                {
                    let relay = claude_relay
                        .take()
                        .expect("managed Claude launch prepared its parent relay");
                    let expected_binding = relay.binding().clone();
                    let child_exit_observed = output.status.is_some();
                    let interrupted = output.timed_out
                        || output.process_error.is_some()
                        || output.stdin_error.is_some()
                        || cancellation.is_cancelled();
                    match relay.finish(child_exit_observed, interrupted) {
                        Ok(finish) => {
                            let mut witness = finish.witness;
                            if let Some(error) = finish.error {
                                record_external_error(
                                    &mut report,
                                    format!("managed Claude parent relay drain failed: {error}"),
                                );
                            }
                            let source_unchanged = claude_session
                                .as_mut()
                                .expect("managed Claude launch retained its account lease")
                                .authority
                                .verify_binding_unchanged()
                                .map(|()| true)
                                .unwrap_or_else(|error| {
                                    record_external_error(
                                        &mut report,
                                        format!(
                                            "managed Claude account/credential source changed before relay drain: {error:#}"
                                        ),
                                    );
                                    false
                                });
                            if !source_unchanged {
                                witness.mark_interrupted();
                            }
                            match output_staging.completion_handles() {
                                Ok(staging) => record_completed_target(
                                    &mut report,
                                    output,
                                    staging,
                                    &mut output_reservation,
                                    &mut json_log_reservation,
                                    &credential_redactor,
                                    CompletedTargetContext {
                                        claude_broker_witness: Some((&witness, &expected_binding)),
                                        ..completed_context
                                    },
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
                        }
                        Err(error) => {
                            record_external_error(
                                &mut report,
                                format!("managed Claude parent relay did not seal: {error}"),
                            );
                            match output_staging.completion_handles() {
                                Ok(staging) => record_completed_target(
                                    &mut report,
                                    output,
                                    staging,
                                    &mut output_reservation,
                                    &mut json_log_reservation,
                                    &credential_redactor,
                                    completed_context,
                                ),
                                Err(staging_error) => record_external_error(
                                    &mut report,
                                    format!(
                                        "private external-agent output staging became unavailable: {staging_error:#}"
                                    ),
                                ),
                            }
                        }
                    }
                }
                Ok(())
            }
            Err(error) => {
                #[cfg(target_os = "linux")]
                if let Some(relay) = claude_relay.take() {
                    let expected_binding = relay.binding().clone();
                    match relay.finish(false, true) {
                        Ok(finish) => {
                            if let Some(relay_error) = finish.error {
                                record_external_error(
                                    &mut report,
                                    format!(
                                        "managed Claude parent relay drain failed: {relay_error}"
                                    ),
                                );
                            }
                            failed_claude_broker_witness = Some((finish.witness, expected_binding));
                        }
                        Err(relay_error) => record_external_error(
                            &mut report,
                            format!("managed Claude parent relay did not seal: {relay_error}"),
                        ),
                    }
                }
                #[cfg(target_os = "linux")]
                if let Some(session) = claude_session.as_mut() {
                    if let Err(revalidation_error) = session.authority.verify_binding_unchanged() {
                        record_external_error(
                            &mut report,
                            format!(
                                "managed Claude account/credential source changed before failed relay release: {revalidation_error:#}"
                            ),
                        );
                    }
                }
                Err(error)
            }
        }
    } else if grok_acp_stdio_protocol_selected(&target_spec) {
        let Some(prompt) = grok_acp_prompt else {
            report.duration_ms = duration_millis(started.elapsed());
            record_external_error(
                &mut report,
                "Grok ACP stdio prompt was unavailable".to_string(),
            );
            return report;
        };
        match run_grok_acp_external_process(
            process_spec,
            cancellation,
            &target_spec,
            prompt,
            timeout,
        ) {
            Ok(interactive) => {
                let mut parent_evidence = None;
                let mut launch_schema = None;
                let mut final_message_error = None;
                if let Ok(outcome) = &interactive.interaction {
                    launch_schema = outcome.launch_schema.clone();
                    parent_evidence = Some(grok_acp_parent_evidence_from_execution(
                        outcome.evidence.clone(),
                    ));
                    if let Some(parent) = &parent_evidence {
                        let target_ok = !interactive.process.timed_out
                            && interactive
                                .process
                                .status
                                .is_some_and(|status| status.success())
                            && interactive.process.process_error.is_none()
                            && interactive.process.stdin_error.is_none();
                        if target_ok {
                            match grok_acp_staged_output_bytes(
                                &target_spec,
                                parent,
                                true,
                                launch_schema.as_ref(),
                            ) {
                                Ok(final_message) => {
                                    let staged =
                                        output_staging.reservation_mut().and_then(|reservation| {
                                            reservation.write_bytes_atomic(
                                                &final_message,
                                                OUTPUT_TEE_LIMIT_BYTES,
                                            )
                                        });
                                    if let Err(error) = staged {
                                        final_message_error = Some(format!(
                                            "failed to stage Grok ACP final message: {error:#}"
                                        ));
                                    }
                                }
                                Err(error) => {
                                    final_message_error = Some(credential_redactor.redact_string(
                                        &format!("Grok ACP output validation failed: {error:#}"),
                                    ));
                                }
                            }
                        }
                    }
                }
                match output_staging.completion_handles() {
                    Ok(staging) => record_completed_target(
                        &mut report,
                        interactive.process,
                        staging,
                        &mut output_reservation,
                        &mut json_log_reservation,
                        &credential_redactor,
                        CompletedTargetContext {
                            runtime,
                            codex_version,
                            spec: &target_spec,
                            original_spec: spec,
                            protected_controls: &target_controls,
                            argv_digest: &argv_digest,
                            program_identity: &program_identity,
                            grok_acp_parent_evidence: parent_evidence.as_ref(),
                            grok_acp_launch_schema_identity: launch_schema.as_ref(),
                            claude_broker_witness: None,
                        },
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
                if let Err(error) = interactive.interaction {
                    report.error = append_external_error(
                        report.error.take(),
                        Some(credential_redactor.redact_string(&format!(
                            "Grok ACP stdio protocol failed closed: {error}"
                        ))),
                    );
                    report.publishable = false;
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    } else if target_spec.invocation == ExternalAgentInvocation::Cursor {
        #[cfg(target_os = "linux")]
        {
            let Some(prompt) = cursor_acp_prompt else {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "Cursor ACP stdio prompt was unavailable".to_string(),
                );
                return report;
            };
            let turn = GrokAcpTurn {
                cwd: target_spec.cwd.to_string_lossy().into_owned(),
                prompt,
                requested_model: target_spec.model.clone(),
                requested_effort: target_spec.reasoning_effort.clone(),
                output_schema: None,
            };
            let limits = match GrokAcpLimits::from_parent_operation_timeout(timeout) {
                Ok(limits) => limits,
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!("Cursor ACP limits failed closed: {error}"),
                    );
                    return report;
                }
            };
            let assigned_paths = match target_spec.cursor_managed_claimed_paths() {
                Ok(paths) => paths,
                Err(error) => {
                    report.duration_ms = duration_millis(started.elapsed());
                    record_external_error(
                        &mut report,
                        format!("Cursor assignment authority failed closed: {error:#}"),
                    );
                    return report;
                }
            };
            let Some(cursor_operation_deadline) = started.checked_add(spec.timeout) else {
                report.duration_ms = duration_millis(started.elapsed());
                record_external_error(
                    &mut report,
                    "managed Cursor operation deadline overflowed".to_string(),
                );
                return report;
            };
            let mut parent = None;
            let interactive = run_process_interactive_with_start_gate(
                process_spec,
                cancellation,
                |gate| {
                    parent = Some(
                        crate::runtime_adapter::cursor_managed_parent::CursorManagedParent::start(
                            gate,
                            &target_spec.cwd,
                            assigned_paths.clone(),
                            cancellation.clone(),
                            cursor_operation_deadline,
                        )
                        .map_err(|error| {
                            format!("managed Cursor parent setup failed: {error:#}")
                        })?,
                    );
                    Ok(())
                },
                |session| {
                    let mut transport = GrokAcpContainedTransport::new(session);
                    crate::runtime_adapter::grok_acp::run_grok_acp_turn(
                        &mut transport,
                        &turn,
                        limits,
                        || cancellation.is_cancelled(),
                    )
                    .map_err(|error| error.to_string())
                },
            );
            match interactive {
                Ok(interactive) => {
                    let mut parent_result = parent
                        .take()
                        .context("managed Cursor parent was not created before target release")
                        .and_then(|parent| parent.finish());
                    let mut final_message_error = None;
                    if let Ok(outcome) = &interactive.interaction {
                        if outcome.permission_escalation_refused {
                            final_message_error = Some(
                                "Cursor ACP requested an unadmitted native client resource"
                                    .to_string(),
                            );
                        } else if let Some(final_text) = outcome.final_text.as_deref() {
                            if let Err(error) =
                                output_staging.reservation_mut().and_then(|reservation| {
                                    reservation.write_bytes_atomic(
                                        final_text.as_bytes(),
                                        OUTPUT_TEE_LIMIT_BYTES,
                                    )
                                })
                            {
                                final_message_error = Some(format!(
                                    "failed to stage Cursor ACP final message: {error:#}"
                                ));
                            }
                        } else {
                            final_message_error =
                                Some("Cursor ACP terminal response omitted final text".to_string());
                        }
                        if let Ok(evidence) = parent_result.as_mut() {
                            if let crate::runtime_adapter::grok_acp::GrokAcpResolvedField::Known(
                                model,
                            ) = &outcome.client_resolved.model
                            {
                                evidence.client_selected_model = Some(model.clone());
                            }
                            if let crate::runtime_adapter::grok_acp::GrokAcpResolvedField::Known(
                                effort,
                            ) = &outcome.client_resolved.effort
                            {
                                evidence.client_selected_effort = Some(effort.clone());
                            }
                        }
                    }
                    match parent_result {
                        Ok(evidence) => report.cursor_managed_parent_evidence = Some(evidence),
                        Err(error) => {
                            report.error = append_external_error(
                                report.error.take(),
                                Some(format!(
                                    "managed Cursor parent completion failed: {error:#}"
                                )),
                            );
                        }
                    }
                    match output_staging.completion_handles() {
                        Ok(staging) => record_completed_target(
                            &mut report,
                            interactive.process,
                            staging,
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
                    if let Err(error) = interactive.interaction {
                        report.error = append_external_error(
                            report.error.take(),
                            Some(credential_redactor.redact_string(&format!(
                                "Cursor ACP stdio protocol failed closed: {error}"
                            ))),
                        );
                        report.publishable = false;
                    }
                    Ok(())
                }
                Err(error) => {
                    if let Some(parent) = parent.take() {
                        if let Ok(evidence) = parent.finish() {
                            report.cursor_managed_parent_evidence = Some(evidence);
                        }
                    }
                    Err(error)
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            unreachable!("managed Cursor was refused before process construction")
        }
    } else {
        run_codex_batch_process(process_spec, cancellation, codex_auth.as_ref()).map(
            |(output, filesystem)| {
                // Bind the original supervisor command, not target_spec's private
                // staging destination. Retain spend before any fallible materialization.
                report.retain_grok_native_usage(
                    spec,
                    runtime,
                    &output.stdout,
                    !output.timed_out
                        && output.status.is_some_and(|status| status.success())
                        && output.process_error.is_none()
                        && output.stdin_error.is_none()
                        && output.safety_evidence_verified(),
                );
                retain_grok_read_only_filesystem(&mut report, spec, runtime, filesystem);
                match output_staging.completion_handles() {
                    Ok(staging) => record_completed_target(
                        &mut report,
                        output,
                        staging,
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
            },
        )
    };
    match process_result {
        Ok(()) => {}
        Err(error) => {
            report.timed_out = matches!(&error, ProcessRunError::SetupTimeout { .. });
            let preparation_failure =
                target_process_environment_failure(&error, target_spec.invocation);
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
                report.retain_grok_native_usage(spec, runtime, &evidence.stdout, false);
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
                if target_spec.invocation == ExternalAgentInvocation::ClaudeCode {
                    let mut claude = crate::runtime_adapter::claude::collect_native_stream(
                        evidence.stdout.as_bytes(),
                        evidence.stdout.is_truncated(),
                    );
                    if let Some((witness, binding)) = &failed_claude_broker_witness {
                        claude.attach_whole_call_witness(witness, binding);
                    }
                    claude.mark_interrupted();
                    report.stdout.run_metadata.claude_native_evidence = Some(claude);
                }
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
    #[cfg(target_os = "linux")]
    if let Some(binding) = &grok_worker_journal {
        let checked = binding
            .profile
            .as_ref()
            .context("Grok journal profile custody missing")
            .and_then(|profile| {
                binding.revalidate(
                    spec,
                    &target_spec,
                    &argv,
                    &SideEffectConfinementProfile::ExternalGrok(profile.clone()),
                )
            });
        if let Err(error) = checked {
            record_grok_journal_custody_failure(&mut report, &error);
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
    // The lease remains owned until target reap, protocol drain and staging cleanup finish.
    if let Some(auth) = &codex_auth {
        if auth.verify_source_unchanged().is_err() {
            report.error = append_external_error(
                report.error.take(),
                Some(
                    "Codex auth source or selected CAM identity changed through completion/drain"
                        .to_string(),
                ),
            );
            report.publishable = false;
        }
    }
    report.stdout.run_metadata.gate_denials = retained_gate_denials;
    report.stdout.run_metadata.pre_action_review_metrics = retained_review_metrics;
    report.duration_ms = duration_millis(started.elapsed());
    if runtime == ExternalExecutionRuntime::Verified
        && selected_merge_grant_consumed
        && report.stdout.target_launch_attempted
        && report.error.is_none()
        && !report.timed_out
        && report.exit_code == Some(0)
        && report.scratch_quiescence_verified()
    {
        if let (Some(admission), Some(output)) = (
            &spec.selected_merge_arbiter,
            report.output_last_message.as_deref(),
        ) {
            if validate_selected_merge_command(spec).is_ok() {
                report.stdout.run_metadata.selected_merge_completion =
                    Some(SelectedMergeCompletionBinding {
                        admission: admission.clone(),
                        held_output_sha256: sha256_hex(output),
                    });
            }
        }
    }
    report
}

fn should_use_read_only_terminal_app_server(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) -> bool {
    cfg!(target_os = "linux")
        && runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::CodexSupervisor
        && spec.workspace_access == WorkspaceAccess::ReadOnly
        && spec
            .agent_lifecycle
            .as_ref()
            .is_some_and(|identity| matches!(identity.role.as_str(), "researcher" | "auditor"))
}

fn managed_worker_app_server_shape(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) -> bool {
    cfg!(target_os = "linux")
        && runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::CodexSupervisor
        && spec.workspace_access == WorkspaceAccess::ReadWrite
        && spec.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree
        && spec
            .agent_lifecycle
            .as_ref()
            .is_some_and(|identity| identity.role == "worker")
}

fn classify_managed_worker_app_server(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) -> Result<bool, String> {
    if !managed_worker_app_server_shape(spec, runtime) {
        return Ok(false);
    }
    // A malformed selected Worker is a refusal, never an unobserved exec fallback.
    if !spec.codex_native_delegation_disabled
        || spec.codex_managed_readonly_route_active()
        || spec.assignment_process_launch_kind != Some(AssignmentProcessLaunchKind::AssignmentChild)
        || spec.worker_journal_artifacts.len() != 1
    {
        return Err("managed writable Worker app-server requires native delegation disabled, private AssignmentChild authority and one bound journal".to_string());
    }
    refuse_assignment_process_launch_before_preflight(spec)
        .map_err(assignment_process_launch_refusal)?;
    let identity = spec
        .agent_lifecycle
        .as_ref()
        .ok_or_else(|| "Worker lifecycle is missing".to_string())?;
    if identity.run_id.is_empty()
        || identity.task_id.is_empty()
        || spec.worker_journal_artifacts[0].worker_id != identity.task_id
    {
        return Err(
            "managed writable Worker app-server journal subject differs from its launch"
                .to_string(),
        );
    }
    spec.verified_live_token_grant()?;
    Ok(true)
}

fn classify_managed_readonly_app_server(
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) -> Result<Option<CodexManagedReadonlyRoute>, String> {
    if spec.codex_managed_readonly_route == CodexManagedReadonlyRoute::Off {
        return Ok(None);
    }
    if let Some(problem) = managed_readonly_shape_problem(spec) {
        return Err(format!(
            "managed read-only Codex app-server opt-in refused: {problem}"
        ));
    }
    if !(cfg!(target_os = "linux") && runtime == ExternalExecutionRuntime::Verified) {
        return Err(
            "managed read-only Codex app-server requires a verified Linux TrustedSystemCodex route"
                .to_string(),
        );
    }
    Ok(Some(spec.codex_managed_readonly_route))
}

fn managed_readonly_shape_problem(spec: &ExternalAgentCommand) -> Option<&'static str> {
    if spec.invocation != ExternalAgentInvocation::CodexSupervisor {
        return Some("invocation must be CodexSupervisor");
    }
    if spec.workspace_access != WorkspaceAccess::ReadOnly {
        return Some("workspace must be read-only");
    }
    if spec.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree {
        return Some("launch target must be the managed child worktree");
    }
    if !spec.codex_native_delegation_disabled {
        return Some("native delegation must be disabled");
    }
    let role_matches = spec.agent_lifecycle.as_ref().is_some_and(|identity| {
        identity.role == AgentRole::ChildOrchestrator.as_str() && !identity.run_id.is_empty()
    });
    if !role_matches {
        return Some("lifecycle role must be child_orchestrator");
    }
    None
}

fn validate_managed_readonly_execute_binding(
    spec: &ExternalAgentCommand,
    route: Option<CodexManagedReadonlyRoute>,
) -> Result<(), String> {
    let Some(route) = route else {
        return Ok(());
    };
    let Some(identity) = spec.agent_lifecycle.as_ref() else {
        return Err("managed read-only Codex app-server is missing lifecycle identity".to_string());
    };
    match route {
        CodexManagedReadonlyRoute::Off => Ok(()),
        CodexManagedReadonlyRoute::InitialWorkerRequests => {
            let Some(launch) = spec.assignment_messaging_launch.as_ref() else {
                return Err(
                    "managed initial Codex parent is missing its sealed inbox endpoint".to_string(),
                );
            };
            launch
                .environment_for(&identity.run_id, &identity.task_id)
                .map(|_| ())
                .map_err(|error| {
                    format!(
                        "managed initial Codex parent sealed endpoint binding refused: {error:#}"
                    )
                })
        }
        CodexManagedReadonlyRoute::Continuation => {
            if let Some(launch) = spec.assignment_messaging_launch.as_ref() {
                launch
                    .environment_for(&identity.run_id, &identity.task_id)
                    .map(|_| ())
                    .map_err(|error| {
                        format!("managed continuation sealed endpoint binding refused: {error:#}")
                    })?;
            }
            Ok(())
        }
    }
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

fn audited_codex_app_server_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    version: EnvironmentVersion,
) -> Result<Vec<OsString>> {
    validate_duplex_app_server_version(version)?;
    Ok(codex_app_server_argv(spec, controls))
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

fn run_observed_app_server_turn<T: codex_app_server::JsonLineTransport>(
    transport: &mut T,
    turn: &codex_app_server::AppServerTurn,
    spec: &ExternalAgentCommand,
    reviewer: &mut dyn codex_app_server::ApprovalReviewer,
    worker_requests: Option<&mut codex_app_server::WorkerRequestCallback<'_>>,
    cancellation: &ProcessCancellation,
) -> Result<codex_app_server::AppServerOutcome, String> {
    let grant = spec
        .verified_live_token_grant()
        .inspect_err(|_| cancellation.cancel())?;
    let mut partial = None;
    let result = codex_app_server::run_app_server_turn_with_worker_requests_observed(
        transport,
        turn,
        codex_app_server::AppServerLimits {
            turn_timeout: spec.timeout,
            token_grant: grant.map(|grant| grant.tokens()),
            ..codex_app_server::AppServerLimits::default()
        },
        reviewer,
        worker_requests,
        || cancellation.is_cancelled() || grant.is_some_and(|grant| grant.stopped()),
        codex_app_server::AppServerObservation {
            partial: &mut partial,
            budget_exhausted: &mut || {
                if let Some(grant) = grant {
                    grant.exhaust();
                }
            },
        },
    );
    match result {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            // After the bounded interrupt drain, promptly reap an uncooperative provider.
            cancellation.cancel();
            if let Some(outcome) = &mut partial {
                outcome.protocol_error = Some(error.to_string());
            }
            partial.ok_or_else(|| error.to_string())
        }
    }
}

fn fail_app_server_outcome(outcome: &mut codex_app_server::AppServerOutcome, error: String) {
    outcome.protocol_error = append_external_error(outcome.protocol_error.take(), Some(error));
    outcome.status = codex_app_server::TurnTerminalStatus::Failed;
    outcome.command_execution_evidence.turn_status = codex_app_server::TurnTerminalStatus::Failed;
    outcome.final_message = None;
}

// These adapters add only selected-auth revalidation to the existing paused start gate.
// Unmanaged commands retain the existing runner, stdin and protocol behavior.
fn run_codex_batch_process(
    spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    auth: Option<&ValidatedCodexAuth>,
) -> Result<(ProcessOutput, Option<ReadOnlyFilesystemEvidence>), ProcessRunError> {
    // Match the exact submission before runner stamping or consumed-proof changes.
    let submitted = spec.clone();
    #[cfg(target_os = "linux")]
    if let Some(auth) = auth.filter(|auth| auth.managed_authority.is_some()) {
        return run_process_cancellable_with_start_gate_and_filesystem_evidence(
            spec,
            cancellation,
            |_| {
                auth.verify_source_unchanged().map_err(|_| {
                    "selected Codex auth source or CAM identity changed before release".to_string()
                })
            },
        )
        .map(|capture| capture.into_parts_for_spec(&submitted));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = auth;
    run_process_cancellable_with_filesystem_evidence(spec, cancellation)
        .map(|capture| capture.into_parts_for_spec(&submitted))
}

fn run_codex_interactive_process<T, F>(
    spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    auth: Option<&ValidatedCodexAuth>,
    handler: F,
) -> Result<InteractiveProcessOutput<T>, ProcessRunError>
where
    F: FnMut(&mut crate::process_runner::ContainedProcessSession<'_>) -> Result<T, String>,
{
    #[cfg(target_os = "linux")]
    if let Some(auth) = auth.filter(|auth| auth.managed_authority.is_some()) {
        return run_process_interactive_with_start_gate(
            spec,
            cancellation,
            |_| {
                auth.verify_source_unchanged().map_err(|_| {
                    "selected Codex auth source or CAM identity changed before release".to_string()
                })
            },
            handler,
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = auth;
    run_process_interactive(spec, cancellation, handler)
}

#[cfg(test)]
fn run_read_only_terminal_app_server_process(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
) -> Result<InteractiveProcessOutput<codex_app_server::AppServerOutcome>, ProcessRunError> {
    run_read_only_terminal_app_server_process_with_auth(
        process_spec,
        cancellation,
        spec,
        prompt,
        None,
    )
}

#[cfg(test)]
fn run_managed_worker_app_server_process(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
) -> Result<InteractiveProcessOutput<codex_app_server::AppServerOutcome>, ProcessRunError> {
    run_managed_worker_app_server_process_with_auth(process_spec, cancellation, spec, prompt, None)
}

#[cfg(test)]
fn run_duplex_app_server_process(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    runtime: &mut ExternalPreActionReviewRuntime<'_>,
) -> DuplexProcessAttempt {
    run_duplex_app_server_process_with_auth(process_spec, cancellation, spec, prompt, runtime, None)
}

fn run_read_only_terminal_app_server_process_with_auth(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    auth: Option<&ValidatedCodexAuth>,
) -> Result<InteractiveProcessOutput<codex_app_server::AppServerOutcome>, ProcessRunError> {
    let turn = codex_app_server::AppServerTurn {
        cwd: spec.cwd.to_string_lossy().into_owned(),
        permission_profile: "maco_external_codex".to_string(),
        prompt,
        model: spec.model.clone(),
        minimum_effort: spec
            .agent_lifecycle
            .as_ref()
            .filter(|identity| identity.role == AgentRole::Auditor.as_str())
            .map(|_| spec.reasoning_effort.clone().unwrap_or_default()),
        output_schema: load_codex_app_server_output_schema(spec)?,
    };
    let cancellation = cancellation.child_scope();
    run_codex_interactive_process(process_spec, &cancellation, auth, |session| {
        let mut transport = codex_app_server::ContainedJsonLineTransport::new(session);
        // Read-only terminal roles have no approval authority, even if a hosted reviewer exists.
        let mut approval_requested = false;
        let mut reviewer = |_: codex_app_server::ApprovalRequest| {
            approval_requested = true;
            Ok(codex_app_server::ApprovalReview::cancel(None))
        };
        let mut outcome = if spec.codex_managed_worker_requests_enabled() {
            let launch = spec.assignment_messaging_launch.as_ref().ok_or_else(|| {
                "managed initial Codex parent is missing its sealed inbox endpoint".to_string()
            })?;
            let identity = spec.agent_lifecycle.as_ref().ok_or_else(|| {
                "managed initial Codex parent is missing lifecycle identity".to_string()
            })?;
            let grant = spec
                .verified_live_token_grant()
                .inspect_err(|_| cancellation.cancel())?;
            let run_id = identity.run_id.as_str();
            let task_id = identity.task_id.as_str();
            let mut forward = |request: &serde_json::Value| {
                launch
                    .forward_worker_request(run_id, task_id, request, &|| {
                        cancellation.is_cancelled() || grant.is_some_and(|grant| grant.stopped())
                    })
                    .map_err(|error| error.to_string())
            };
            run_observed_app_server_turn(
                &mut transport,
                &turn,
                spec,
                &mut reviewer,
                Some(&mut forward),
                &cancellation,
            )
        } else {
            run_observed_app_server_turn(
                &mut transport,
                &turn,
                spec,
                &mut reviewer,
                None,
                &cancellation,
            )
        }?;
        if let Err(error) =
            validate_read_only_terminal_app_server_outcome(&outcome, approval_requested)
        {
            fail_app_server_outcome(&mut outcome, error);
        }
        // Duplex auto-review coverage is unnecessary here: the inner workspace is read-only,
        // the existing verified outer profile remains enforced, and every approval cancels.
        Ok(outcome)
    })
}

fn run_managed_worker_app_server_turn<T: codex_app_server::JsonLineTransport>(
    transport: &mut T,
    turn: &codex_app_server::AppServerTurn,
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
) -> Result<codex_app_server::AppServerOutcome, String> {
    let mut approval_requested = false;
    let mut reviewer = |_: codex_app_server::ApprovalRequest| {
        approval_requested = true;
        Ok(codex_app_server::ApprovalReview::cancel(None))
    };
    // No dynamic Worker tool or callback. Native in-scope edits use the unchanged
    // workspace-write profile; approval and permission expansion always cancel.
    let mut outcome =
        run_observed_app_server_turn(transport, turn, spec, &mut reviewer, None, cancellation)?;
    if approval_requested || outcome.refused_ceiling_expansions != 0 {
        cancellation.cancel();
        fail_app_server_outcome(
            &mut outcome,
            "managed writable Worker app-server refused an approval or permission expansion"
                .to_string(),
        );
    }
    Ok(outcome)
}

fn run_managed_worker_app_server_process_with_auth(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    auth: Option<&ValidatedCodexAuth>,
) -> Result<InteractiveProcessOutput<codex_app_server::AppServerOutcome>, ProcessRunError> {
    let turn = codex_app_server::AppServerTurn {
        cwd: spec.cwd.to_string_lossy().into_owned(),
        permission_profile: "maco_external_codex".to_string(),
        prompt,
        model: spec.model.clone(),
        minimum_effort: None,
        output_schema: load_codex_app_server_output_schema(spec)?,
    };
    let cancellation = cancellation.child_scope();
    run_codex_interactive_process(process_spec, &cancellation, auth, |session| {
        let mut transport = codex_app_server::ContainedJsonLineTransport::new(session);
        run_managed_worker_app_server_turn(&mut transport, &turn, spec, &cancellation)
    })
}

fn load_codex_app_server_output_schema(
    spec: &ExternalAgentCommand,
) -> Result<Option<serde_json::Value>, ProcessRunError> {
    let Some(path) = spec.output_schema.as_ref() else {
        return Ok(None);
    };
    let bytes = read_bounded_regular_file_nofollow(path, 1024 * 1024).map_err(|source| {
        ProcessRunError::IoSetup {
            label: "Codex app-server output schema".to_string(),
            command: spec.program.display().to_string(),
            source,
        }
    })?;
    let schema = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
        ProcessRunError::IoSetup {
            label: "Codex app-server output schema".to_string(),
            command: spec.program.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        }
    })?;
    if !schema.is_object() {
        return Err(ProcessRunError::IoSetup {
            label: "Codex app-server output schema".to_string(),
            command: spec.program.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "output schema root must be an object",
            ),
        });
    }
    Ok(Some(schema))
}

fn validate_read_only_terminal_app_server_outcome(
    outcome: &codex_app_server::AppServerOutcome,
    approval_requested: bool,
) -> Result<(), String> {
    // The shared driver currently cancels immediately. Retain this independent guard so a
    // later Completed turn after an empty permission grant can never erase the refusal.
    if approval_requested || outcome.refused_ceiling_expansions != 0 {
        return Err("read-only terminal Codex app-server refused an approval request".to_string());
    }
    if outcome.status != codex_app_server::TurnTerminalStatus::Completed
        || outcome
            .item_outcomes
            .iter()
            .any(|item| item.item_type == "fileChange")
    {
        return Err(
            "read-only terminal Codex app-server refused a non-completed turn or file change"
                .to_string(),
        );
    }
    Ok(())
}

fn run_duplex_app_server_process_with_auth(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    runtime: &mut ExternalPreActionReviewRuntime<'_>,
    auth: Option<&ValidatedCodexAuth>,
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
        minimum_effort: None,
        output_schema: match load_codex_app_server_output_schema(spec) {
            Ok(schema) => schema,
            Err(error) => {
                return DuplexProcessAttempt {
                    process: Err(error),
                    metrics: reviewer.reviewer.metrics(),
                    gate_denials: Vec::new(),
                };
            }
        },
    };
    let cancellation = cancellation.child_scope();
    let mut process = run_codex_interactive_process(process_spec, &cancellation, auth, |session| {
        let mut transport = codex_app_server::ContainedJsonLineTransport::new(session);
        let mut outcome = run_observed_app_server_turn(
            &mut transport,
            &turn,
            spec,
            &mut reviewer,
            None,
            &cancellation,
        )?;
        if outcome.protocol_error.is_some() {
            return Ok(outcome);
        }
        let validation = (|| {
            let fallback_denial =
                duplex_fallback_denial(runtime.context, &review_session_id, &outcome).map_err(
                    |error| format!("failed to construct duplex fallback refusal: {error:#}"),
                )?;
            reviewer
                .journal
                .append(&terminal_turn_journal_record(
                    runtime.context.run_id(),
                    &review_session_id,
                    &outcome,
                    fallback_denial.as_ref(),
                ))
                .map_err(|error| {
                    format!("strict turn-terminal journal append failed: {error:#}")
                })?;
            if let Some(denial) = fallback_denial {
                reviewer.observed_denials.push(denial);
                return Err(
                    "child refused because mandatory duplex pre-action fallback was required"
                        .to_string(),
                );
            }
            Ok(())
        })();
        if let Err(error) = validation {
            fail_app_server_outcome(&mut outcome, error);
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
            let error = format!("strict process-terminal journal append failed: {error:#}");
            match &mut result.interaction {
                Ok(outcome) => fail_app_server_outcome(outcome, error),
                Err(previous) => *previous = format!("{previous}; {error}"),
            }
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
    original_spec: &'a ExternalAgentCommand,
    protected_controls: &'a ProtectedWorktreeControls,
    argv_digest: &'a str,
    program_identity: &'a ExternalProgramIdentity,
    grok_acp_parent_evidence: Option<&'a GrokAcpParentEvidence>,
    grok_acp_launch_schema_identity: Option<&'a GrokAcpBoundOutputSchema>,
    claude_broker_witness: Option<(&'a ClaudeWholeCallWitness, &'a ClaudeBrokerBinding)>,
}

struct GrokAcpInteractiveOutcome {
    evidence: GrokAcpExecutionEvidence,
    launch_schema: Option<GrokAcpBoundOutputSchema>,
}

fn run_grok_acp_external_process(
    process_spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    spec: &ExternalAgentCommand,
    prompt: String,
    operation_timeout: Duration,
) -> Result<InteractiveProcessOutput<GrokAcpInteractiveOutcome>, ProcessRunError> {
    if spec.workspace_access == WorkspaceAccess::ReadWrite {
        let context = LaunchContext {
            prompt: &spec.prompt,
            model: spec.model.as_deref(),
            effort: spec.reasoning_effort.as_deref(),
            cwd: &spec.cwd,
            output: &spec.output_last_message,
        };
        let contract = spec
            .runtime_adapter
            .as_ref()
            .and_then(|config| config.grok_acp_process_contract(&context, &process_spec));
        if contract.is_none() {
            return Err(ProcessRunError::IoSetup {
                label: "Grok ACP launch contract".to_string(),
                command: spec.program.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Grok ACP process lost its bounded descriptor or forced leaf environment",
                ),
            });
        }
    }
    let launch_schema =
        bind_grok_acp_launch_schema(spec).map_err(|error| ProcessRunError::IoSetup {
            label: "Grok ACP output schema".to_string(),
            command: spec.program.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()),
        })?;
    let turn = GrokAcpTurn {
        cwd: spec.cwd.to_string_lossy().into_owned(),
        prompt,
        requested_model: spec.model.clone(),
        requested_effort: spec.reasoning_effort.clone(),
        output_schema: launch_schema.clone(),
    };
    let limits =
        GrokAcpLimits::from_parent_operation_timeout(operation_timeout).map_err(|error| {
            ProcessRunError::IoSetup {
                label: "Grok ACP stdio".to_string(),
                command: spec.program.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()),
            }
        })?;
    let mut steering_bridge = spec
        .agent_lifecycle
        .as_ref()
        .map(GrokAcpSteeringBridge::from_identity)
        .transpose()
        .map_err(|error| ProcessRunError::IoSetup {
            label: "Grok ACP steering bridge".to_string(),
            command: spec.program.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()),
        })?;

    let interactive = run_process_interactive(process_spec, cancellation, |session| {
        let mut transport = GrokAcpContainedTransport::new(session);
        let cancelled = || cancellation.is_cancelled();
        let evidence = if let Some(bridge) = steering_bridge.as_mut() {
            crate::runtime_adapter::grok_acp::run_grok_acp_turn_with_steering(
                &mut transport,
                &turn,
                limits,
                cancelled,
                bridge,
            )
        } else {
            crate::runtime_adapter::grok_acp::run_grok_acp_turn(
                &mut transport,
                &turn,
                limits,
                cancelled,
            )
        }
        .map_err(|error| error.to_string())?;
        Ok(GrokAcpInteractiveOutcome {
            evidence,
            launch_schema: turn.output_schema.clone(),
        })
    });

    if let Some(bridge) = steering_bridge {
        bridge
            .finalize_after_child_exit()
            .map_err(|error| ProcessRunError::IoSetup {
                label: "Grok ACP steering finalization".to_string(),
                command: spec.program.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()),
            })?;
    }

    interactive
}

fn bind_grok_acp_launch_schema(
    spec: &ExternalAgentCommand,
) -> Result<Option<GrokAcpBoundOutputSchema>> {
    let Some(path) = spec.output_schema.as_ref() else {
        return Ok(None);
    };
    let canonical = crate::runtime_adapter::grok::load_grok_output_schema_argv(path)?;
    Ok(Some(
        GrokAcpBoundOutputSchema::from_canonical_json(&canonical)
            .map_err(|error| anyhow::anyhow!("{error}"))?,
    ))
}

fn grok_acp_parent_resolved_as_str(field: &GrokAcpParentResolvedField) -> Option<&str> {
    match field {
        GrokAcpParentResolvedField::Known(value) => Some(value.as_str()),
        GrokAcpParentResolvedField::Unknown => None,
    }
}

fn grok_acp_parent_identity_publication_refusal(
    spec: &ExternalAgentCommand,
    evidence: Option<&GrokAcpParentEvidence>,
) -> Option<&'static str> {
    let Some(evidence) = evidence else {
        return Some(
            "Grok ACP publication refused: resolved identity evidence is missing or incomplete",
        );
    };
    grok_acp_admitted_identity_publication_status(
        spec.model.as_deref(),
        spec.reasoning_effort.as_deref(),
        evidence.requested_model.as_deref(),
        evidence.requested_effort.as_deref(),
        grok_acp_parent_resolved_as_str(&evidence.client_resolved_model),
        grok_acp_parent_resolved_as_str(&evidence.client_resolved_effort),
        grok_acp_resolution_status_from_parent_label(&evidence.resolution_status),
    )
    .refusal_message()
}

fn grok_acp_staged_output_bytes(
    spec: &ExternalAgentCommand,
    evidence: &GrokAcpParentEvidence,
    target_completed_successfully: bool,
    launch_schema: Option<&GrokAcpBoundOutputSchema>,
) -> Result<Vec<u8>> {
    if !target_completed_successfully {
        bail!("Grok ACP target did not complete successfully");
    }
    if spec.output_schema.is_some() || launch_schema.is_some() {
        let Some(launch_schema) = launch_schema else {
            bail!("Grok ACP schema identity was not bound at launch");
        };
        if spec.output_schema.is_none() {
            bail!("Grok ACP launch schema identity has no admitted schema path");
        }
        if evidence.structured_output_error.is_some() {
            bail!("Grok ACP returned a terminal structuredOutputError");
        }
        let structured = evidence
            .structured_output
            .as_ref()
            .context("Grok ACP terminal response is missing structuredOutput")?;
        launch_schema
            .validate_structured_output(structured)
            .map_err(anyhow::Error::msg)?;
        return crate::runtime_adapter::grok::canonical_grok_structured_output(structured);
    }
    let text = evidence
        .final_text
        .as_deref()
        .context("Grok ACP terminal response is missing final text")?;
    Ok(text.as_bytes().to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeAdapterCapturedOutput {
    ExistingStagedOutput,
    Captured(Vec<u8>),
    Unavailable,
}

fn grok_bounded_stdout_usage_evidence(stdout: &CapturedBytes) -> GrokStreamUsageEvidence {
    if stdout.is_truncated() {
        return GrokStreamUsageEvidence::NotProcessObservable;
    }
    match crate::runtime_adapter::grok::parse_grok_event_stream(stdout.as_bytes()) {
        Ok(stream) => GrokStreamUsageEvidence::from_usage_status(stream.usage_status()),
        Err(_) => GrokStreamUsageEvidence::NotProcessObservable,
    }
}

#[cfg(test)]
fn runtime_adapter_captured_output(
    spec: &ExternalAgentCommand,
    stdout: &[u8],
    stderr: &[u8],
    target_completed_successfully: bool,
) -> Result<RuntimeAdapterCapturedOutput> {
    runtime_adapter_captured_output_with_claude_evidence(
        spec,
        stdout,
        stderr,
        target_completed_successfully,
        None,
    )
}

fn runtime_adapter_captured_output_with_claude_evidence(
    spec: &ExternalAgentCommand,
    stdout: &[u8],
    stderr: &[u8],
    target_completed_successfully: bool,
    claude_evidence: Option<&ClaudeNativeEvidence>,
) -> Result<RuntimeAdapterCapturedOutput> {
    if spec.invocation == ExternalAgentInvocation::Grok {
        if grok_acp_stdio_protocol_selected(spec) {
            return Ok(RuntimeAdapterCapturedOutput::ExistingStagedOutput);
        }
        if !target_completed_successfully {
            return Ok(RuntimeAdapterCapturedOutput::Unavailable);
        }
        let stream = crate::runtime_adapter::grok::parse_grok_event_stream(stdout)
            .context("Grok runtime output failed bounded streaming-json validation")?;
        if !stream.successful_completion() {
            // Retain raw terminal and usage evidence without reflecting child-controlled data.
            if stream.completed() {
                bail!("Grok runtime returned a non-success terminal streaming-json end event");
            }
            bail!("Grok runtime returned a terminal streaming-json error event");
        }
        if spec.output_schema.is_some() {
            let crate::runtime_adapter::grok::GrokStreamOutcome::Completed(end) = stream.outcome()
            else {
                bail!("Grok runtime did not return a completed terminal end event");
            };
            if end.structured_output_error().is_some() {
                // Never reflect the provider-controlled validation diagnostic: it may contain
                // report content or other sensitive data from the child session.
                bail!("Grok runtime returned a terminal structuredOutputError");
            }
            let structured = end
                .structured_output()
                .context("Grok runtime terminal end event is missing structuredOutput")?;
            return Ok(RuntimeAdapterCapturedOutput::Captured(
                crate::runtime_adapter::grok::canonical_grok_structured_output(structured)?,
            ));
        }
        return Ok(RuntimeAdapterCapturedOutput::Captured(
            stream.response_text().as_bytes().to_vec(),
        ));
    }

    if spec.invocation == ExternalAgentInvocation::ClaudeCode {
        if !target_completed_successfully {
            return Ok(RuntimeAdapterCapturedOutput::Unavailable);
        }
        let parsed;
        let evidence = match claude_evidence {
            Some(evidence) => evidence,
            None => {
                parsed = crate::runtime_adapter::claude::collect_native_stream(stdout, false);
                &parsed
            }
        };
        let result = evidence
            .result_text
            .as_ref()
            .context("Claude native stream is missing the terminal result text")?;
        return Ok(RuntimeAdapterCapturedOutput::Captured(result.clone()));
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

/// Parent-held handles into the private output staging root that target completion reads from
/// and publishes through. Both are descriptors the parent opened before the unit ran.
struct CompletedTargetStaging<'a> {
    /// The staged raw output leaf the contained agent wrote its last message to.
    output: &'a mut ReservedOutputFile,
    /// The parent-owned Codex home, present only for supervisor launches.
    codex_home: Option<&'a SecureOutputRoot>,
}

fn record_completed_app_server_target(
    report: &mut ExternalAgentRun,
    interactive: InteractiveProcessOutput<codex_app_server::AppServerOutcome>,
    output_staging: &mut ExternalOutputStaging,
    output_reservation: &mut ReservedOutputFile,
    json_log_reservation: &mut ReservedOutputFile,
    credential_redactor: &CredentialRedactor,
    context: CompletedTargetContext<'_>,
) {
    let launch_spec = context.spec;
    let protocol = interactive.interaction;
    let parent_evidence = output_staging.codex_home.as_ref().map(|codex_home| {
        let inputs = CodexParentEvidenceInputs {
            codex_version: context.codex_version,
            cwd: &context.spec.cwd,
            requested_model: context.spec.model.as_deref(),
            requested_effort: context.spec.reasoning_effort.as_deref(),
        };
        codex_parent_evidence_from_app_server_run(&inputs, protocol.as_ref().ok(), codex_home)
    });
    let mut final_message_error = None;
    if let Ok(outcome) = &protocol {
        report.retain_codex_command_execution_evidence(outcome);
        if let Some(error) = &outcome.protocol_error {
            report.error = append_external_error(
                report.error.take(),
                Some(credential_redactor.redact_string(error)),
            );
            report.publishable = false;
        }
        if let Some(final_message) = &outcome.final_message {
            let final_message = credential_redactor.redact_bytes(final_message.as_bytes());
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
    match output_staging.completion_handles() {
        Ok(staging) => record_completed_target(
            report,
            interactive.process,
            staging,
            output_reservation,
            json_log_reservation,
            credential_redactor,
            context,
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
    // record_completed_target handles ordinary `codex exec --json` launches.
    // Replace its CLI-stream interpretation only for this verified app-server turn.
    if let Some(evidence) = parent_evidence {
        report.stdout.run_metadata.codex_app_server_parent_evidence = Some(evidence.clone());
        report.codex_parent_evidence = Some(evidence);
    }
    // Capture token completion before an unavailable identity blocks acceptance.
    report.stdout.run_metadata.codex_app_server_usage_complete = report.exit_code == Some(0)
        && !report.timed_out
        && report.error.is_none()
        && report
            .codex_command_execution_evidence()
            .is_some_and(|evidence| {
                evidence.turn_status == codex_app_server::TurnTerminalStatus::Completed
            });
    report.qualify_codex_auditor_effort(launch_spec);
    if report
        .authenticated_app_server_evidence()
        .is_none_or(|evidence| evidence.resolution_status != "complete" || evidence.model_mismatch)
        || report.stdout.raw_capture_truncated()
    {
        report.error = append_external_error(
            report.error.take(),
            Some(
                "Codex app-server identity/usage resolution or raw capture is incomplete, or the observed model mismatches the requested model"
                    .to_string(),
            ),
        );
        report.publishable = false;
    }
    if protocol
        .as_ref()
        .is_ok_and(|outcome| outcome.protocol_error.is_some())
    {
        report.publishable = false;
    }
    if let Some(error) = final_message_error {
        report.error = append_external_error(report.error.take(), Some(error));
        report.publishable = false;
    }
    if let Err(error) = protocol {
        report.error = append_external_error(
            report.error.take(),
            Some(
                credential_redactor
                    .redact_string(&format!("Codex app-server protocol failed closed: {error}")),
            ),
        );
        report.publishable = false;
    }
}

fn record_completed_target(
    report: &mut ExternalAgentRun,
    output: ProcessOutput,
    staging: CompletedTargetStaging<'_>,
    output_reservation: &mut ReservedOutputFile,
    json_log_reservation: &mut ReservedOutputFile,
    credential_redactor: &CredentialRedactor,
    context: CompletedTargetContext<'_>,
) {
    let CompletedTargetStaging {
        output: staged_output,
        codex_home,
    } = staging;
    let safety_verified = output.safety_evidence_verified();
    let target_completed_successfully = !output.timed_out
        && output.status.is_some_and(|status| status.success())
        && output.process_error.is_none()
        && output.stdin_error.is_none();
    let mut claude_native_evidence =
        (context.spec.invocation == ExternalAgentInvocation::ClaudeCode).then(|| {
            crate::runtime_adapter::claude::collect_native_stream(
                output.stdout.as_bytes(),
                output.stdout.is_truncated(),
            )
        });
    if let (Some(evidence), Some((witness, binding))) =
        (&mut claude_native_evidence, context.claude_broker_witness)
    {
        evidence.attach_whole_call_witness(witness, binding);
    }
    if !target_completed_successfully {
        if let Some(evidence) = &mut claude_native_evidence {
            evidence.mark_interrupted();
        }
    }
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
    report.stdout.run_metadata.claude_native_evidence = claude_native_evidence.clone();
    report.stdout.run_metadata.sandbox_denials = sandbox_denials;
    report.stderr = summarize_redacted_output(&output.stderr, credential_redactor);
    if let Some(evidence) = context.grok_acp_parent_evidence {
        report.grok_acp_parent_evidence = Some(evidence.clone());
    } else if context.spec.invocation == ExternalAgentInvocation::Grok {
        report.grok_stream_usage_evidence =
            Some(grok_bounded_stdout_usage_evidence(&output.stdout));
    } else if context.spec.invocation == ExternalAgentInvocation::CodexSupervisor {
        // Codex evidence is derived only from parent-held captures: the stdout stream held by
        // the runner and the rollout below the parent-owned Codex home. A truncated stream can
        // no longer prove the run's shape, so it is withheld and resolves as invalid JSONL.
        if let Some(codex_home) = codex_home {
            let inputs = CodexParentEvidenceInputs {
                codex_version: context.codex_version,
                cwd: &context.spec.cwd,
                requested_model: context.spec.model.as_deref(),
                requested_effort: context.spec.reasoning_effort.as_deref(),
            };
            let stdout = (!output.stdout.is_truncated()).then(|| output.stdout.as_bytes());
            let evidence = codex_parent_evidence_from_run(&inputs, stdout, codex_home);
            report.stdout.run_metadata.codex_cli_parent_evidence = Some(evidence.clone());
            report.stdout.run_metadata.codex_cli_usage =
                stdout.and_then(|bytes| codex_usage_from_jsonl(bytes).ok().flatten());
            report.codex_parent_evidence = Some(evidence);
        }
    }
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
    if claude_native_evidence
        .as_ref()
        .is_some_and(|evidence| !evidence.complete())
    {
        report.error = append_external_error(
            report.error.take(),
            Some(
                "Claude native identity and usage coverage is incomplete for this invocation"
                    .to_string(),
            ),
        );
    }
    report.stdout.run_metadata.grok_read_only_completion_facts = None;
    let mut validated_grok_native_output_staged = false;
    let staged_output_available = match runtime_adapter_captured_output_with_claude_evidence(
        context.spec,
        output.stdout.as_bytes(),
        output.stderr.as_bytes(),
        target_completed_successfully,
        claude_native_evidence.as_ref(),
    )
    .and_then(|captured| qualify_grok_read_only_capture(context.original_spec, report, captured))
    {
        Ok(RuntimeAdapterCapturedOutput::ExistingStagedOutput) => true,
        Ok(RuntimeAdapterCapturedOutput::Captured(captured)) => {
            match staged_output.write_bytes_atomic(&captured, OUTPUT_TEE_LIMIT_BYTES) {
                Ok(()) => {
                    validated_grok_native_output_staged = context.spec.invocation
                        == ExternalAgentInvocation::Grok
                        && !grok_acp_stdio_protocol_selected(context.spec);
                    true
                }
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
            Ok(bytes) => {
                report.output_last_message = Some(bytes);
                if validated_grok_native_output_staged {
                    retain_held_grok_read_only_completion_facts(
                        report,
                        context.original_spec,
                        context.runtime,
                    );
                }
            }
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
    if context.runtime == ExternalExecutionRuntime::Verified
        && grok_acp_stdio_protocol_selected(context.spec)
    {
        if let Some(message) = grok_acp_parent_identity_publication_refusal(
            context.spec,
            context.grok_acp_parent_evidence,
        ) {
            report.error = append_external_error(report.error.take(), Some(message.to_string()));
        }
        if context.spec.output_schema.is_some() && context.grok_acp_launch_schema_identity.is_none()
        {
            report.error = append_external_error(
                report.error.take(),
                Some("Grok ACP schema identity was not bound at launch".to_string()),
            );
        }
    }
    if context.runtime == ExternalExecutionRuntime::Verified
        && context.spec.invocation == ExternalAgentInvocation::Cursor
    {
        if let Some(message) = cursor_managed_publication_refusal(
            context.spec,
            report.cursor_managed_parent_evidence.as_ref(),
        ) {
            report.error = append_external_error(report.error.take(), Some(message));
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
        && report.error.is_none()
        && !report
            .grok_acp_parent_evidence
            .as_ref()
            .is_some_and(|evidence| evidence.permission_escalation_refused);
    report.stdout.run_metadata.codex_cli_usage_complete = report.publishable;
    if report.codex_command_execution_evidence().is_none()
        && report
            .stdout
            .run_metadata
            .codex_cli_parent_evidence
            .as_ref()
            .is_some_and(|evidence| {
                evidence.model_mismatch || report.stdout.run_metadata.codex_cli_usage.is_none()
            })
    {
        report.publishable = false;
    }
}

fn cursor_managed_publication_refusal(
    spec: &ExternalAgentCommand,
    evidence: Option<&crate::runtime_adapter::CursorManagedParentEvidence>,
) -> Option<String> {
    let Some(evidence) = evidence else {
        return Some("managed Cursor parent evidence is missing".to_string());
    };
    if !evidence.peer_verified
        || evidence.session_resource_acks == 0
        || evidence.shared_services_acks == 0
        || evidence.shared_services_refusals != 0
        || evidence.refused_actions != 0
        || evidence.admitted_attempts == 0
        || evidence.admitted_attempts != evidence.completed_attempts
        || evidence.usage_attempts_covered != evidence.admitted_attempts
        || evidence.usage_attempts_incomplete != 0
        || evidence.captured_events == 0
        || evidence.usage_is_incomplete != Some(false)
    {
        return Some(
            "managed Cursor parent evidence is incomplete or contains a refused authority path"
                .to_string(),
        );
    }
    if spec.workspace_access == WorkspaceAccess::ReadWrite
        && (evidence.filesystem_writes == 0 || evidence.offline_checks == 0)
    {
        return Some(
            "managed Cursor writable run did not prove an assigned write and parent-owned offline check"
                .to_string(),
        );
    }
    if spec
        .model
        .as_ref()
        .is_some_and(|model| evidence.actual_provider_model.as_ref() != Some(model))
        || spec
            .reasoning_effort
            .as_ref()
            .is_some_and(|effort| evidence.actual_effort.as_ref() != Some(effort))
    {
        return Some(
            "managed Cursor observed model or effort does not match the selected launch"
                .to_string(),
        );
    }
    None
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

pub(crate) fn refused_external_run_before_launch(
    spec: &ExternalAgentCommand,
    error: String,
) -> ExternalAgentRun {
    failed_external_run(
        spec,
        Instant::now(),
        command_display(&spec.program, &[]),
        false,
        error,
    )
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
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        cursor_managed_parent_evidence: None,
        codex_parent_evidence: None,
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
    preserve_unquiescent: bool,
    root_path: PathBuf,
    reservation: Option<ReservedOutputFile>,
    /// Exact parent-created Grok prompt leaf; never a writable staging-root grant.
    worker_effective_prompt: Option<ReservedOutputFile>,
    /// Parent-owned `CODEX_HOME` for supervisor launches. It lives below the staging root so
    /// the unit already binds it read-write, and it outlives the unit so the parent can read
    /// the Codex rollout before the whole staging root is removed or quarantined.
    codex_home: Option<SecureOutputRoot>,
    machine_global_retention: Option<ExternalMachineGlobalRetentionBinding>,
    bound_store: Option<MachineGlobalStore>,
    bound_root_reservation: Option<ReservedDirectory>,
    cleanup_completed: bool,
}

/// Name of the parent-owned Codex home below the private output staging root.
const CODEX_HOME_STAGING_NAME: &str = "codex-home";

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
                worker_effective_prompt: None,
                codex_home: None,
                machine_global_retention: Some(binding),
                bound_store: Some(store),
                bound_root_reservation: Some(root_reservation),
                cleanup_completed: false,
                preserve_unquiescent: false,
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
                worker_effective_prompt: None,
                codex_home: None,
                machine_global_retention: None,
                bound_store: None,
                bound_root_reservation: None,
                cleanup_completed: false,
                preserve_unquiescent: false,
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

    #[cfg(target_os = "linux")]
    fn stage_worker_effective_prompt(
        &mut self,
        writable_workspace: &Path,
        prompt: &[u8],
    ) -> Result<PathBuf> {
        if self.worker_effective_prompt.is_some() {
            bail!("private output staging already holds a Worker effective prompt");
        }
        let root = SecureOutputRoot::open_private(&self.root_path)?;
        root.reject_inside(writable_workspace)?;
        let reservation = root.reserve(OsStr::new("worker-effective-prompt.md"))?;
        // Register cleanup ownership before any fallible write or launch binding.
        let reserved = self.worker_effective_prompt.insert(reservation);
        reserved.write_bytes_atomic(prompt, MAX_PROMPT_BYTES)?;
        Ok(reserved.path().to_path_buf())
    }

    /// Creates the parent-owned `CODEX_HOME` as a 0700 direct child of the staging root.
    ///
    /// The staging root is already bound read-write into the unit, so no additional sandbox
    /// path is opened. The directory is removed with the staging root during cleanup.
    fn stage_codex_home(&mut self) -> Result<&Path> {
        if self.codex_home.is_some() {
            bail!("private output staging already holds a Codex home");
        }
        let root = SecureOutputRoot::open_private(&self.root_path)?;
        let home = root
            .create_child(OsStr::new(CODEX_HOME_STAGING_NAME))
            .context("failed to stage the parent-owned Codex home")?;
        Ok(self.codex_home.insert(home).path())
    }

    /// Borrows the staged output leaf together with the parent-owned Codex home (when staged)
    /// so target completion can publish output and read the rollout from held descriptors.
    fn completion_handles(&mut self) -> Result<CompletedTargetStaging<'_>> {
        let output = self
            .reservation
            .as_mut()
            .context("private output staging reservation was already cleaned")?;
        Ok(CompletedTargetStaging {
            output,
            codex_home: self.codex_home.as_ref(),
        })
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
                // The exact prompt leaf travels with the private quarantine.
                self.worker_effective_prompt.take();
                // The staged Codex home travels with the quarantined staging root.
                self.codex_home.take();
                self.bound_root_reservation.take();
                self.bound_store.take();
                self.cleanup_completed = true;
                Ok(ExternalOutputCleanup::Quarantined(operation))
            }
            GateOutcome::Denied(denial) => Ok(ExternalOutputCleanup::Denied(denial)),
        }
    }

    fn cleanup_inner(&mut self) -> Result<()> {
        if let Some(prompt) = self.worker_effective_prompt.take() {
            prompt
                .remove()
                .context("failed to remove held Worker effective prompt")?;
        }
        if let Some(reservation) = self.reservation.take() {
            reservation
                .remove()
                .context("failed to remove reserved raw output staging leaf")?;
        }
        if let Some(codex_home) = self.codex_home.take() {
            remove_staged_codex_home(codex_home)?;
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
        if self.cleanup_completed || self.preserve_unquiescent {
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

/// Removes the parent-owned Codex home together with every session, log, and state file the
/// contained Codex process wrote below it. The held directory identity is re-verified first so
/// a rebound pathname can never redirect the recursive removal.
fn remove_staged_codex_home(codex_home: SecureOutputRoot) -> Result<()> {
    codex_home
        .verify_path_identity()
        .context("staged Codex home identity changed before removal")?;
    fs::remove_dir_all(codex_home.path()).with_context(|| {
        format!(
            "failed to remove staged Codex home {}",
            codex_home.path().display()
        )
    })
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
    fixed_version_probe_evidence: Option<EnvironmentFixedVersionProbeEvidence>,
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
        if let Some(evidence) = error.registration_rollback_evidence() {
            let verified = evidence.process_tree.is_verified_empty()
                && evidence.side_effects.is_verified()
                && evidence.process_error.is_none()
                && evidence.stdin_error.is_none();
            self.record(
                if verified {
                    evidence.process_tree
                } else {
                    ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
                },
                evidence.side_effects,
                verified,
            );
            return;
        }
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
            | ProcessRunError::Spawn { .. }
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
            | ProcessRunError::Spawn { .. }
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
    invocation: ExternalAgentInvocation,
) -> Option<(EnvironmentFailureCategory, Option<EnvironmentRequirement>)> {
    match error {
        ProcessRunError::ContainmentUnavailable { .. }
        | ProcessRunError::ProcessOwnership { .. } => Some((
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(external_sandbox_requirement(invocation)),
        )),
        ProcessRunError::EnvironmentFailure { failure, .. } => Some((
            failure.category,
            (failure.category == EnvironmentFailureCategory::SandboxUnavailable)
                .then(|| external_sandbox_requirement(invocation)),
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
    report.stdout.run_metadata.fixed_version_probe_evidence =
        evidence.fixed_version_probe_evidence.clone();
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
    credential_redactor: Option<&CredentialRedactor>,
    process_evidence: &mut EnvironmentPreflightProcessEvidence,
) -> std::result::Result<EnvironmentVersionProbe, CodexPreflightFailure> {
    let requirement = codex_environment_requirement();
    let version = run_fixed_version_probe(
        EnvironmentExecutable::Codex,
        ExternalAgentInvocation::CodexSupervisor,
        program,
        cwd,
        timeout,
        cancellation,
        environment,
        side_effect_profile,
        codex_auth,
        agent_lifecycle,
        credential_redactor,
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
        None,
        process_evidence,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_grok_environment_preflight(
    spec: &ExternalAgentCommand,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    profile: &SideEffectConfinementProfile,
    credentials: Option<&BoundGrokCredentials<'_>>,
    lifecycle: Option<&AgentLaunchMetadata>,
    credential_redactor: &CredentialRedactor,
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
    let auth = grok_auth_environment_requirement();
    let (result, failure, _) = evaluate_environment_requirement(
        &auth,
        ExternalAgentInvocation::Grok,
        &spec.cwd,
        timeout,
        cancellation,
        environment,
        profile,
        None,
        credentials,
        None,
        None,
        lifecycle,
        None,
        &mut report.process_evidence,
    );
    report.results.push(result);
    if let Some(failure) = failure {
        report.failures.push(failure);
        return report;
    }

    // Prove the actual bound sandbox with a fixed no-op, never the provider or Codex.
    let probe_program = [
        "/usr/bin/true",
        "/bin/true",
        "/run/current-system/sw/bin/true",
    ]
    .into_iter()
    .map(Path::new)
    .find(|path| path.is_file())
    .unwrap_or_else(|| Path::new("/usr/bin/true"));
    let probe = with_external_runtime_context(
        ProcessSpec::direct(
            "Grok sandbox preflight",
            probe_program,
            std::iter::empty::<&str>(),
            &spec.cwd,
            4096,
        )
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(timeout.saturating_sub(started.elapsed()))),
        environment.clone(),
        profile.clone(),
        ExternalAgentInvocation::Grok,
        None,
        lifecycle,
        None,
    );
    match run_process_cancellable(probe, cancellation) {
        Ok(output) => {
            report.process_evidence.record_output(&output);
            report.timed_out = output.timed_out;
            if output.safety_sensitive_succeeded()
                && output.side_effects
                    == SideEffectConfinementEvidence::Verified(
                        SideEffectConfinementProfileKind::ExternalGrok,
                    )
            {
                report.verified_confinement = Some(SideEffectConfinementProfileKind::ExternalGrok);
            }
        }
        Err(error) => {
            report.process_evidence.record_error(&error);
            report.timed_out = matches!(error, ProcessRunError::SetupTimeout { .. });
        }
    }
    let sandbox = external_sandbox_requirement(ExternalAgentInvocation::Grok);
    for requirement in std::iter::once(&sandbox).chain(
        spec.environment_requirements
            .iter()
            .filter(|r| **r != auth && **r != sandbox),
    ) {
        let (result, failure, timed_out) = evaluate_environment_requirement(
            requirement,
            ExternalAgentInvocation::Grok,
            &spec.cwd,
            timeout.saturating_sub(started.elapsed()),
            cancellation,
            environment,
            profile,
            None,
            credentials,
            None,
            report.verified_confinement,
            lifecycle,
            Some(credential_redactor),
            &mut report.process_evidence,
        );
        report.results.push(result);
        if let Some(failure) = failure {
            report.failures.push(failure);
        }
        report.timed_out |= timed_out;
        if !report.failures.is_empty() {
            break;
        }
    }
    report
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
    grok_credentials: Option<&BoundGrokCredentials<'_>>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    credential_redactor: Option<&CredentialRedactor>,
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
        credential_redactor,
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
            spec.invocation,
            &spec.cwd,
            remaining,
            cancellation,
            environment,
            side_effect_profile,
            codex_auth,
            grok_credentials.filter(|_| spec.invocation == ExternalAgentInvocation::Grok),
            report.codex_version,
            report.verified_confinement,
            agent_lifecycle,
            credential_redactor,
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
    invocation: ExternalAgentInvocation,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    side_effect_profile: &SideEffectConfinementProfile,
    codex_auth: Option<&ValidatedCodexAuth>,
    grok_credentials: Option<&BoundGrokCredentials<'_>>,
    observed_codex_version: Option<EnvironmentVersion>,
    verified_confinement: Option<SideEffectConfinementProfileKind>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    credential_redactor: Option<&CredentialRedactor>,
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
                        invocation,
                        &program,
                        cwd,
                        timeout,
                        cancellation,
                        environment,
                        side_effect_profile,
                        codex_auth,
                        agent_lifecycle,
                        credential_redactor,
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
            let present = configuration_present(
                *configuration,
                codex_auth,
                grok_credentials,
                side_effect_profile,
            );
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
            let verified_networked_grok = verified_confinement
                == Some(SideEffectConfinementProfileKind::ExternalGrok)
                && matches!(
                    side_effect_profile,
                    SideEffectConfinementProfile::ExternalGrok(_)
                );
            let verified_parent_relayed_claude = verified_confinement
                == Some(SideEffectConfinementProfileKind::ExternalClaude)
                && matches!(
                    side_effect_profile,
                    SideEffectConfinementProfile::ExternalClaude(_)
                );
            let verified_networked_cursor = verified_confinement
                == Some(SideEffectConfinementProfileKind::ExternalCursor)
                && matches!(
                    side_effect_profile,
                    SideEffectConfinementProfile::ExternalCursor(_)
                );
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
            } else if *access == EnvironmentNetworkAccess::Enabled
                && (verified_networked_grok
                    || verified_parent_relayed_claude
                    || verified_networked_cursor)
            {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::Network {
                            enabled: true,
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
                        "the supervised child requires network access, but its fixed permission profile did not verify network access"
                            .to_string(),
                    )),
                    false,
                )
            }
        }
        EnvironmentRequirement::Sandbox { capability } => {
            let required_profile = match capability {
                EnvironmentSandboxCapability::VerifiedExternalCodex => {
                    SideEffectConfinementProfileKind::ExternalCodex
                }
                EnvironmentSandboxCapability::VerifiedExternalClaude => {
                    SideEffectConfinementProfileKind::ExternalClaude
                }
                EnvironmentSandboxCapability::VerifiedExternalGrok => {
                    SideEffectConfinementProfileKind::ExternalGrok
                }
                EnvironmentSandboxCapability::VerifiedExternalCursor => {
                    SideEffectConfinementProfileKind::ExternalCursor
                }
            };
            let verified = verified_confinement == Some(required_profile);
            if verified {
                (
                    EnvironmentPreflightResult {
                        requirement: requirement.clone(),
                        status: EnvironmentPreflightStatus::Satisfied,
                        observation: Some(EnvironmentPreflightObservation::Sandbox {
                            profile: required_profile,
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
                        format!(
                            "the fixed {required_profile:?} confinement profile was not safely verified"
                        ),
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
    fn preflight_spawn_failure_keeps_never_spawned_proof() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let error = run_process_cancellable(
            ProcessSpec::direct(
                "auditor version preflight",
                temp.path().join("missing-codex"),
                ["--version"],
                temp.path(),
                128,
            ),
            &ProcessCancellation::new(),
        )
        .expect_err("missing executable must fail before spawning");
        assert!(matches!(error, ProcessRunError::Spawn { .. }));
        assert!(process_run_error_definitely_before_process_start(&error));
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.record_error(&error);
        assert!(!evidence.started);
        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        let mut report = explicit_custom_policy_refusal(&command);
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        assert!(report.scratch_quiescence_verified());
        assert!(report.environment_preflight_quiescence_verified());

        // A later failure before spawn cannot erase an earlier unverified probe.
        evidence.record(
            ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
            SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            false,
        );
        evidence.record_error(&error);
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        assert!(!report.scratch_quiescence_verified());
        Ok(())
    }

    #[test]
    fn preflight_registration_failure_requires_verified_rollback() -> Result<()> {
        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        for (tree_verified, effects_verified, cleanup_failed) in [
            (true, true, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let error = ProcessRunError::agent_registration_failed(
                "auditor version preflight".to_string(),
                "codex --version".to_string(),
                "failed to register launched agent".to_string(),
                crate::process_runner::ProcessFailureEvidence {
                    stdout: CapturedBytes::default(),
                    stderr: CapturedBytes::default(),
                    process_tree: if tree_verified {
                        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
                    } else {
                        ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
                    },
                    side_effects: if effects_verified {
                        SideEffectConfinementEvidence::Verified(
                            SideEffectConfinementProfileKind::ExternalCodex,
                        )
                    } else {
                        SideEffectConfinementEvidence::Unverified(
                            SideEffectConfinementProfileKind::ExternalCodex,
                        )
                    },
                    process_error: cleanup_failed.then(|| "rollback failed".to_string()),
                    stdin_error: None,
                },
            );
            assert!(!process_run_error_definitely_before_process_start(&error));
            let mut evidence = EnvironmentPreflightProcessEvidence::default();
            evidence.record_error(&error);
            assert!(evidence.started, "the containment wrapper was spawned");
            let mut report = explicit_custom_policy_refusal(&command);
            retain_environment_preflight_process_evidence(&mut report, &evidence);
            let expected = tree_verified && effects_verified && !cleanup_failed;
            assert_eq!(report.scratch_quiescence_verified(), expected);
            assert_eq!(report.environment_preflight_quiescence_verified(), expected);
            assert!(!report.succeeded());
            report.process_tree = None;
            report.side_effects = None;
            assert_eq!(report.scratch_quiescence_verified(), expected);
            let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&report)?)?;
            assert!(!restored.scratch_quiescence_verified());
        }
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.record_error(&ProcessRunError::ProcessOwnership {
            label: "auditor version preflight".to_string(),
            command: "codex --version".to_string(),
            source: std::io::Error::other(
                "failed to register launched agent; cleanup verified empty",
            ),
        });
        let mut report = explicit_custom_policy_refusal(&command);
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        assert!(
            !report.scratch_quiescence_verified(),
            "text is not rollback proof"
        );
        Ok(())
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
mod managed_readonly_route_tests;
#[cfg(test)]
mod tests;
