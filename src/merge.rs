pub use crate::merge_freshness::{
    MergeApplyReviewRefusalEnvelope, MergePreviewDriftAxis, MergePreviewFreshnessError,
    MergePreviewFreshnessWatermark, MergeReviewBindingStatus,
};
pub use crate::merge_semantic::{
    SemanticConflictClassification, SemanticConflictClassificationStatus,
    SemanticConflictConfidence, SemanticConflictDependencyImpact, SemanticConflictDependencySide,
    SemanticConflictImport, SemanticConflictLineRange, SemanticConflictOverlap,
    SemanticConflictOverlapKind, SemanticConflictRisk, SemanticConflictSide,
    SemanticConflictSymbol,
};
use crate::{
    artifacts::{
        state_auth::sha256_hex, ArtifactFileDisposition, ArtifactRunWriter, RunArtifactFamily,
    },
    external_agent::{
        run_external_agent, ExternalAgentCommand, ExternalMachineGlobalRetentionBinding,
    },
    gate_denial::{GateCheckSource, GateDenial},
    llm::Redactor,
    megafile::{MegafileAssessment, MegafileStore, MegafileThresholds},
    merge_semantic::{classify_semantic_candidate_pair, classify_semantic_conflicts},
    orchestration_event::{
        ArbitrationOutcome, ArbitrationOutcomeDetails, ArbitrationSide, OrchestrationEventJournal,
        OrchestrationRole,
    },
    orchestrator::RunId,
    process_runner::{
        run_process, ContainmentEvidence, EnvironmentMode, ProcessOutput, ProcessSpec, Shell,
        SideEffectConfinementEvidence, SideEffectConfinementProfile,
        SideEffectConfinementProfileKind, StdinMode, StrictOfflineWorkspaceProfile,
        TrustedFixedNetworkProfile, WorkspaceAccess,
    },
    semantic_coord::{SemanticIntent, SemanticIntentStore},
    supervise::{verified_megafile_decomposition_evidence, VerifiedMegafileDecompositionEvidence},
    sync::{normalize_repo_relative_path, PathClaim},
    sync_store::SyncStore,
    worktree::{
        normalize_agent_id, ManagedWorktreeReadLease, ManagedWorktreeWriteLease,
        NeutralWorktreeCreateOptions, WorktreeLifecycleReport, WorktreeManager, WorktreeRecord,
    },
};
use anyhow::{bail, Context, Result};
use git2::{ErrorCode, ObjectType, Oid, Repository, Status, StatusOptions};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fmt::Write as FmtWrite,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_DIFF_SUMMARY_CHAR_LIMIT: usize = 32 * 1024;
pub const VALIDATION_BINDING_VERSION: u32 = 1;
pub const ARBITRATION_INPUT_VERSION: u32 = 1;
pub const ARBITRATION_PROPOSAL_VERSION: u32 = 1;
pub const ARBITRATION_REPORT_VERSION: u32 = 1;
const CANDIDATE_CAPTURE_ATTEMPTS: usize = 3;
const MAX_ARBITRATION_INPUT_BYTES: usize = 768 * 1024;
const MAX_ARBITRATION_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_ARBITRATION_PROPOSAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARBITRATION_PATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARBITRATION_RATIONALE_BYTES: usize = 64 * 1024;
const MAX_ARBITRATION_VALIDATION_COMMANDS: usize = 128;
const MAX_ARBITRATION_CHANGED_PATHS: usize = 8 * 1024;
const ARBITRATION_INPUT_PATH: &str = "trusted/arbitration-input.json";
const ARBITRATION_PROMPT_PATH: &str = "trusted/arbitration-prompt.md";
const ARBITRATION_SCHEMA_PATH: &str = "trusted/arbitration-output.schema.json";
const ARBITRATION_RATIONALE_PATH: &str = "reports/arbitration-rationale.json";
const ARBITRATION_CANDIDATE_PATH: &str = "reports/arbitration-candidate.patch";
const ARBITRATION_FINAL_REPORT_PATH: &str = "reports/supervisor-final.json";
const ARBITRATION_INCOMING_DIR: &str = "arbiter-incoming";
const LOCK_RECORD_VERSION: u32 = 3;
const REPOSITORY_MUTATION_LOCK_FILE: &str = "repository-mutation.lock";
const MAX_LOCK_RECORD_BYTES: u64 = 4 * 1024;
const VALIDATION_RAW_MAX_ENTRIES: usize = 8 * 1024;
const VALIDATION_RAW_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const VALIDATION_RAW_MAX_SINGLE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const VALIDATION_MARKER_MAX_BYTES: u64 = 64 * 1024;
const MAX_BOUND_VALIDATION_REPORTS: usize = 1024;
const MAX_BOUND_VALIDATION_NAME_BYTES: usize = 1024;
const MAX_BOUND_VALIDATION_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_BOUND_VALIDATION_PATHS_PER_REPORT: usize = 8192;
pub(crate) const DEFAULT_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS: u64 = 120;
pub(crate) const MAX_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const LOCAL_GIT_PROCESS_TIMEOUT_ENV: &str = "MACO_MERGE_LOCAL_GIT_TIMEOUT_SECONDS";
const LOCAL_GIT_PROCESS_TIMEOUT_FLAG: &str = "--local-git-timeout-seconds";
const LOCAL_GIT_PROCESS_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS);
pub(crate) const NETWORK_PROCESS_TIMEOUT: Duration = Duration::from_secs(300);
const CANDIDATE_VALIDATION_PROCESS_TIMEOUT: Duration = Duration::from_secs(600);
const GIT_CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const VALIDATION_CAPTURE_LIMIT_BYTES: usize = 1024 * 1024;
const GIT_STDIN_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const REPOSITORY_INDEX_MAX_BYTES: u64 = 64 * 1024 * 1024;
const PRIVATE_RUNTIME_OWNER_VERSION: u32 = 1;
const PRIVATE_RUNTIME_OWNER_FILE: &str = "maco-runtime-owner.json";
const PRIVATE_RUNTIME_LOCK_FILE: &str = ".maco-private-runtime.lock";
const PRIVATE_RUNTIME_OWNER_MAX_BYTES: u64 = 4 * 1024;
const PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES: usize = 128;
const PRIVATE_RUNTIME_REMOVAL_MAX_ENTRIES: usize = 32 * 1024;
const PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum LocalGitProcessTimeoutError {
    #[error("local Git timeout must be an integer number of seconds, got {value:?}")]
    InvalidInteger { value: String },
    #[error("local Git timeout must be between 1 and {max_seconds} seconds, got {seconds}")]
    OutOfRange { seconds: u64, max_seconds: u64 },
}

pub(crate) fn parse_local_git_process_timeout(
    value: Option<&str>,
) -> std::result::Result<Duration, LocalGitProcessTimeoutError> {
    let Some(value) = value else {
        return Ok(LOCAL_GIT_PROCESS_TIMEOUT);
    };
    let seconds =
        value
            .parse::<u64>()
            .map_err(|_| LocalGitProcessTimeoutError::InvalidInteger {
                value: value.to_string(),
            })?;
    local_git_process_timeout_from_seconds(seconds)
}

fn local_git_process_timeout_from_seconds(
    seconds: u64,
) -> std::result::Result<Duration, LocalGitProcessTimeoutError> {
    let max_seconds = MAX_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS;
    if seconds == 0 || seconds > max_seconds {
        return Err(LocalGitProcessTimeoutError::OutOfRange {
            seconds,
            max_seconds,
        });
    }
    Ok(Duration::from_secs(seconds))
}

pub(crate) fn parse_local_git_process_timeout_seconds(
    value: &str,
) -> std::result::Result<u64, LocalGitProcessTimeoutError> {
    parse_local_git_process_timeout(Some(value)).map(|timeout| timeout.as_secs())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MergeLocalGitOptions {
    candidate_snapshot_diff_timeout: Duration,
    candidate_snapshot_diff_deadline_knobs: Option<(&'static str, &'static str)>,
}

impl MergeLocalGitOptions {
    pub(crate) fn from_seconds(
        seconds: u64,
    ) -> std::result::Result<Self, LocalGitProcessTimeoutError> {
        Ok(Self {
            candidate_snapshot_diff_timeout: local_git_process_timeout_from_seconds(seconds)?,
            candidate_snapshot_diff_deadline_knobs: Some((
                LOCAL_GIT_PROCESS_TIMEOUT_FLAG,
                LOCAL_GIT_PROCESS_TIMEOUT_ENV,
            )),
        })
    }
}

impl Default for MergeLocalGitOptions {
    fn default() -> Self {
        Self {
            candidate_snapshot_diff_timeout: LOCAL_GIT_PROCESS_TIMEOUT,
            candidate_snapshot_diff_deadline_knobs: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeCollectOptions {
    pub repo: PathBuf,
    pub agent_id: String,
    pub claimed_paths: Vec<PathBuf>,
    pub include_full_diff: bool,
    pub diff_summary_char_limit: usize,
    pub validations: Vec<ValidationReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergePreviewOptions {
    pub collect: MergeCollectOptions,
    pub forces: MergeForceOptions,
    pub require_validation: bool,
    pub review_intent: MergeApplyReviewIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeApplyOptions {
    pub preview: MergePreviewOptions,
    pub candidate_validation_commands: Vec<CandidateValidationCommand>,
    /// Mandatory evidence from the exact previously reviewed preview. Apply
    /// recaptures and compares every bound axis before any primary mutation.
    pub reviewed_watermark: MergePreviewFreshnessWatermark,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MergeApplyReviewIntent {
    pub candidate_validation_commands: Vec<String>,
    pub require_validation_after_candidate: bool,
    pub auto_reap_merged: bool,
    pub trunk_ref: Option<String>,
    pub apply_auto_reap: bool,
}

impl MergeApplyReviewIntent {
    pub fn validate(&self) -> Result<()> {
        if self
            .candidate_validation_commands
            .iter()
            .any(|command| command.trim().is_empty())
        {
            bail!("merge apply review intent contains an empty candidate validation command");
        }
        if self
            .trunk_ref
            .as_deref()
            .is_some_and(|trunk_ref| trunk_ref.trim().is_empty())
        {
            bail!("merge apply review intent contains an empty trunk reference");
        }
        if self.auto_reap_merged != self.trunk_ref.is_some() {
            bail!("merge apply review intent requires auto_reap_merged and trunk_ref together");
        }
        if self.apply_auto_reap && !self.auto_reap_merged {
            bail!("merge apply review intent apply_auto_reap requires auto_reap_merged");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MegafileMergePolicy {
    pub block: bool,
    pub decomposition_target: Option<PathBuf>,
    pub decomposition_run_id: Option<RunId>,
    pub thresholds: MegafileThresholds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateValidationCommand {
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeArbitrationOptions {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub arbiter_agent_id: String,
    pub sides: [ArbitrationSideSpec; 2],
    pub validation_commands: Vec<CandidateValidationCommand>,
    pub approve: bool,
    pub codex_bin: PathBuf,
    pub timeout: Duration,
    pub worktree_root: Option<PathBuf>,
    pub machine_global_config: PathBuf,
    pub machine_global_runtime_root_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArbitrationSideSpec {
    Agent {
        agent_id: String,
        claimed_paths: Vec<PathBuf>,
    },
    Primary,
}

impl ArbitrationSideSpec {
    fn journal_side(&self) -> ArbitrationSide {
        match self {
            Self::Agent { agent_id, .. } => ArbitrationSide::Agent {
                id: agent_id.clone(),
            },
            Self::Primary => ArbitrationSide::Primary,
        }
    }

    fn source_identity(&self) -> String {
        match self {
            Self::Agent { agent_id, .. } => agent_id.clone(),
            Self::Primary => "primary".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArbitrationNeutralWorktree {
    pub agent_id: String,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub branch: String,
    pub exact_base_oid: String,
    pub inherited_claim: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ArbitrationSideEvidence {
    pub participant: ArbitrationSide,
    pub head_oid: String,
    pub tree_oid: String,
    pub base_oid: String,
    pub diff_sha256: String,
    pub diff_bytes: usize,
    pub diff: String,
    #[serde(serialize_with = "serialize_paths")]
    pub changed_paths: Vec<PathBuf>,
    pub candidate_binding: Option<CandidateValidationBinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct ArbitrationInput {
    pub version: u32,
    pub arbiter_id: String,
    pub reviewed_base_oid: String,
    pub neutral_worktree: ArbitrationNeutralWorktree,
    pub sides: [ArbitrationSideEvidence; 2],
    pub relevant_path_claims: Vec<PathClaim>,
    pub relevant_semantic_intents: Vec<SemanticIntent>,
    pub semantic_classification: SemanticConflictClassification,
}

#[derive(Debug, Clone)]
struct PreparedMergeArbitration {
    pub input: ArbitrationInput,
    pub input_json: Vec<u8>,
    pub input_sha256: String,
    pub primary_repo_root: PathBuf,
    pub primary_state_sha256: String,
    pub source_diffs: [Vec<u8>; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArbitrationProposalDisposition {
    Proposed,
    Rejected,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArbitrationProposal {
    pub version: u32,
    pub input_sha256: String,
    pub disposition: ArbitrationProposalDisposition,
    pub rationale: String,
    pub candidate_patch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ArbitrationRunnerExecution {
    pub(crate) kind: String,
    trusted_local_boundary: bool,
    pub(crate) command: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArbitrationRunnerResult {
    proposal: ArbitrationProposal,
    execution: ArbitrationRunnerExecution,
}

#[derive(Debug, Clone)]
struct ArbitrationRunnerRequest {
    prompt_path: PathBuf,
    output_schema_path: PathBuf,
    output_last_message_path: PathBuf,
    json_log_path: PathBuf,
    neutral_worktree_path: PathBuf,
    hidden_primary_root: PathBuf,
    run_id: String,
    arbiter_id: String,
}

trait ArbitrationRunner {
    fn run(&self, request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult>;
}

#[derive(Debug, Clone)]
struct ExternalArbitrationRunner {
    codex_bin: PathBuf,
    timeout: Duration,
    machine_global_config: PathBuf,
    machine_global_runtime_root_id: String,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct StaticArbitrationRunner {
    output: Vec<u8>,
}

#[cfg(test)]
impl StaticArbitrationRunner {
    fn from_bytes(output: impl Into<Vec<u8>>) -> Result<Self> {
        let output = output.into();
        parse_arbitration_proposal(&output)?;
        Ok(Self { output })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArbitrationPreservationProof {
    pub side: ArbitrationSide,
    pub preserved: bool,
    pub required_additions: usize,
    pub preserved_additions: usize,
    pub required_deletions: usize,
    pub preserved_deletions: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MergeArbitrationReport {
    pub version: u32,
    pub run_id: String,
    pub arbiter_id: String,
    pub outcome: ArbitrationOutcome,
    pub approved: bool,
    pub primary_mutated: bool,
    pub later_ordinary_merge_apply_required: bool,
    pub reviewed_base_oid: String,
    pub sides: [ArbitrationSide; 2],
    pub neutral_worktree: ArbitrationNeutralWorktree,
    pub input_artifact: String,
    pub input_sha256: String,
    pub rationale_artifact: String,
    pub rationale_sha256: String,
    pub candidate_artifact: Option<String>,
    pub candidate_sha256: Option<String>,
    pub candidate_binding: Option<CandidateValidationBinding>,
    pub candidate_status: ValidationStatus,
    pub preservation: Vec<ArbitrationPreservationProof>,
    pub validation_commands: Vec<String>,
    pub validations: Vec<ValidationReport>,
    pub semantic_classification: SemanticConflictClassification,
    pub(crate) runner: ArbitrationRunnerExecution,
    pub reason: String,
}

trait ArbitrationEnvironment {
    fn prepare(&self, options: &MergeArbitrationOptions) -> Result<PreparedMergeArbitration>;

    fn materialize_candidate(
        &self,
        prepared: &PreparedMergeArbitration,
        proposal: &ArbitrationProposal,
    ) -> Result<MergeApplyPreview>;

    fn validate_candidate(
        &self,
        preview: &MergeApplyPreview,
        commands: &[CandidateValidationCommand],
    ) -> Result<Vec<ValidationReport>>;

    fn current_primary_state_sha256(&self, prepared: &PreparedMergeArbitration) -> Result<String>;
}

#[derive(Debug, Clone, Copy, Default)]
struct ProductionArbitrationEnvironment;

impl ArbitrationRunner for ExternalArbitrationRunner {
    fn run(&self, request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult> {
        let mut command = ExternalAgentCommand::codex(
            &self.codex_bin,
            &request.neutral_worktree_path,
            &request.prompt_path,
            &request.json_log_path,
            &request.output_last_message_path,
            self.timeout,
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_hidden_root(&request.hidden_primary_root)
        .with_agent_lifecycle(
            &request.hidden_primary_root,
            "arbiter",
            &request.run_id,
            &request.arbiter_id,
        )
        .with_machine_global_retention(ExternalMachineGlobalRetentionBinding {
            config: self.machine_global_config.clone(),
            root_id: self.machine_global_runtime_root_id.clone(),
            owner: request.arbiter_id.clone(),
            correction_correlation_id: request.run_id.clone(),
        });
        command.output_schema = Some(request.output_schema_path.clone());
        let run = run_external_agent(&command);
        let execution = ArbitrationRunnerExecution {
            kind: "external_local_agent".to_string(),
            trusted_local_boundary: run.succeeded(),
            command: run.command.clone(),
            exit_code: run.exit_code,
            timed_out: run.timed_out,
        };
        if !run.succeeded() {
            bail!(
                "neutral arbiter did not complete through the trusted local execution boundary: {}",
                run.error
                    .as_deref()
                    .or_else(|| (!run.stderr.text.is_empty()).then_some(run.stderr.text.as_str()))
                    .unwrap_or("trusted execution evidence was incomplete")
            );
        }
        let output = run
            .output_last_message()
            .context("neutral arbiter produced no held final-message output")?;
        let proposal = parse_arbitration_proposal(output)?;
        Ok(ArbitrationRunnerResult {
            proposal,
            execution,
        })
    }
}

#[cfg(test)]
impl ArbitrationRunner for StaticArbitrationRunner {
    fn run(&self, _request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult> {
        Ok(ArbitrationRunnerResult {
            proposal: parse_arbitration_proposal(&self.output)?,
            execution: ArbitrationRunnerExecution {
                kind: "static_fake".to_string(),
                trusted_local_boundary: false,
                command: Vec::new(),
                exit_code: Some(0),
                timed_out: false,
            },
        })
    }
}

fn parse_arbitration_proposal(bytes: &[u8]) -> Result<ArbitrationProposal> {
    if bytes.len() > MAX_ARBITRATION_PROPOSAL_BYTES {
        bail!("arbiter output exceeds its {MAX_ARBITRATION_PROPOSAL_BYTES}-byte limit");
    }
    let value: Value =
        serde_json::from_slice(bytes).context("arbiter output is not strict proposal JSON")?;
    let object = value
        .as_object()
        .context("arbiter output must be one strict JSON object")?;
    for field in [
        "version",
        "input_sha256",
        "disposition",
        "rationale",
        "candidate_patch",
    ] {
        if !object.contains_key(field) {
            bail!("arbiter output is missing required field '{field}'");
        }
    }
    let proposal: ArbitrationProposal =
        serde_json::from_value(value).context("arbiter output is not strict proposal JSON")?;
    validate_arbitration_proposal_shape(&proposal)?;
    Ok(proposal)
}

fn validate_arbitration_proposal_shape(proposal: &ArbitrationProposal) -> Result<()> {
    if proposal.version != ARBITRATION_PROPOSAL_VERSION {
        bail!(
            "unsupported arbitration proposal version {}; expected {}",
            proposal.version,
            ARBITRATION_PROPOSAL_VERSION
        );
    }
    validate_lowercase_sha256(&proposal.input_sha256, "arbitration input digest")?;
    if proposal.rationale.trim().is_empty()
        || proposal.rationale.trim() != proposal.rationale
        || proposal.rationale.len() > MAX_ARBITRATION_RATIONALE_BYTES
        || proposal.rationale.contains('\0')
    {
        bail!("arbiter rationale is empty, non-canonical, or exceeds its bounded text contract");
    }
    if proposal
        .candidate_patch
        .as_ref()
        .is_some_and(|patch| patch.len() > MAX_ARBITRATION_PATCH_BYTES)
    {
        bail!("arbiter candidate patch exceeds its {MAX_ARBITRATION_PATCH_BYTES}-byte limit");
    }
    match proposal.disposition {
        ArbitrationProposalDisposition::Proposed if proposal.candidate_patch.is_none() => {
            bail!("a proposed arbitration resolution must include candidate_patch")
        }
        ArbitrationProposalDisposition::Escalated if proposal.candidate_patch.is_some() => {
            bail!("an escalated arbitration result must not include candidate_patch")
        }
        _ => Ok(()),
    }
}

fn validate_lowercase_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must be canonical lowercase SHA-256");
    }
    Ok(())
}

/// Runs neutral merge arbitration through the crate-owned production boundaries.
///
/// External callers cannot substitute an arbitration runner.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::merge::arbitrate_merge_with_runner;
/// ```
///
/// External callers cannot substitute an arbitration environment.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::merge::arbitrate_merge_with_environment;
/// ```
///
/// External callers also cannot construct trusted runner evidence.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::merge::ArbitrationRunnerExecution;
///
/// let _execution = ArbitrationRunnerExecution {
///     kind: "injected".to_string(),
///     trusted_local_boundary: true,
///     command: Vec::new(),
///     exit_code: Some(0),
///     timed_out: false,
/// };
/// ```
pub fn arbitrate_merge(options: MergeArbitrationOptions) -> Result<MergeArbitrationReport> {
    let runner = ExternalArbitrationRunner {
        codex_bin: options.codex_bin.clone(),
        timeout: options.timeout,
        machine_global_config: options.machine_global_config.clone(),
        machine_global_runtime_root_id: options.machine_global_runtime_root_id.clone(),
    };
    arbitrate_merge_with_runner(options, &runner)
}

fn arbitrate_merge_with_runner(
    options: MergeArbitrationOptions,
    runner: &dyn ArbitrationRunner,
) -> Result<MergeArbitrationReport> {
    arbitrate_merge_with_environment(options, runner, &ProductionArbitrationEnvironment)
}

fn arbitrate_merge_with_environment(
    options: MergeArbitrationOptions,
    runner: &dyn ArbitrationRunner,
    environment: &dyn ArbitrationEnvironment,
) -> Result<MergeArbitrationReport> {
    let options = canonicalize_arbitration_options(options)?;
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let mut writer = ArtifactRunWriter::reserve(
        &repo_root,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "merge-arbitration",
    )
    .context("failed to reserve private arbitration artifacts")?;
    let prepared = environment
        .prepare(&options)
        .context("failed to prepare exact neutral arbitration input")?;
    writer.write_bytes(
        ARBITRATION_INPUT_PATH,
        &prepared.input_json,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let prompt = arbitration_prompt(&prepared);
    if prompt.len() > MAX_ARBITRATION_PROMPT_BYTES {
        bail!(
            "arbitration prompt exceeds the trusted external runner's {MAX_ARBITRATION_PROMPT_BYTES}-byte limit"
        );
    }
    writer.write_bytes(
        ARBITRATION_PROMPT_PATH,
        prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    writer.write_bytes(
        ARBITRATION_SCHEMA_PATH,
        arbitration_output_schema().as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;

    let incoming = writer.create_scratch_dir(ARBITRATION_INCOMING_DIR)?;
    let runner_request = ArbitrationRunnerRequest {
        prompt_path: writer.run_dir().join(ARBITRATION_PROMPT_PATH),
        output_schema_path: writer.run_dir().join(ARBITRATION_SCHEMA_PATH),
        output_last_message_path: incoming.path().join("proposal.json"),
        json_log_path: incoming.path().join("arbiter.jsonl"),
        neutral_worktree_path: prepared.input.neutral_worktree.path.clone(),
        hidden_primary_root: repo_root.clone(),
        run_id: options.run_id.as_str().to_string(),
        arbiter_id: options.arbiter_agent_id.clone(),
    };
    let runner_result = runner.run(&runner_request);
    if runner_result.is_err() {
        writer
            .discard_scratch(&incoming)
            .context("failed to discard failed arbiter invocation scratch")?;
    }
    let runner_result = runner_result?;
    writer
        .discard_scratch(&incoming)
        .context("failed to discard completed arbiter invocation scratch")?;
    validate_arbitration_proposal_shape(&runner_result.proposal)?;
    if runner_result.proposal.input_sha256 != prepared.input_sha256 {
        bail!("arbiter proposal input digest does not match the exact reviewed arbitration input");
    }

    let rationale_value = serde_json::json!({
        "version": ARBITRATION_REPORT_VERSION,
        "input_sha256": prepared.input_sha256,
        "disposition": runner_result.proposal.disposition,
        "rationale": runner_result.proposal.rationale,
    });
    let rationale_record = writer.write_json(
        ARBITRATION_RATIONALE_PATH,
        &rationale_value,
        ArtifactFileDisposition::PrivateEvidence,
    )?;

    let mut candidate_artifact = None;
    let mut candidate_sha256 = None;
    let mut candidate_binding = None;
    let mut candidate_status = ValidationStatus::NotRun;
    let mut preservation = Vec::new();
    let mut validations = Vec::new();
    let mut reason = runner_result.proposal.rationale.clone();
    let outcome = match runner_result.proposal.disposition {
        ArbitrationProposalDisposition::Escalated => ArbitrationOutcome::Escalated,
        ArbitrationProposalDisposition::Rejected | ArbitrationProposalDisposition::Proposed => {
            let mut materialized_proposal = runner_result.proposal.clone();
            if materialized_proposal.candidate_patch.is_none() {
                materialized_proposal.candidate_patch = Some(String::new());
            }
            let preview = environment
                .materialize_candidate(&prepared, &materialized_proposal)
                .context("failed to materialize and canonically recapture arbiter candidate")?;
            let candidate_record = writer.write_bytes(
                ARBITRATION_CANDIDATE_PATH,
                &preview.candidate.raw_diff,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
            candidate_artifact = Some(ARBITRATION_CANDIDATE_PATH.to_string());
            candidate_sha256 = Some(candidate_record.sha256);
            candidate_binding = Some(
                preview
                    .candidate
                    .validation_binding
                    .clone()
                    .canonicalized()
                    .context("recaptured arbiter candidate binding is not canonical")?,
            );
            if candidate_binding
                .as_ref()
                .is_some_and(|binding| binding.agent_id != options.arbiter_agent_id)
            {
                bail!("recaptured candidate is not bound to the neutral arbiter identity");
            }
            match runner_result.proposal.disposition {
                ArbitrationProposalDisposition::Rejected => {
                    candidate_status = ValidationStatus::Skipped;
                    ArbitrationOutcome::Rejected
                }
                ArbitrationProposalDisposition::Proposed => {
                    preservation = prove_both_sides_preserved(
                        &prepared.input.sides,
                        &prepared.source_diffs,
                        &preview.candidate.raw_diff,
                    )?;
                    if preservation.iter().any(|proof| !proof.preserved) {
                        candidate_status = ValidationStatus::Failed;
                        reason =
                            "arbiter candidate discarded or could not prove one side contribution"
                                .to_string();
                        ArbitrationOutcome::Rejected
                    } else {
                        validations = environment
                            .validate_candidate(&preview, &options.validation_commands)
                            .context(
                                "failed to run candidate-bound arbitration validation commands",
                            )?;
                        if validations.is_empty()
                            || validations
                                .iter()
                                .any(|report| report.status != ValidationStatus::Passed)
                        {
                            candidate_status = ValidationStatus::Failed;
                            reason =
                                "arbiter candidate failed candidate-bound validation".to_string();
                            ArbitrationOutcome::Rejected
                        } else if options.approve && runner_result.execution.trusted_local_boundary
                        {
                            candidate_status = ValidationStatus::Passed;
                            ArbitrationOutcome::Accepted
                        } else {
                            candidate_status = ValidationStatus::Skipped;
                            reason = if options.approve {
                                "candidate is preserved and validated, but the injected static runner is non-authoritative; trusted local arbitration and a later ordinary merge apply are still required".to_string()
                            } else {
                                "candidate is preserved and validated but awaits explicit arbitration approval; a later ordinary merge apply is still required".to_string()
                            };
                            ArbitrationOutcome::Escalated
                        }
                    }
                }
                ArbitrationProposalDisposition::Escalated => {
                    bail!("escalated proposal unexpectedly reached candidate materialization")
                }
            }
        }
    };

    let current_primary_sha256 = environment.current_primary_state_sha256(&prepared)?;
    if current_primary_sha256 != prepared.primary_state_sha256 {
        bail!(
            "primary repository changed during arbitration; refusing to record a successful neutral outcome"
        );
    }

    let sides = [
        options.sides[0].journal_side(),
        options.sides[1].journal_side(),
    ];
    let report = MergeArbitrationReport {
        version: ARBITRATION_REPORT_VERSION,
        run_id: options.run_id.as_str().to_string(),
        arbiter_id: options.arbiter_agent_id.clone(),
        outcome,
        approved: outcome == ArbitrationOutcome::Accepted
            && options.approve
            && runner_result.execution.trusted_local_boundary,
        primary_mutated: false,
        later_ordinary_merge_apply_required: true,
        reviewed_base_oid: prepared.input.reviewed_base_oid.clone(),
        sides: sides.clone(),
        neutral_worktree: prepared.input.neutral_worktree.clone(),
        input_artifact: ARBITRATION_INPUT_PATH.to_string(),
        input_sha256: prepared.input_sha256.clone(),
        rationale_artifact: ARBITRATION_RATIONALE_PATH.to_string(),
        rationale_sha256: rationale_record.sha256.clone(),
        candidate_artifact,
        candidate_sha256,
        candidate_binding: candidate_binding.clone(),
        candidate_status,
        preservation,
        validation_commands: options
            .validation_commands
            .iter()
            .map(|command| command.command.clone())
            .collect(),
        validations,
        semantic_classification: prepared.input.semantic_classification.clone(),
        runner: runner_result.execution,
        reason: reason.clone(),
    };
    writer.write_json(
        ARBITRATION_FINAL_REPORT_PATH,
        &report,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let mut journal = OrchestrationEventJournal::new(".", options.run_id.as_str());
    let journal_reason = arbitration_journal_reason(outcome);
    journal
        .append_arbitration_outcome(
            &mut writer,
            None,
            OrchestrationRole::Orchestrator,
            ArbitrationOutcomeDetails {
                outcome,
                arbiter_id: options.arbiter_agent_id,
                sides,
                candidate_binding,
                candidate_status,
                rationale_report: Some(ARBITRATION_RATIONALE_PATH.to_string()),
                rationale_sha256: Some(rationale_record.sha256),
                reason: journal_reason.to_string(),
            },
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "arbitration outcome journal append failed or may have completed durably; inspect the private event journal before retrying: {error}"
            )
        })?;
    writer
        .finalize(ARBITRATION_FINAL_REPORT_PATH, false)
        .context("failed to finalize tamper-evident private arbitration artifacts")?;
    Ok(report)
}

fn canonicalize_arbitration_options(
    mut options: MergeArbitrationOptions,
) -> Result<MergeArbitrationOptions> {
    options.arbiter_agent_id = normalize_agent_id(&options.arbiter_agent_id)
        .context("neutral arbiter identity is invalid")?;
    if options.timeout.is_zero() {
        bail!("neutral arbiter timeout must be positive");
    }
    if options.validation_commands.is_empty() {
        bail!("arbitration requires at least one candidate validation command");
    }
    if options.validation_commands.len() > MAX_ARBITRATION_VALIDATION_COMMANDS {
        bail!(
            "arbitration exceeds its {MAX_ARBITRATION_VALIDATION_COMMANDS}-command validation limit"
        );
    }
    for command in &mut options.validation_commands {
        command.command = command.command.trim().to_string();
        if command.command.is_empty()
            || command.command.len() > 1024 * 1024
            || command.command.contains('\0')
        {
            bail!("arbitration validation command is empty or exceeds its bounded contract");
        }
    }
    let mut primary_count = 0usize;
    let mut participants = BTreeSet::new();
    for side in &mut options.sides {
        match side {
            ArbitrationSideSpec::Agent {
                agent_id,
                claimed_paths,
            } => {
                *agent_id =
                    normalize_agent_id(agent_id).context("arbitration side agent id is invalid")?;
                if agent_id == "primary" {
                    bail!("agent id 'primary' is reserved by the arbitration side contract");
                }
                if agent_id == &options.arbiter_agent_id {
                    bail!("neutral arbiter identity must differ from both arbitration sides");
                }
                if !participants.insert(agent_id.clone()) {
                    bail!("arbitration sides must be distinct");
                }
                *claimed_paths = normalize_claim_paths(std::mem::take(claimed_paths))?;
            }
            ArbitrationSideSpec::Primary => {
                primary_count += 1;
                if primary_count > 1 || !participants.insert("primary".to_string()) {
                    bail!("arbitration sides must be distinct");
                }
            }
        }
    }
    if primary_count == 0
        && options
            .sides
            .iter()
            .all(|side| !matches!(side, ArbitrationSideSpec::Agent { .. }))
    {
        bail!("arbitration requires at least one agent side");
    }
    Ok(options)
}

impl ArbitrationEnvironment for ProductionArbitrationEnvironment {
    fn prepare(&self, options: &MergeArbitrationOptions) -> Result<PreparedMergeArbitration> {
        let repo_root = discover_primary_repo_root(&options.repo)?;
        let manager = WorktreeManager::new(&repo_root);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .context("neutral arbitration requires a clean exact primary repository")?;
        let primary_state_sha256 = primary_state_sha256(&repo_root)?;

        let mut candidates = BTreeMap::new();
        for side in &options.sides {
            if let ArbitrationSideSpec::Agent {
                agent_id,
                claimed_paths,
            } = side
            {
                let candidate = collect_agent_result(MergeCollectOptions {
                    repo: repo_root.clone(),
                    agent_id: agent_id.clone(),
                    claimed_paths: claimed_paths.clone(),
                    include_full_diff: false,
                    diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                    validations: Vec::new(),
                })
                .with_context(|| {
                    format!("failed to capture exact arbitration side '{agent_id}'")
                })?;
                candidates.insert(agent_id.clone(), candidate);
            }
        }
        if candidates.is_empty() {
            bail!("neutral arbitration requires at least one captured agent side");
        }

        let reviewed_base = reviewed_arbitration_base(&candidates)?;
        let primary_repo = crate::git_repository::open(&repo_root).with_context(|| {
            format!("failed to open primary repository {}", repo_root.display())
        })?;
        primary_repo.find_commit(reviewed_base).with_context(|| {
            format!("reviewed arbitration base {reviewed_base} is not a commit")
        })?;

        let source_ids = [
            options.sides[0].source_identity(),
            options.sides[1].source_identity(),
        ];
        let neutral_record = manager
            .create_neutral_with_repository_cleanliness(
                NeutralWorktreeCreateOptions {
                    arbiter_agent_id: options.arbiter_agent_id.clone(),
                    source_agent_ids: source_ids,
                    base_oid: reviewed_base,
                    worktree_root: options.worktree_root.clone(),
                },
                &cleanliness,
            )
            .context("failed to create structurally neutral arbitration worktree")?;
        let neutral_worktree = ArbitrationNeutralWorktree {
            agent_id: neutral_record.name.clone(),
            path: neutral_record.path.clone(),
            branch: neutral_record.branch.clone(),
            exact_base_oid: reviewed_base.to_string(),
            inherited_claim: false,
        };

        let mut source_diffs = Vec::with_capacity(2);
        let mut side_evidence = Vec::with_capacity(2);
        for side in &options.sides {
            let (evidence, raw_diff) = arbitration_side_evidence(
                side,
                &candidates,
                &primary_repo,
                &repo_root,
                reviewed_base,
            )?;
            side_evidence.push(evidence);
            source_diffs.push(raw_diff);
        }
        let side_evidence: [ArbitrationSideEvidence; 2] = side_evidence
            .try_into()
            .map_err(|_| anyhow::anyhow!("arbitration side evidence count changed"))?;
        let source_diffs: [Vec<u8>; 2] = source_diffs
            .try_into()
            .map_err(|_| anyhow::anyhow!("arbitration side diff count changed"))?;
        let collision_paths = arbitration_collision_paths(&side_evidence[0], &side_evidence[1])?;
        let semantic_classification = match (&options.sides[0], &options.sides[1]) {
            (
                ArbitrationSideSpec::Agent {
                    agent_id: first, ..
                },
                ArbitrationSideSpec::Agent {
                    agent_id: second, ..
                },
            ) => classify_semantic_candidate_pair(
                candidates
                    .get(first)
                    .context("first arbitration candidate disappeared")?,
                candidates
                    .get(second)
                    .context("second arbitration candidate disappeared")?,
                &collision_paths,
            ),
            (ArbitrationSideSpec::Agent { agent_id, .. }, ArbitrationSideSpec::Primary)
            | (ArbitrationSideSpec::Primary, ArbitrationSideSpec::Agent { agent_id, .. }) => {
                classify_semantic_conflicts(
                    candidates
                        .get(agent_id)
                        .context("agent arbitration candidate disappeared")?,
                    &SafetyCheck {
                        status: SafetyCheckStatus::Failed,
                        message: Some(
                            "cross-worktree arbitration collision requires neutral review"
                                .to_string(),
                        ),
                        paths: collision_paths.clone(),
                    },
                )
            }
            _ => bail!("arbitration sides are not a supported participant pair"),
        };

        let side_agent_ids = options
            .sides
            .iter()
            .filter_map(|side| match side {
                ArbitrationSideSpec::Agent { agent_id, .. } => Some(agent_id.as_str()),
                ArbitrationSideSpec::Primary => None,
            })
            .collect::<BTreeSet<_>>();
        let relevant_path_claims = SyncStore::open(&repo_root)?
            .snapshot()?
            .into_iter()
            .filter(|claim| {
                side_agent_ids.contains(claim.agent_id.as_str())
                    || claim.paths.iter().any(|claimed| {
                        collision_paths
                            .iter()
                            .any(|path| arbitration_paths_overlap(claimed, path))
                    })
            })
            .collect::<Vec<_>>();
        let relevant_semantic_intents =
            SemanticIntentStore::open(&repo_root)?
                .snapshot()?
                .into_iter()
                .filter(|intent| {
                    side_agent_ids.contains(intent.agent_id.as_str())
                        || intent.paths.iter().chain(intent.impacted_files.iter()).any(
                            |intent_path| {
                                collision_paths
                                    .iter()
                                    .any(|path| arbitration_paths_overlap(intent_path, path))
                            },
                        )
                })
                .collect::<Vec<_>>();

        let input = ArbitrationInput {
            version: ARBITRATION_INPUT_VERSION,
            arbiter_id: options.arbiter_agent_id.clone(),
            reviewed_base_oid: reviewed_base.to_string(),
            neutral_worktree,
            sides: side_evidence,
            relevant_path_claims,
            relevant_semantic_intents,
            semantic_classification,
        };
        let mut input_json =
            serde_json::to_vec_pretty(&input).context("failed to encode arbitration input")?;
        input_json.push(b'\n');
        if input_json.len() > MAX_ARBITRATION_INPUT_BYTES {
            bail!("arbitration input exceeds its {MAX_ARBITRATION_INPUT_BYTES}-byte limit");
        }
        let input_sha256 = sha256_hex(&input_json);
        Ok(PreparedMergeArbitration {
            input,
            input_json,
            input_sha256,
            primary_repo_root: repo_root,
            primary_state_sha256,
            source_diffs,
        })
    }

    fn materialize_candidate(
        &self,
        prepared: &PreparedMergeArbitration,
        proposal: &ArbitrationProposal,
    ) -> Result<MergeApplyPreview> {
        let patch = proposal
            .candidate_patch
            .as_deref()
            .context("candidate materialization requires a proposal patch")?;
        let claimed_paths = arbitration_candidate_scope(&prepared.input.sides)?;
        let collect_options = MergeCollectOptions {
            repo: prepared.primary_repo_root.clone(),
            agent_id: prepared.input.arbiter_id.clone(),
            claimed_paths: claimed_paths.clone(),
            include_full_diff: true,
            diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations: Vec::new(),
        };
        let manager = WorktreeManager::new(&prepared.primary_repo_root);
        let write_lease = manager
            .acquire_write_execution_lease(&prepared.input.arbiter_id)
            .context("failed to acquire the neutral arbitration worktree write lease")?;
        let initial = collect_agent_result_with_evidence_and_write_lease(
            collect_options.clone(),
            ValidationEvidenceBundle::default(),
            &write_lease,
        )
        .context("failed to capture pristine neutral arbitration worktree")?;
        if !initial.raw_diff.is_empty() {
            bail!("neutral arbitration worktree changed before candidate materialization");
        }
        if !patch.is_empty() {
            let output = run_git_with_input_with_writable_worktree(
                &prepared.input.neutral_worktree.path,
                &["apply", "--binary"],
                patch.as_bytes(),
            )
            .context("failed to apply arbiter proposal inside the neutral worktree")?;
            if !output.success {
                bail!(
                    "arbiter proposal patch did not apply to the exact reviewed base: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        let candidate = collect_agent_result_with_evidence_and_write_lease(
            collect_options,
            ValidationEvidenceBundle::default(),
            &write_lease,
        )
        .context("failed to canonically recapture materialized neutral candidate")?;
        if proposal.disposition == ArbitrationProposalDisposition::Proposed
            && candidate.raw_diff.is_empty()
        {
            bail!("proposed arbitration candidate is empty");
        }
        if !candidate.unclaimed_changed_paths.is_empty() {
            bail!(
                "arbiter candidate changed paths outside the bounded collision scope: {}",
                format_arbitration_paths(&candidate.unclaimed_changed_paths)
            );
        }
        if candidate.metadata.merge_base.as_deref()
            != Some(prepared.input.reviewed_base_oid.as_str())
        {
            bail!("arbiter candidate no longer uses the exact reviewed arbitration base");
        }
        build_merge_apply_preview(
            candidate,
            MergeForceOptions {
                allow_dirty_primary: false,
                allow_stale_base: true,
                allow_unclaimed_edits: false,
                allow_validation_failures: false,
                allow_apply_conflicts: true,
            },
            false,
            MergeApplyReviewIntent::default(),
        )
    }

    fn validate_candidate(
        &self,
        preview: &MergeApplyPreview,
        commands: &[CandidateValidationCommand],
    ) -> Result<Vec<ValidationReport>> {
        run_candidate_validation_commands(preview, commands)
    }

    fn current_primary_state_sha256(&self, prepared: &PreparedMergeArbitration) -> Result<String> {
        primary_state_sha256(primary_repo_path_for_verification(prepared))
    }
}

fn primary_repo_path_for_verification(prepared: &PreparedMergeArbitration) -> &Path {
    &prepared.primary_repo_root
}

fn reviewed_arbitration_base(candidates: &BTreeMap<String, MergeCandidate>) -> Result<Oid> {
    let mut bases = candidates
        .values()
        .map(|candidate| {
            let base = candidate
                .metadata
                .merge_base
                .as_deref()
                .context("arbitration side has no reviewed merge base")?;
            Oid::from_str(base).context("arbitration side merge base is invalid")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if bases.len() != 1 {
        bail!("arbitration sides do not share one exact reviewed base");
    }
    bases
        .pop_first()
        .context("arbitration reviewed base disappeared")
}

fn arbitration_side_evidence(
    side: &ArbitrationSideSpec,
    candidates: &BTreeMap<String, MergeCandidate>,
    primary_repo: &Repository,
    repo_root: &Path,
    reviewed_base: Oid,
) -> Result<(ArbitrationSideEvidence, Vec<u8>)> {
    let (participant, head_oid, tree_oid, changed_paths, raw_diff, candidate_binding) = match side {
        ArbitrationSideSpec::Agent { agent_id, .. } => {
            let candidate = candidates
                .get(agent_id)
                .with_context(|| format!("captured arbitration side '{agent_id}' disappeared"))?;
            let head_oid = candidate
                .metadata
                .agent_head
                .clone()
                .context("arbitration agent side has no HEAD commit")?;
            (
                side.journal_side(),
                head_oid,
                candidate.snapshot_tree.to_string(),
                candidate.changed_paths.clone(),
                candidate.raw_diff.clone(),
                Some(candidate.validation_binding.clone().canonicalized()?),
            )
        }
        ArbitrationSideSpec::Primary => {
            let head =
                head_oid(primary_repo)?.context("primary arbitration side has no HEAD commit")?;
            let tree = primary_repo
                .find_commit(head)
                .context("failed to open primary arbitration HEAD")?
                .tree_id();
            let (changed_paths, raw_diff) =
                capture_worktree_diff_from_commit(primary_repo, repo_root, reviewed_base)?;
            (
                ArbitrationSide::Primary,
                head.to_string(),
                tree.to_string(),
                changed_paths,
                raw_diff,
                None,
            )
        }
    };
    if changed_paths.len() > MAX_ARBITRATION_CHANGED_PATHS {
        bail!("arbitration side exceeds its {MAX_ARBITRATION_CHANGED_PATHS}-path limit");
    }
    if raw_diff.len() > MAX_ARBITRATION_PATCH_BYTES {
        bail!("arbitration side diff exceeds its bounded input limit");
    }
    let diff = patch_text_for_json(&raw_diff);
    Ok((
        ArbitrationSideEvidence {
            participant,
            head_oid,
            tree_oid,
            base_oid: reviewed_base.to_string(),
            diff_sha256: sha256_hex(&raw_diff),
            diff_bytes: raw_diff.len(),
            diff,
            changed_paths,
            candidate_binding,
        },
        raw_diff,
    ))
}

fn arbitration_collision_paths(
    first: &ArbitrationSideEvidence,
    second: &ArbitrationSideEvidence,
) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for first_path in &first.changed_paths {
        for second_path in &second.changed_paths {
            if arbitration_paths_overlap(first_path, second_path) {
                paths.insert(first_path.clone());
                paths.insert(second_path.clone());
            }
        }
    }
    if paths.is_empty() {
        bail!("arbitration sides do not have a cross-worktree path collision");
    }
    Ok(paths.into_iter().collect())
}

fn arbitration_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn arbitration_candidate_scope(sides: &[ArbitrationSideEvidence; 2]) -> Result<Vec<PathBuf>> {
    normalize_claim_paths(
        sides
            .iter()
            .flat_map(|side| side.changed_paths.iter().cloned())
            .collect(),
    )
}

fn primary_state_sha256(repo_path: &Path) -> Result<String> {
    let repo_root = discover_primary_repo_root(repo_path)?;
    let state = PrimaryRepositoryState::capture(&repo_root)?;
    let bytes = format!(
        "head={}\nindex={}\nworktree={}\n",
        state
            .head
            .map(|oid| oid.to_string())
            .unwrap_or_else(|| "none".to_string()),
        state
            .index_digest
            .map(|oid| oid.to_string())
            .unwrap_or_else(|| "none".to_string()),
        state.worktree_digest
    );
    Ok(sha256_hex(bytes.as_bytes()))
}

fn arbitration_prompt(prepared: &PreparedMergeArbitration) -> String {
    format!(
        "You are a terminal neutral merge arbiter. Do not delegate, spawn workers, or invoke another agent. Review the exact typed input at the end of this prompt. Return only strict JSON matching the supplied schema. Do not mutate the worktree. A proposed candidate_patch must be a bounded Git binary patch against reviewed_base_oid and must preserve the exact additions and deletions contributed by both sides. Echo input_sha256 exactly. Primary mutation is forbidden; even an approved result only prepares the neutral candidate for a later ordinary human-invoked merge preview/apply.\n\ninput_sha256: {}\n\n{}",
        prepared.input_sha256,
        String::from_utf8_lossy(&prepared.input_json)
    )
}

fn arbitration_journal_reason(outcome: ArbitrationOutcome) -> &'static str {
    match outcome {
        ArbitrationOutcome::Accepted => {
            "neutral arbitration candidate accepted after both-side preservation and candidate-bound validation"
        }
        ArbitrationOutcome::Rejected => {
            "neutral arbitration candidate rejected by the proposal, preservation, or validation gate"
        }
        ArbitrationOutcome::Escalated => {
            "neutral arbitration requires trusted execution, explicit approval, or human resolution"
        }
    }
}

fn arbitration_output_schema() -> &'static str {
    r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "input_sha256", "disposition", "rationale", "candidate_patch"],
  "properties": {
    "version": {"const": 1},
    "input_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "disposition": {"enum": ["proposed", "rejected", "escalated"]},
    "rationale": {"type": "string", "minLength": 1, "maxLength": 65536},
    "candidate_patch": {"type": ["string", "null"], "maxLength": 4194304}
  }
}"#
}

#[derive(Debug, Default)]
struct PatchContributions {
    additions: BTreeMap<PathBuf, BTreeMap<String, usize>>,
    deletions: BTreeMap<PathBuf, BTreeMap<String, usize>>,
    changed_paths: BTreeSet<PathBuf>,
    binary_paths: BTreeSet<PathBuf>,
}

fn prove_both_sides_preserved(
    sides: &[ArbitrationSideEvidence; 2],
    source_diffs: &[Vec<u8>; 2],
    candidate_diff: &[u8],
) -> Result<Vec<ArbitrationPreservationProof>> {
    let candidate = collect_patch_contributions(candidate_diff)?;
    let mut proofs = Vec::with_capacity(2);
    for (index, side) in sides.iter().enumerate() {
        let source = collect_patch_contributions(&source_diffs[index])?;
        let required_additions = contribution_count(&source.additions);
        let required_deletions = contribution_count(&source.deletions);
        let preserved_additions =
            count_preserved_contributions(&source.additions, &candidate.additions);
        let preserved_deletions =
            count_preserved_contributions(&source.deletions, &candidate.deletions);
        let mut problems = Vec::new();
        if !source.binary_paths.is_empty() {
            problems.push(format!(
                "binary contribution preservation cannot be proven for {}",
                format_arbitration_paths(&source.binary_paths.iter().cloned().collect::<Vec<_>>())
            ));
        }
        if required_additions == 0 && required_deletions == 0 {
            problems.push("side diff exposed no exact text contribution tokens".to_string());
        }
        if preserved_additions != required_additions {
            problems.push(format!(
                "candidate preserved {preserved_additions}/{required_additions} exact added-line contributions"
            ));
        }
        if preserved_deletions != required_deletions {
            problems.push(format!(
                "candidate preserved {preserved_deletions}/{required_deletions} exact deleted-line contributions"
            ));
        }
        if !source
            .changed_paths
            .iter()
            .all(|path| candidate.changed_paths.contains(path))
        {
            problems.push("candidate omitted one or more side-changed paths".to_string());
        }
        proofs.push(ArbitrationPreservationProof {
            side: side.participant.clone(),
            preserved: problems.is_empty(),
            required_additions,
            preserved_additions,
            required_deletions,
            preserved_deletions,
            problems,
        });
    }
    Ok(proofs)
}

fn collect_patch_contributions(diff_bytes: &[u8]) -> Result<PatchContributions> {
    if diff_bytes.len() > MAX_ARBITRATION_PATCH_BYTES {
        bail!("patch contribution proof input exceeds its bounded patch limit");
    }
    if diff_bytes.is_empty() {
        return Ok(PatchContributions::default());
    }
    let diff = git2::Diff::from_buffer(diff_bytes)
        .context("candidate preservation proof received an invalid Git patch")?;
    let mut contributions = PatchContributions::default();
    for delta in diff.deltas() {
        for path in arbitration_delta_paths(&delta) {
            contributions.changed_paths.insert(path.clone());
            if delta.old_file().is_binary() || delta.new_file().is_binary() {
                contributions.binary_paths.insert(path);
            }
        }
    }
    diff.print(git2::DiffFormat::Patch, |delta, _hunk, line| {
        let origin = line.origin();
        if !matches!(origin, '+' | '-') {
            return true;
        }
        let Some(path) = arbitration_diff_line_path(&delta, origin) else {
            return true;
        };
        let digest = sha256_hex(line.content());
        let target = if origin == '+' {
            &mut contributions.additions
        } else {
            &mut contributions.deletions
        };
        let count = target
            .entry(path.to_path_buf())
            .or_default()
            .entry(digest)
            .or_insert(0usize);
        *count = count.saturating_add(1);
        true
    })
    .context("failed to inspect candidate preservation patch")?;
    Ok(contributions)
}

fn count_preserved_contributions(
    required: &BTreeMap<PathBuf, BTreeMap<String, usize>>,
    candidate: &BTreeMap<PathBuf, BTreeMap<String, usize>>,
) -> usize {
    required
        .iter()
        .map(|(path, digests)| {
            candidate
                .get(path)
                .map(|observed| {
                    digests
                        .iter()
                        .map(|(digest, required_count)| {
                            observed
                                .get(digest)
                                .copied()
                                .unwrap_or(0)
                                .min(*required_count)
                        })
                        .sum::<usize>()
                })
                .unwrap_or(0)
        })
        .sum()
}

fn contribution_count(contributions: &BTreeMap<PathBuf, BTreeMap<String, usize>>) -> usize {
    contributions
        .values()
        .flat_map(|digests| digests.values())
        .copied()
        .sum()
}

fn arbitration_delta_paths(delta: &git2::DiffDelta<'_>) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    if let Some(path) = delta.old_file().path() {
        paths.insert(path.to_path_buf());
    }
    if let Some(path) = delta.new_file().path() {
        paths.insert(path.to_path_buf());
    }
    paths.into_iter().collect()
}

fn arbitration_diff_line_path<'a>(
    delta: &'a git2::DiffDelta<'_>,
    origin: char,
) -> Option<&'a Path> {
    if origin == '-' {
        delta.old_file().path().or_else(|| delta.new_file().path())
    } else {
        delta.new_file().path().or_else(|| delta.old_file().path())
    }
}

fn format_arbitration_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeForceOptions {
    pub allow_dirty_primary: bool,
    pub allow_stale_base: bool,
    pub allow_unclaimed_edits: bool,
    pub allow_validation_failures: bool,
    pub allow_apply_conflicts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeCandidate {
    pub metadata: WorktreeMergeMetadata,
    #[serde(serialize_with = "serialize_paths")]
    pub claimed_paths: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub changed_paths: Vec<PathBuf>,
    pub changes: Vec<ChangedPath>,
    #[serde(serialize_with = "serialize_paths")]
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub diff: DiffOutput,
    pub validations: Vec<ValidationReport>,
    pub validation_binding: CandidateValidationBinding,
    #[serde(skip_serializing)]
    pub validation_evidence: ValidationEvidenceBundle,
    #[serde(skip_serializing)]
    pub(crate) raw_diff: Vec<u8>,
    #[serde(skip_serializing)]
    pub(crate) snapshot_tree: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorktreeMergeMetadata {
    pub agent_id: String,
    #[serde(serialize_with = "serialize_path")]
    pub worktree_path: PathBuf,
    pub branch: String,
    #[serde(serialize_with = "serialize_path")]
    pub primary_repo_root: PathBuf,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub base_matches_primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedPath {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Typechange,
    Untracked,
    Conflicted,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiffOutput {
    pub summary: OutputSummary,
    pub full: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValidationReport {
    pub name: String,
    pub status: ValidationStatus,
    pub message: Option<String>,
    #[serde(default, serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateValidationBinding {
    pub version: u32,
    pub agent_id: String,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub diff_oid: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationEvidenceBundle {
    groups: Vec<ValidationEvidenceGroup>,
}

/// Canonical passed validation evidence bound to exactly one candidate.
///
/// The fields are private so strict publication call sites can only obtain
/// this capability through the validating factories on
/// [`ValidationEvidenceBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundValidationEvidenceBundle {
    binding: CandidateValidationBinding,
    evidence: ValidationEvidenceBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationEvidenceGroup {
    binding: Option<CandidateValidationBinding>,
    reports: Vec<ValidationReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    NotRun,
    Passed,
    Failed,
    Skipped,
}

impl CandidateValidationBinding {
    pub(crate) fn canonicalized(mut self) -> Result<Self> {
        if self.version != VALIDATION_BINDING_VERSION {
            bail!(
                "unsupported validation binding version {}; expected {}",
                self.version,
                VALIDATION_BINDING_VERSION
            );
        }
        let normalized_agent = normalize_agent_id(&self.agent_id)
            .context("validation binding has an invalid agent_id")?;
        if normalized_agent != self.agent_id {
            bail!("validation binding agent_id must be canonical");
        }
        self.primary_head = canonical_optional_oid(self.primary_head, "primary_head")?;
        self.agent_head = canonical_optional_oid(self.agent_head, "agent_head")?;
        self.merge_base = canonical_optional_oid(self.merge_base, "merge_base")?;
        self.diff_oid = canonical_oid(&self.diff_oid, "diff_oid")?;
        Ok(self)
    }
}

impl ValidationEvidenceBundle {
    pub fn legacy(reports: Vec<ValidationReport>) -> Self {
        if reports.is_empty() {
            Self::default()
        } else {
            Self {
                groups: vec![ValidationEvidenceGroup {
                    binding: None,
                    reports,
                }],
            }
        }
    }

    pub fn reports(&self) -> Vec<ValidationReport> {
        let mut reports = self
            .groups
            .iter()
            .flat_map(|group| group.reports.iter().cloned())
            .collect::<Vec<_>>();
        sort_validation_reports(&mut reports);
        reports
    }

    pub fn extend(&mut self, mut other: Self) {
        self.groups.append(&mut other.groups);
    }

    /// Constructs canonical passed evidence for one exact candidate binding.
    pub(crate) fn bound_to(
        binding: CandidateValidationBinding,
        reports: Vec<ValidationReport>,
    ) -> Result<BoundValidationEvidenceBundle> {
        Self {
            groups: vec![ValidationEvidenceGroup {
                binding: Some(binding),
                reports,
            }],
        }
        .try_into_exact_bound()
    }

    /// Validates an existing bundle before granting strict publication
    /// authority. Legacy, unbound, multi-group, malformed, empty, skipped, or
    /// failed evidence cannot be upgraded by naming it bound.
    pub(crate) fn try_into_exact_bound(self) -> Result<BoundValidationEvidenceBundle> {
        if self.groups.len() != 1 {
            bail!("strict publication evidence must contain exactly one bound group");
        }
        let group = self
            .groups
            .into_iter()
            .next()
            .context("strict publication evidence group disappeared")?;
        let binding = group
            .binding
            .context("strict publication evidence uses the legacy unbound format")?
            .canonicalized()?;
        let reports = canonical_bound_validation_reports(group.reports)?;
        let evidence = Self {
            groups: vec![ValidationEvidenceGroup {
                binding: Some(binding.clone()),
                reports,
            }],
        };
        Ok(BoundValidationEvidenceBundle { binding, evidence })
    }

    fn push_bound_reports(
        &mut self,
        binding: CandidateValidationBinding,
        reports: Vec<ValidationReport>,
    ) {
        if reports.is_empty() {
            return;
        }
        self.groups.push(ValidationEvidenceGroup {
            binding: Some(binding),
            reports,
        });
    }
}

impl BoundValidationEvidenceBundle {
    pub(crate) fn binding(&self) -> &CandidateValidationBinding {
        &self.binding
    }

    pub(crate) fn evidence(&self) -> &ValidationEvidenceBundle {
        &self.evidence
    }
}

fn canonical_bound_validation_reports(
    mut reports: Vec<ValidationReport>,
) -> Result<Vec<ValidationReport>> {
    if reports.is_empty() {
        bail!("strict publication evidence requires at least one passed validation report");
    }
    if reports.len() > MAX_BOUND_VALIDATION_REPORTS {
        bail!(
            "strict publication evidence exceeds its {MAX_BOUND_VALIDATION_REPORTS}-report limit"
        );
    }
    for report in &mut reports {
        report.name = report.name.trim().to_string();
        if report.name.is_empty()
            || report.name.len() > MAX_BOUND_VALIDATION_NAME_BYTES
            || report.name.chars().any(char::is_control)
        {
            bail!("strict publication validation report name is invalid");
        }
        if report.status != ValidationStatus::Passed {
            bail!("strict publication evidence accepts only passed validation reports");
        }
        if report
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_BOUND_VALIDATION_MESSAGE_BYTES)
        {
            bail!("strict publication validation message exceeds its size limit");
        }
        if report.paths.len() > MAX_BOUND_VALIDATION_PATHS_PER_REPORT {
            bail!(
                "strict publication validation report exceeds its {MAX_BOUND_VALIDATION_PATHS_PER_REPORT}-path limit"
            );
        }
        report.paths = report
            .paths
            .iter()
            .map(|path| normalize_repo_relative_path(path).map_err(anyhow::Error::from))
            .collect::<Result<Vec<_>>>()?;
        report.paths.sort();
        report.paths.dedup();
    }
    sort_validation_reports(&mut reports);
    reports.dedup();
    Ok(reports)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyPreview {
    pub review_intent: MergeApplyReviewIntent,
    pub candidate: MergeCandidate,
    pub safety: MergeApplySafety,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplySafety {
    pub primary_state_unchanged: SafetyCheck,
    pub dirty_primary: SafetyCheck,
    pub stale_base: SafetyCheck,
    pub apply_check: SafetyCheck,
    pub unclaimed_edits: SafetyCheck,
    pub validation: SafetyCheck,
    pub validation_evidence: ValidationEvidenceCheck,
    pub megafile: SafetyCheck,
    pub megafile_warnings: Vec<MegafileAssessment>,
    #[serde(serialize_with = "serialize_optional_path")]
    pub megafile_decomposition_target: Option<PathBuf>,
    pub megafile_decomposition_evidence: Option<VerifiedMegafileDecompositionEvidence>,
    pub megafile_blocking: bool,
    pub validation_required: bool,
    pub candidate_validation_commands: Vec<String>,
    pub force_options: MergeForceOptions,
    pub apply_mode: ApplyMode,
    pub semantic_conflicts: SemanticConflictClassification,
    pub readiness: ApplyReadiness,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SafetyCheck {
    pub status: SafetyCheckStatus,
    pub message: Option<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCheckStatus {
    Passed,
    Failed,
    #[default]
    Skipped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyMode {
    #[default]
    None,
    Direct,
    ThreeWay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyReadiness {
    pub status: ApplyReadinessStatus,
    pub blockers: Vec<ApplyBlocker>,
    pub forced: Vec<ApplyBlocker>,
    pub details: Vec<ApplyBlockerDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyReadinessStatus {
    Safe,
    Forced,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyBlocker {
    DirtyPrimary,
    StaleBase,
    PrimaryStateChanged,
    ApplyCheckFailed,
    ExcludedReference,
    UnclaimedEdits,
    ValidationMissing,
    ValidationNotRun,
    ValidationSkipped,
    ValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationEvidenceCheck {
    pub status: SafetyCheckStatus,
    pub binding_status: ValidationBindingStatus,
    pub message: Option<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationBindingStatus {
    NotRequired,
    NoPassedReport,
    Bound,
    Unbound,
    Mismatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyBlockerDetail {
    pub kind: ApplyBlocker,
    pub disposition: ApplyBlockerDisposition,
    pub check_status: SafetyCheckStatus,
    #[serde(serialize_with = "serialize_paths")]
    pub paths: Vec<PathBuf>,
    pub message: Option<String>,
    pub validation_reports: Vec<ValidationReport>,
    pub validation_commands: Vec<String>,
    pub next_safe_operation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyBlockerDisposition {
    Blocked,
    Forced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyReport {
    pub preview: MergeApplyPreview,
    pub status: MergeApplyReportStatus,
    pub applied: bool,
    pub review_bound: bool,
    pub review_binding_status: MergeReviewBindingStatus,
    pub gate_denials: Vec<GateDenial>,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub recorded_collision_paths: Vec<PathBuf>,
    pub accepted_decomposition: Option<MegafileAssessment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<WorktreeLifecycleReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeApplyReportStatus {
    Applied,
    NothingToApply,
    Blocked,
}

pub(crate) struct RequiredCommandOutput {
    pub(crate) success: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

type GitCommandOutput = RequiredCommandOutput;

pub(crate) struct RepoCommonLock {
    file: fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RepoLockOwner {
    version: u32,
    pid: u32,
    nonce: String,
    created_unix_seconds: u64,
    operation: String,
    process_start: Option<ProcessStartIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum ProcessStartIdentity {
    #[cfg(target_os = "linux")]
    LinuxProcStartTicks(u64),
    #[cfg(target_os = "windows")]
    WindowsCreationFiletime(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateBoundaryState {
    primary_head: Option<Oid>,
    agent_head: Option<Oid>,
    index_digest: Option<Oid>,
    worktree_status: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateRepositorySnapshot {
    metadata: WorktreeMergeMetadata,
    index_digest: Option<Oid>,
    worktree_status: Vec<u8>,
    snapshot_tree: Oid,
    changes: Vec<ChangedPath>,
    raw_diff: Vec<u8>,
}

struct TemporaryIndex {
    directory: PathBuf,
    alternate_object_directory: PathBuf,
    _runtime_directory: Option<PrivateRuntimeDirectory>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateRuntimeKind {
    CandidateCapture,
    CandidateValidation,
    PublicationGit,
    GhConfig,
}

impl PrivateRuntimeKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::CandidateCapture => "maco-candidate-capture-",
            Self::CandidateValidation => "maco-candidate-validation-",
            Self::PublicationGit => "maco-publication-git-",
            Self::GhConfig => "maco-gh-config-",
        }
    }

    fn owner_path(self, directory: &Path) -> PathBuf {
        match self {
            Self::CandidateValidation => directory.join(".git").join(PRIVATE_RUNTIME_OWNER_FILE),
            _ => directory.join(PRIVATE_RUNTIME_OWNER_FILE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateRuntimeOwner {
    version: u32,
    pid: u32,
    process_start: Option<ProcessStartIdentity>,
    boot_id: Option<String>,
    created_unix_seconds: u64,
    kind: PrivateRuntimeKind,
    nonce: String,
}

pub(crate) struct PrivateRuntimeDirectory {
    runtime_root: PathBuf,
    path: PathBuf,
    owner: PrivateRuntimeOwner,
    directory_metadata: fs::Metadata,
    closed: bool,
}

struct PrivateRuntimeRootLock {
    file: fs::File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateRuntimeScavengeReport {
    removed: usize,
    retained: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedWorktreeTree {
    oid: Oid,
    entries: BTreeMap<PathBuf, CandidateSnapshotEntry>,
    changes: Vec<ChangedPath>,
    raw_diff: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateSnapshotEntry {
    RegularFile { bytes: usize },
    Other { filemode: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrimaryRepositoryState {
    head: Option<Oid>,
    index_digest: Option<Oid>,
    worktree_digest: Oid,
}

/// A verified managed-worktree record whose shared execution lease remains
/// held for the complete lifetime of the value.
///
/// Field access transparently dereferences to [`WorktreeRecord`] for existing
/// callers, but the record cannot be returned without retaining the lease.
#[derive(Debug)]
pub struct AgentWorktreeReadLease {
    lease: ManagedWorktreeReadLease,
}

impl AgentWorktreeReadLease {
    pub fn record(&self) -> &WorktreeRecord {
        self.lease.record()
    }
}

impl Deref for AgentWorktreeReadLease {
    type Target = WorktreeRecord;

    fn deref(&self) -> &Self::Target {
        self.record()
    }
}

/// Resolves a managed worktree for immutable inspection only.
///
/// The returned shared lease excludes writers and removal. Callers that may
/// run validation, repair, Git index updates, or any other mutating operation
/// must acquire `WorktreeManager::acquire_write_execution_lease` instead.
pub fn find_agent_worktree_read_only(
    manager: &WorktreeManager,
    agent_id: impl AsRef<str>,
) -> Result<AgentWorktreeReadLease> {
    let agent_id = normalize_agent_id(agent_id.as_ref())?;
    let lease = manager
        .acquire_read_execution_lease(&agent_id)
        .with_context(|| {
            format!("worktree for agent '{agent_id}' is not registered or readable")
        })?;
    Ok(AgentWorktreeReadLease { lease })
}

/// Compatibility spelling for immutable lookup.
///
/// Despite the historical name, this API grants read-only authority. It is
/// retained while mutating call sites migrate to explicit write leases.
pub fn find_agent_worktree(
    manager: &WorktreeManager,
    agent_id: impl AsRef<str>,
) -> Result<AgentWorktreeReadLease> {
    find_agent_worktree_read_only(manager, agent_id)
}

pub fn collect_agent_result(options: MergeCollectOptions) -> Result<MergeCandidate> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    collect_agent_result_with_evidence(options, evidence)
}

fn collect_agent_result_with_evidence(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeCandidate> {
    collect_agent_result_with_evidence_after_lease(options, validation_evidence, || {})
}

fn collect_agent_result_with_evidence_and_local_git_options(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    local_git: MergeLocalGitOptions,
) -> Result<MergeCandidate> {
    collect_agent_result_with_evidence_after_lease_and_local_git_options(
        options,
        validation_evidence,
        local_git,
        || {},
    )
}

fn collect_agent_result_with_evidence_after_lease<F>(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    after_lease: F,
) -> Result<MergeCandidate>
where
    F: FnOnce(),
{
    collect_agent_result_with_evidence_after_lease_and_local_git_options(
        options,
        validation_evidence,
        MergeLocalGitOptions::default(),
        after_lease,
    )
}

fn collect_agent_result_with_evidence_after_lease_and_local_git_options<F>(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    local_git: MergeLocalGitOptions,
    after_lease: F,
) -> Result<MergeCandidate>
where
    F: FnOnce(),
{
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let leased_worktree = find_agent_worktree_read_only(&manager, &options.agent_id)?;
    after_lease();
    collect_agent_result_from_verified_record(
        options,
        validation_evidence,
        repo_root,
        leased_worktree.record(),
        local_git,
    )
}

/// Collects an immutable candidate while a caller retains exclusive authority
/// for the managed worktree.
///
/// This is the publication/autopilot bridge: it verifies the borrowed lease's
/// repository and agent binding, then snapshots directly under that authority
/// instead of trying to nest a shared read lease beneath the caller's write
/// lease.
pub(crate) fn collect_agent_result_with_evidence_and_write_lease(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<MergeCandidate> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    manager.verify_write_execution_lease(&options.agent_id, write_lease)?;
    collect_agent_result_from_verified_record(
        options,
        validation_evidence,
        repo_root,
        write_lease.record(),
        MergeLocalGitOptions::default(),
    )
}

fn collect_agent_result_from_verified_record(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    repo_root: PathBuf,
    record: &WorktreeRecord,
    local_git: MergeLocalGitOptions,
) -> Result<MergeCandidate> {
    let primary_repo = crate::git_repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let agent_repo = crate::git_repository::open(&record.path)
        .with_context(|| format!("failed to open agent worktree {}", record.path.display()))?;

    let claimed_paths = normalize_claim_paths(options.claimed_paths)?;
    let snapshot = capture_consistent_candidate_snapshot(
        &primary_repo,
        &agent_repo,
        record,
        repo_root,
        local_git,
    )?;
    let snapshot_tree = snapshot.snapshot_tree;
    let metadata = snapshot.metadata;
    let changes = snapshot.changes;
    let changed_paths = changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    let unclaimed_changed_paths = unclaimed_paths(&changed_paths, &claimed_paths);
    let raw_diff = snapshot.raw_diff;
    let presented_diff = patch_text_for_json(&raw_diff);
    let validation_binding = candidate_validation_binding(&metadata, &raw_diff)?;
    let validations = validation_evidence.reports();
    let diff = DiffOutput {
        summary: summarize_text(&presented_diff, options.diff_summary_char_limit),
        full: options.include_full_diff.then_some(presented_diff),
    };

    Ok(MergeCandidate {
        metadata,
        claimed_paths,
        changed_paths,
        changes,
        unclaimed_changed_paths,
        diff,
        validations,
        validation_binding,
        validation_evidence,
        raw_diff,
        snapshot_tree,
    })
}

pub fn preview_merge_apply(options: MergePreviewOptions) -> Result<MergeApplyPreview> {
    let evidence = ValidationEvidenceBundle::legacy(options.collect.validations.clone());
    preview_merge_apply_with_evidence(options, evidence)
}

pub fn preview_merge_apply_with_evidence(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyPreview> {
    preview_merge_apply_with_megafile_policy(
        options,
        validation_evidence,
        MegafileMergePolicy::default(),
    )
}

pub fn preview_merge_apply_with_megafile_policy(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
) -> Result<MergeApplyPreview> {
    preview_merge_apply_with_megafile_policy_and_local_git_options(
        options,
        validation_evidence,
        megafile_policy,
        MergeLocalGitOptions::default(),
    )
}

pub(crate) fn preview_merge_apply_with_megafile_policy_and_local_git_options(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
    local_git: MergeLocalGitOptions,
) -> Result<MergeApplyPreview> {
    let mut preview = build_unassessed_merge_apply_preview_with_local_git_options(
        options,
        validation_evidence,
        local_git,
    )?;
    assess_megafile_policy_with_local_git_options(&mut preview, &megafile_policy, local_git)?;
    Ok(preview)
}

fn build_unassessed_merge_apply_preview_with_local_git_options(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    local_git: MergeLocalGitOptions,
) -> Result<MergeApplyPreview> {
    options.review_intent.validate()?;
    let MergePreviewOptions {
        mut collect,
        forces,
        require_validation,
        review_intent,
    } = options;
    collect.include_full_diff = true;
    let candidate = collect_agent_result_with_evidence_and_local_git_options(
        collect,
        validation_evidence,
        local_git,
    )?;
    build_merge_apply_preview(candidate, forces, require_validation, review_intent)
}

/// Builds a merge preview without attempting to acquire a nested shared
/// worktree lease when the caller already holds verified write authority.
pub(crate) fn preview_merge_apply_with_evidence_and_write_lease(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<MergeApplyPreview> {
    options.review_intent.validate()?;
    let MergePreviewOptions {
        mut collect,
        forces,
        require_validation,
        review_intent,
    } = options;
    collect.include_full_diff = true;
    let candidate = collect_agent_result_with_evidence_and_write_lease(
        collect,
        validation_evidence,
        write_lease,
    )?;
    let mut preview =
        build_merge_apply_preview(candidate, forces, require_validation, review_intent)?;
    assess_megafile_policy(&mut preview, &MegafileMergePolicy::default())?;
    Ok(preview)
}

pub(crate) fn build_merge_apply_preview(
    candidate: MergeCandidate,
    forces: MergeForceOptions,
    require_validation: bool,
    review_intent: MergeApplyReviewIntent,
) -> Result<MergeApplyPreview> {
    review_intent.validate()?;
    if require_validation != review_intent.require_validation_after_candidate {
        bail!(
            "merge preview validation requirement does not match the reviewed merge apply intent"
        );
    }
    let patch = candidate.raw_diff.as_slice();
    let candidate_validation_commands = review_intent.candidate_validation_commands.clone();
    let base_require_validation = require_validation && candidate_validation_commands.is_empty();

    let primary_state_unchanged = passed_safety_check();
    let dirty_primary = dirty_primary_check(&candidate.metadata.primary_repo_root)?;
    let stale_base = stale_base_check(&candidate.metadata);
    let unclaimed_edits = unclaimed_edits_check(&candidate.unclaimed_changed_paths);
    let validation = validation_check(&candidate.validations, base_require_validation);
    let validation_evidence = validation_evidence_check(
        &candidate.validation_evidence,
        &candidate.validation_binding,
        base_require_validation,
        &candidate.changed_paths,
    );
    let megafile = SafetyCheck {
        status: SafetyCheckStatus::Skipped,
        message: Some("megafile telemetry has not been assessed".to_string()),
        paths: Vec::new(),
    };
    let (apply_check, apply_mode) = apply_check(
        &candidate.metadata.primary_repo_root,
        patch,
        forces.allow_apply_conflicts,
    )?;
    let semantic_conflicts = classify_semantic_conflicts(&candidate, &apply_check);
    let checks = SafetyChecks {
        primary_state_unchanged: &primary_state_unchanged,
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validation_evidence: &validation_evidence,
        megafile: &megafile,
        validations: &candidate.validations,
        require_validation: base_require_validation,
        validation_commands: &candidate_validation_commands,
        validation_related_paths: &candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &forces);

    Ok(MergeApplyPreview {
        review_intent,
        candidate,
        safety: MergeApplySafety {
            primary_state_unchanged,
            dirty_primary,
            stale_base,
            apply_check,
            unclaimed_edits,
            validation,
            validation_evidence,
            megafile,
            megafile_warnings: Vec::new(),
            megafile_decomposition_target: None,
            megafile_decomposition_evidence: None,
            megafile_blocking: false,
            validation_required: base_require_validation,
            candidate_validation_commands,
            force_options: forces,
            apply_mode,
            semantic_conflicts,
            readiness,
        },
    })
}

fn assess_megafile_policy(
    preview: &mut MergeApplyPreview,
    policy: &MegafileMergePolicy,
) -> Result<()> {
    assess_megafile_policy_with_local_git_options(preview, policy, MergeLocalGitOptions::default())
}

fn assess_megafile_policy_with_local_git_options(
    preview: &mut MergeApplyPreview,
    policy: &MegafileMergePolicy,
    local_git: MergeLocalGitOptions,
) -> Result<()> {
    policy
        .thresholds
        .validate()
        .context("merge megafile thresholds are invalid")?;
    let decomposition_target = policy
        .decomposition_target
        .as_deref()
        .map(normalize_repo_relative_path)
        .transpose()
        .context("megafile decomposition target is invalid")?;
    match (&decomposition_target, &policy.decomposition_run_id) {
        (Some(_), None) => {
            bail!("megafile decomposition target requires a finalized supervise run id")
        }
        (None, Some(_)) => bail!("megafile decomposition run id requires an exact target"),
        _ => {}
    }

    if let Some(target) = &decomposition_target {
        if !preview.candidate.changed_paths.contains(target) {
            bail!(
                "megafile decomposition target '{}' is not changed by this candidate",
                path_json_text(target)
            );
        }
        if !preview.candidate.claimed_paths.contains(target) {
            bail!(
                "megafile decomposition target '{}' requires an exact path claim",
                path_json_text(target)
            );
        }
    }

    let decomposition_evidence = match (&decomposition_target, &policy.decomposition_run_id) {
        (Some(target), Some(run_id)) => {
            let evidence = verified_megafile_decomposition_evidence(
                &preview.candidate.metadata.primary_repo_root,
                run_id.clone(),
                &preview.candidate.metadata.agent_id,
                target,
                &preview.candidate.changed_paths,
            )
            .context("megafile decomposition supervise evidence was rejected")?;
            verify_decomposition_candidate_structure(&preview.candidate, &evidence, local_git)?;
            Some(evidence)
        }
        _ => None,
    };

    let store = MegafileStore::open_existing_with_thresholds(
        &preview.candidate.metadata.primary_repo_root,
        policy.thresholds.clone(),
    )
    .context("authenticated megafile telemetry could not be read for the merge decision")?;
    let mut assessments = match store {
        Some(store) => store.report()?.assessments,
        None => Vec::new(),
    };
    assessments.retain(|assessment| {
        assessment.is_megafile && preview.candidate.changed_paths.contains(&assessment.path)
    });
    assessments.sort_by(|left, right| left.path.cmp(&right.path));

    if let Some(target) = &decomposition_target {
        if !assessments
            .iter()
            .any(|assessment| assessment.path == *target)
        {
            bail!(
                "megafile decomposition target '{}' is not an authenticated threshold-crossing megafile",
                path_json_text(target)
            );
        }
    }

    let blocked_paths = assessments
        .iter()
        .filter(|assessment| decomposition_target.as_ref() != Some(&assessment.path))
        .map(|assessment| assessment.path.clone())
        .collect::<Vec<_>>();
    let megafile = if policy.block && !blocked_paths.is_empty() {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "candidate touches authenticated threshold-crossing megafiles; run an exact typed decomposition assignment or omit opt-in blocking"
                    .to_string(),
            ),
            paths: blocked_paths,
        }
    } else if assessments.is_empty() {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: Some(
                "no changed path crosses the authenticated megafile thresholds".to_string(),
            ),
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: Some(if decomposition_target.is_some() {
                "authenticated megafile warnings are non-blocking for the exact typed decomposition target"
                    .to_string()
            } else {
                "authenticated megafile thresholds crossed; default merge policy is warn-only"
                    .to_string()
            }),
            paths: assessments
                .iter()
                .map(|assessment| assessment.path.clone())
                .collect(),
        }
    };

    preview.safety.megafile = megafile;
    preview.safety.megafile_warnings = assessments;
    preview.safety.megafile_decomposition_target = decomposition_target;
    preview.safety.megafile_decomposition_evidence = decomposition_evidence;
    preview.safety.megafile_blocking = policy.block;
    reclassify_preview_readiness(preview);
    Ok(())
}

fn verify_decomposition_candidate_structure(
    candidate: &MergeCandidate,
    evidence: &VerifiedMegafileDecompositionEvidence,
    local_git: MergeLocalGitOptions,
) -> Result<()> {
    let target_change = candidate
        .changes
        .iter()
        .find(|change| change.path == evidence.target_path)
        .context("decomposition target is absent from candidate change metadata")?;
    if !matches!(
        target_change.kind,
        ChangeKind::Modified | ChangeKind::Deleted
    ) {
        bail!(
            "decomposition target '{}' must be modified or deleted, not {:?}",
            path_json_text(&evidence.target_path),
            target_change.kind
        );
    }
    if evidence.replacement_paths.is_empty() {
        bail!("verified decomposition evidence has no replacement paths");
    }

    let repo =
        crate::git_repository::open(&candidate.metadata.primary_repo_root).with_context(|| {
            format!(
                "failed to open primary repository {} for decomposition structure verification",
                candidate.metadata.primary_repo_root.display()
            )
        })?;
    let primary_head = candidate
        .metadata
        .primary_head
        .as_deref()
        .context("decomposition structure verification requires a primary candidate base")?;
    let primary_oid = Oid::from_str(primary_head)
        .with_context(|| format!("invalid candidate primary head '{primary_head}'"))?;
    let primary_tree = repo
        .find_commit(primary_oid)
        .context("failed to resolve candidate primary base commit")?
        .tree()
        .context("failed to resolve candidate primary base tree")?;
    let snapshot_entries = recapture_candidate_snapshot_entries(candidate, local_git)?;
    if candidate.validation_binding != evidence.supervisor_candidate_binding {
        bail!(
            "current decomposition candidate content binding does not match the exact supervisor-inspected candidate finalized by run '{}'",
            evidence.run_id.as_str()
        );
    }

    let base_target_size = regular_blob_size_at_path(
        &repo,
        &primary_tree,
        &evidence.target_path,
        "primary candidate base target",
    )?
    .context(
        "decomposition target does not exist as a regular file in the primary candidate base",
    )?;
    match candidate_regular_file_size(
        &snapshot_entries,
        &evidence.target_path,
        "candidate decomposition target",
    )? {
        Some(candidate_size) if candidate_size < base_target_size => {}
        Some(candidate_size) => bail!(
            "decomposition target '{}' did not shrink: base={} bytes, candidate={} bytes",
            path_json_text(&evidence.target_path),
            base_target_size,
            candidate_size
        ),
        None if target_change.kind == ChangeKind::Deleted => {}
        None => bail!(
            "decomposition target '{}' disappeared without a deleted change",
            path_json_text(&evidence.target_path)
        ),
    }

    for replacement in &evidence.replacement_paths {
        let replacement_change = candidate
            .changes
            .iter()
            .find(|change| change.path == *replacement)
            .with_context(|| {
                format!(
                    "evidence-bound replacement '{}' is absent from candidate change metadata",
                    path_json_text(replacement)
                )
            })?;
        if !matches!(
            replacement_change.kind,
            ChangeKind::Added | ChangeKind::Untracked
        ) {
            bail!(
                "evidence-bound replacement '{}' is not newly added",
                path_json_text(replacement)
            );
        }
        if regular_blob_size_at_path(
            &repo,
            &primary_tree,
            replacement,
            "primary candidate base replacement",
        )?
        .is_some()
        {
            bail!(
                "evidence-bound replacement '{}' already exists in the primary candidate base",
                path_json_text(replacement)
            );
        }
        let replacement_size =
            candidate_regular_file_size(&snapshot_entries, replacement, "candidate replacement")?
                .with_context(|| {
                format!(
                    "evidence-bound replacement '{}' is absent from the candidate snapshot",
                    path_json_text(replacement)
                )
            })?;
        if replacement_size == 0 {
            bail!(
                "evidence-bound replacement '{}' is empty",
                path_json_text(replacement)
            );
        }
    }
    Ok(())
}

fn candidate_regular_file_size(
    snapshot_entries: &BTreeMap<PathBuf, CandidateSnapshotEntry>,
    path: &Path,
    description: &str,
) -> Result<Option<usize>> {
    match snapshot_entries.get(path) {
        Some(CandidateSnapshotEntry::RegularFile { bytes }) => Ok(Some(*bytes)),
        Some(CandidateSnapshotEntry::Other { filemode }) => bail!(
            "{description} '{}' is not a regular file (mode {filemode:o})",
            path.display()
        ),
        None => Ok(None),
    }
}

fn capture_matching_decomposition_snapshot<T, F>(
    local_git: MergeLocalGitOptions,
    mut capture: F,
) -> Result<T>
where
    T: PartialEq,
    F: FnMut(MergeLocalGitOptions) -> Result<Option<T>>,
{
    capture_two_matching(|| capture(local_git))
}

fn recapture_candidate_snapshot_entries(
    candidate: &MergeCandidate,
    local_git: MergeLocalGitOptions,
) -> Result<BTreeMap<PathBuf, CandidateSnapshotEntry>> {
    let agent_repo =
        crate::git_repository::open(&candidate.metadata.worktree_path).with_context(|| {
            format!(
                "failed to open candidate worktree {} for decomposition recapture",
                candidate.metadata.worktree_path.display()
            )
        })?;
    let agent_head = candidate
        .metadata
        .agent_head
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("candidate agent head is invalid")?;
    let base = collection_base_oid(&candidate.metadata)?;
    let captured = capture_matching_decomposition_snapshot(local_git, |local_git| {
        snapshot_worktree_candidate_from_base_with_local_git_options(
            &agent_repo,
            &candidate.metadata.worktree_path,
            agent_head,
            base,
            local_git,
        )
        .map(Some)
    })
    .context("failed to recapture candidate for decomposition structure verification")?;
    let recaptured_paths = captured
        .changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    if captured.oid != candidate.snapshot_tree
        || captured.raw_diff != candidate.raw_diff
        || recaptured_paths != candidate.changed_paths
    {
        bail!("candidate changed while decomposition structure evidence was verified");
    }
    Ok(captured.entries)
}

fn regular_blob_size_at_path(
    repo: &Repository,
    tree: &git2::Tree<'_>,
    path: &Path,
    description: &str,
) -> Result<Option<usize>> {
    let entry = match tree.get_path(path) {
        Ok(entry) => entry,
        Err(error) if error.code() == ErrorCode::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {description} '{}'", path.display()))
        }
    };
    if entry.kind() != Some(ObjectType::Blob) || !matches!(entry.filemode(), 0o100644 | 0o100755) {
        bail!("{description} '{}' is not a regular file", path.display());
    }
    let blob = repo
        .find_blob(entry.id())
        .with_context(|| format!("failed to read {description} blob '{}'", path.display()))?;
    Ok(Some(blob.size()))
}

fn reclassify_preview_readiness(preview: &mut MergeApplyPreview) {
    let checks = SafetyChecks {
        primary_state_unchanged: &preview.safety.primary_state_unchanged,
        dirty_primary: &preview.safety.dirty_primary,
        stale_base: &preview.safety.stale_base,
        apply_check: &preview.safety.apply_check,
        unclaimed_edits: &preview.safety.unclaimed_edits,
        validation: &preview.safety.validation,
        validation_evidence: &preview.safety.validation_evidence,
        megafile: &preview.safety.megafile,
        validations: &preview.candidate.validations,
        require_validation: preview.safety.validation_required,
        validation_commands: &preview.safety.candidate_validation_commands,
        validation_related_paths: &preview.candidate.changed_paths,
    };
    preview.safety.readiness = classify_apply_safety(checks, &preview.safety.force_options);
}

const DIRECT_PROGRAMMATIC_APPLY_DISABLED: &str = "direct programmatic apply is disabled; callers must use the guarded merge apply CLI with previously emitted reviewed preview evidence";

fn direct_programmatic_apply_disabled() -> Result<MergeApplyReport> {
    bail!(DIRECT_PROGRAMMATIC_APPLY_DISABLED)
}

pub fn apply_merge_result(_options: MergeApplyOptions) -> Result<MergeApplyReport> {
    direct_programmatic_apply_disabled()
}

pub fn apply_merge_result_with_evidence(
    _options: MergeApplyOptions,
    _validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    direct_programmatic_apply_disabled()
}

pub fn merge_apply_report(_options: MergeApplyOptions) -> Result<MergeApplyReport> {
    direct_programmatic_apply_disabled()
}

#[cfg(test)]
pub(crate) fn merge_apply_report_internal(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.preview.collect.validations.clone());
    merge_apply_report_with_evidence_internal(options, evidence)
}

pub fn merge_apply_report_with_evidence(
    _options: MergeApplyOptions,
    _validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    direct_programmatic_apply_disabled()
}

#[cfg(test)]
pub(crate) fn merge_apply_report_with_evidence_internal(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    merge_apply_report_with_megafile_policy_internal(
        options,
        validation_evidence,
        MegafileMergePolicy::default(),
    )
}

pub fn merge_apply_report_with_megafile_policy(
    _options: MergeApplyOptions,
    _validation_evidence: ValidationEvidenceBundle,
    _megafile_policy: MegafileMergePolicy,
) -> Result<MergeApplyReport> {
    direct_programmatic_apply_disabled()
}

#[cfg(test)]
pub(crate) fn merge_apply_report_with_megafile_policy_internal(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
) -> Result<MergeApplyReport> {
    merge_apply_report_with_megafile_policy_and_local_git_options(
        options,
        validation_evidence,
        megafile_policy,
        MergeLocalGitOptions::default(),
    )
}

pub(crate) fn merge_apply_report_with_megafile_policy_and_local_git_options(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
    local_git: MergeLocalGitOptions,
) -> Result<MergeApplyReport> {
    let MergeApplyOptions {
        preview,
        candidate_validation_commands,
        reviewed_watermark,
    } = options;
    // Validate and bind caller-provided authority before any repository read,
    // lock acquisition, or merge-domain telemetry.
    preview.review_intent.validate()?;
    let candidate_validation_command_labels = candidate_validation_commands
        .iter()
        .map(|command| command.command.clone())
        .collect::<Vec<_>>();
    if candidate_validation_command_labels != preview.review_intent.candidate_validation_commands
        || preview.require_validation != preview.review_intent.require_validation_after_candidate
    {
        return Err(MergePreviewFreshnessError::Mismatch {
            axes: vec![MergePreviewDriftAxis::BasePreview],
            moved: "base preview".to_string(),
        }
        .into());
    }
    let reviewed_watermark = reviewed_watermark.canonicalized()?;
    let current_preview = preview_merge_apply_with_megafile_policy_and_local_git_options(
        preview.clone(),
        validation_evidence.clone(),
        megafile_policy.clone(),
        local_git,
    )?;
    let current_watermark = MergePreviewFreshnessWatermark::capture_from_preview(&current_preview)?;
    crate::merge_freshness::refuse_if_drifted(&reviewed_watermark, &current_watermark)?;
    let repo_root = discover_primary_repo_root(&preview.collect.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "merge-apply")?;
    let require_validation_after_candidate =
        preview.review_intent.require_validation_after_candidate;
    let review_context = MergeReviewRevalidationContext {
        reviewed: reviewed_watermark,
        preview_options: preview.clone(),
        validation_evidence: validation_evidence.clone(),
        megafile_policy: megafile_policy.clone(),
        local_git,
    };
    let mut preview = build_unassessed_merge_apply_preview_with_local_git_options(
        preview,
        validation_evidence,
        local_git,
    )?;
    let preliminary = MergePreviewFreshnessWatermark::capture_from_preview(&preview)?;
    crate::merge_freshness::refuse_if_state_or_candidate_drifted(
        &review_context.reviewed,
        &preliminary,
    )?;
    assess_megafile_policy_with_local_git_options(&mut preview, &megafile_policy, local_git)?;
    review_context.verify_preview(&preview)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        let recorded_collision_paths =
            record_merge_collision_decision(&preview, &megafile_policy.thresholds)?;
        let mut report = blocked_merge_apply_report(preview)?;
        report.recorded_collision_paths = recorded_collision_paths;
        return Ok(report);
    }
    let expected_primary_state = PrimaryRepositoryState::capture(&repo_root)?;

    let mut report = apply_prechecked_merge_with_candidate_validation_locked(
        preview,
        candidate_validation_commands,
        require_validation_after_candidate,
        &expected_primary_state,
        &review_context,
        &megafile_policy.thresholds,
        local_git,
    )?;
    if report.applied {
        if let Some(evidence) = report
            .preview
            .safety
            .megafile_decomposition_evidence
            .as_ref()
        {
            let assessment = MegafileStore::open_with_thresholds(
                &repo_root,
                megafile_policy.thresholds,
            )
            .context(
                "merge was applied, but authenticated megafile telemetry could not be opened to record the accepted decomposition; do not retry the merge",
            )?
            .record_accepted_decomposition(
                &evidence.target_path,
                evidence.replacement_paths.clone(),
            )
            .context(
                "merge was applied, but accepted decomposition telemetry could not be persisted; do not retry the merge",
            )?;
            report.accepted_decomposition = Some(assessment);
        }
    }
    Ok(report)
}

struct MergeReviewRevalidationContext {
    reviewed: MergePreviewFreshnessWatermark,
    preview_options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
    local_git: MergeLocalGitOptions,
}

impl MergeReviewRevalidationContext {
    fn verify_preview(&self, preview: &MergeApplyPreview) -> Result<()> {
        let current = MergePreviewFreshnessWatermark::capture_from_preview(preview)?;
        crate::merge_freshness::refuse_if_drifted(&self.reviewed, &current)?;
        Ok(())
    }

    fn recapture_and_verify(&self) -> Result<()> {
        let current_preview = preview_merge_apply_with_megafile_policy_and_local_git_options(
            self.preview_options.clone(),
            self.validation_evidence.clone(),
            self.megafile_policy.clone(),
            self.local_git,
        )?;
        self.verify_preview(&current_preview)
    }
}

fn record_merge_collision_decision(
    preview: &MergeApplyPreview,
    thresholds: &MegafileThresholds,
) -> Result<Vec<PathBuf>> {
    let direct_apply_collision = preview.safety.apply_check.status == SafetyCheckStatus::Failed
        || preview.safety.apply_mode == ApplyMode::ThreeWay;
    if !direct_apply_collision {
        return Ok(Vec::new());
    }
    let mut paths = if preview.safety.apply_check.paths.is_empty() {
        preview.candidate.changed_paths.clone()
    } else {
        preview.safety.apply_check.paths.clone()
    };
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    MegafileStore::open_with_thresholds(
        &preview.candidate.metadata.primary_repo_root,
        thresholds.clone(),
    )
    .context("authenticated megafile telemetry could not be opened for collision accounting")?
    .record_collision_paths(&paths)
    .context(
        "merge collision decision was not persisted to authenticated megafile telemetry; merge integration is refused",
    )?;
    Ok(paths)
}

fn blocked_merge_apply_report(preview: MergeApplyPreview) -> Result<MergeApplyReport> {
    let error = if preview.safety.readiness.blockers.is_empty() {
        None
    } else {
        Some(format!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        ))
    };
    let gate_denials = merge_apply_gate_denials(&preview)?;

    Ok(MergeApplyReport {
        preview,
        status: MergeApplyReportStatus::Blocked,
        applied: false,
        review_bound: true,
        review_binding_status: MergeReviewBindingStatus::Matched,
        gate_denials,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error,
        recorded_collision_paths: Vec::new(),
        accepted_decomposition: None,
        lifecycle: None,
    })
}

fn merge_apply_gate_denials(preview: &MergeApplyPreview) -> Result<Vec<GateDenial>> {
    let owner = &preview.candidate.metadata.agent_id;
    let mut gate_denials = Vec::new();
    for detail in preview
        .safety
        .readiness
        .details
        .iter()
        .filter(|detail| detail.disposition == ApplyBlockerDisposition::Blocked)
    {
        let ordinal = gate_denials.len().saturating_add(1);
        let correlation_id = format!("merge-apply-{owner}-{ordinal}");
        let denial = GateDenial::from_apply_blocker_detail(
            correlation_id,
            owner,
            gate_check_source_for_apply_blocker(detail.kind),
            detail,
        )
        .context("failed to deliver structured merge blocker to the integration controller")?;
        gate_denials.push(denial);
    }
    Ok(gate_denials)
}

fn gate_check_source_for_apply_blocker(blocker: ApplyBlocker) -> GateCheckSource {
    match blocker {
        ApplyBlocker::DirtyPrimary | ApplyBlocker::PrimaryStateChanged => {
            GateCheckSource::PrimaryDrift
        }
        ApplyBlocker::StaleBase => GateCheckSource::MergeScope,
        ApplyBlocker::ApplyCheckFailed => GateCheckSource::GitApplyCheck,
        ApplyBlocker::ExcludedReference | ApplyBlocker::UnclaimedEdits => {
            GateCheckSource::MergeScope
        }
        ApplyBlocker::ValidationMissing => GateCheckSource::ValidationBinding,
        ApplyBlocker::ValidationNotRun | ApplyBlocker::ValidationSkipped => {
            GateCheckSource::ValidationState
        }
        ApplyBlocker::ValidationFailed => GateCheckSource::Validation,
    }
}

fn apply_prechecked_merge_with_candidate_validation_locked(
    mut preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
    expected_primary_state: &PrimaryRepositoryState,
    review_context: &MergeReviewRevalidationContext,
    megafile_thresholds: &MegafileThresholds,
    local_git: MergeLocalGitOptions,
) -> Result<MergeApplyReport> {
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        );
    }

    let patch = preview.candidate.raw_diff.clone();
    if patch.is_empty() {
        review_context.recapture_and_verify()?;
        return Ok(MergeApplyReport {
            preview,
            status: MergeApplyReportStatus::NothingToApply,
            applied: false,
            review_bound: true,
            review_binding_status: MergeReviewBindingStatus::Matched,
            gate_denials: Vec::new(),
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
            recorded_collision_paths: Vec::new(),
            accepted_decomposition: None,
            lifecycle: None,
        });
    }

    if preview.safety.apply_check.status != SafetyCheckStatus::Passed {
        bail!("merge apply refused: git apply check did not pass");
    }

    if !candidate_validation_commands.is_empty() {
        let command_labels = candidate_validation_commands
            .iter()
            .map(|command| command.command.clone())
            .collect::<Vec<_>>();
        let reports = run_candidate_validation_commands_with_local_git_options(
            &preview,
            &candidate_validation_commands,
            local_git,
        )?;
        preview.candidate.validation_evidence.push_bound_reports(
            preview.candidate.validation_binding.clone(),
            reports.clone(),
        );
        preview.candidate.validations.extend(reports);
        preview.safety.candidate_validation_commands = command_labels;
        preview.safety.validation_required = true;
        preview.safety.validation = validation_check(&preview.candidate.validations, true);
        preview.safety.validation_evidence = validation_evidence_check(
            &preview.candidate.validation_evidence,
            &preview.candidate.validation_binding,
            true,
            &preview.candidate.changed_paths,
        );
        let checks = SafetyChecks {
            primary_state_unchanged: &preview.safety.primary_state_unchanged,
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validation_evidence: &preview.safety.validation_evidence,
            megafile: &preview.safety.megafile,
            validations: &preview.candidate.validations,
            require_validation: true,
            validation_commands: &preview.safety.candidate_validation_commands,
            validation_related_paths: &preview.candidate.changed_paths,
        };
        preview.safety.readiness = classify_apply_safety(checks, &preview.safety.force_options);
    } else if require_validation_after_candidate {
        preview.safety.validation_required = true;
        preview.safety.validation = validation_check(&preview.candidate.validations, true);
        preview.safety.validation_evidence = validation_evidence_check(
            &preview.candidate.validation_evidence,
            &preview.candidate.validation_binding,
            true,
            &preview.candidate.changed_paths,
        );
        let checks = SafetyChecks {
            primary_state_unchanged: &preview.safety.primary_state_unchanged,
            dirty_primary: &preview.safety.dirty_primary,
            stale_base: &preview.safety.stale_base,
            apply_check: &preview.safety.apply_check,
            unclaimed_edits: &preview.safety.unclaimed_edits,
            validation: &preview.safety.validation,
            validation_evidence: &preview.safety.validation_evidence,
            megafile: &preview.safety.megafile,
            validations: &preview.candidate.validations,
            require_validation: true,
            validation_commands: &preview.safety.candidate_validation_commands,
            validation_related_paths: &preview.candidate.changed_paths,
        };
        preview.safety.readiness = classify_apply_safety(checks, &preview.safety.force_options);
    }

    refresh_apply_safety(&mut preview, expected_primary_state)?;
    // The implicit preview above is only a comparison observation. Rebuild it
    // after candidate validation and target refresh so the reviewed authority
    // is checked again immediately before telemetry or primary mutation.
    review_context.recapture_and_verify()?;
    let recorded_collision_paths = record_merge_collision_decision(&preview, megafile_thresholds)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        let mut report = blocked_merge_apply_report(preview)?;
        report.recorded_collision_paths = recorded_collision_paths;
        return Ok(report);
    }

    let args = match preview.safety.apply_mode {
        ApplyMode::Direct => vec!["apply", "--binary"],
        ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
        ApplyMode::None => Vec::new(),
    };
    if args.is_empty() {
        return Ok(MergeApplyReport {
            preview,
            status: MergeApplyReportStatus::NothingToApply,
            applied: false,
            review_bound: true,
            review_binding_status: MergeReviewBindingStatus::Matched,
            gate_denials: Vec::new(),
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
            recorded_collision_paths,
            accepted_decomposition: None,
            lifecycle: None,
        });
    }

    let output = run_git_with_input_with_writable_worktree(
        &preview.candidate.metadata.primary_repo_root,
        &args,
        &patch,
    )
    .context("failed to run git apply")?;
    if !output.success {
        bail!(
            "git apply failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(MergeApplyReport {
        preview,
        status: MergeApplyReportStatus::Applied,
        applied: true,
        review_bound: true,
        review_binding_status: MergeReviewBindingStatus::Matched,
        gate_denials: Vec::new(),
        stdout: summarize_text(
            &String::from_utf8_lossy(&output.stdout),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        stderr: summarize_text(
            &String::from_utf8_lossy(&output.stderr),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        error: None,
        recorded_collision_paths,
        accepted_decomposition: None,
        lifecycle: None,
    })
}

pub fn validation_reports_from_json(value: &Value) -> Result<Vec<ValidationReport>> {
    validation_evidence_from_json(value).map(|evidence| evidence.reports())
}

pub fn validation_reports_from_json_for_agent(
    value: &Value,
    agent_id: Option<&str>,
) -> Result<Vec<ValidationReport>> {
    validation_evidence_from_json_for_agent(value, agent_id).map(|evidence| evidence.reports())
}

pub fn validation_evidence_from_json(value: &Value) -> Result<ValidationEvidenceBundle> {
    validation_evidence_from_json_for_agent(value, None)
}

pub fn validation_evidence_from_json_for_agent(
    value: &Value,
    agent_id: Option<&str>,
) -> Result<ValidationEvidenceBundle> {
    if let Some(agents) = value.get("agents").and_then(Value::as_array) {
        let mut evidence = ValidationEvidenceBundle::default();
        let mut matched_agent = false;
        for agent in agents {
            let candidate_id = agent.get("id").and_then(Value::as_str);
            if agent_id.is_some() && candidate_id != agent_id {
                continue;
            }
            matched_agent = true;
            evidence.extend(validation_evidence_from_agent_json(agent).with_context(|| {
                match candidate_id {
                    Some(id) => format!("invalid validation reports for agent '{id}'"),
                    None => "invalid validation reports for summary agent".to_string(),
                }
            })?);
        }
        if agent_id.is_some() && !matched_agent {
            let id = agent_id.unwrap_or_default();
            bail!("validation report summary does not contain agent '{id}'");
        }
        return Ok(evidence);
    }

    validation_evidence_group_from_json(value)
}

fn validation_evidence_group_from_json(value: &Value) -> Result<ValidationEvidenceBundle> {
    let report_values = if let Some(validations) = value.get("validation").and_then(Value::as_array)
    {
        validations
    } else if let Some(validations) = value.get("validations").and_then(Value::as_array) {
        validations
    } else if let Some(reports) = value.get("reports").and_then(Value::as_array) {
        reports
    } else if let Some(array) = value.as_array() {
        array
    } else if value.as_object().is_some() {
        let binding = validation_binding_from_json(value)?;
        return Ok(ValidationEvidenceBundle {
            groups: vec![ValidationEvidenceGroup {
                binding,
                reports: vec![validation_report_from_json(value)?],
            }],
        });
    } else {
        bail!("validation report JSON must be an object or array");
    };

    let mut reports = report_values
        .iter()
        .map(validation_report_from_json)
        .collect::<Result<Vec<_>>>()?;
    sort_validation_reports(&mut reports);
    if reports.is_empty() {
        return Ok(ValidationEvidenceBundle::default());
    }
    Ok(ValidationEvidenceBundle {
        groups: vec![ValidationEvidenceGroup {
            binding: validation_binding_from_json(value)?,
            reports,
        }],
    })
}

fn validation_evidence_from_agent_json(agent: &Value) -> Result<ValidationEvidenceBundle> {
    if agent.get("validation").is_some()
        || agent.get("validations").is_some()
        || agent.get("reports").is_some()
    {
        validation_evidence_from_json(agent)
    } else {
        Ok(ValidationEvidenceBundle::default())
    }
}

fn capture_consistent_candidate_snapshot(
    primary_repo: &Repository,
    agent_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
    local_git: MergeLocalGitOptions,
) -> Result<CandidateRepositorySnapshot> {
    capture_two_matching(|| {
        capture_candidate_snapshot_once(
            primary_repo,
            agent_repo,
            record,
            primary_repo_root.clone(),
            local_git,
        )
    })
}

fn capture_two_matching<T, F>(mut capture: F) -> Result<T>
where
    T: PartialEq,
    F: FnMut() -> Result<Option<T>>,
{
    for _ in 0..CANDIDATE_CAPTURE_ATTEMPTS {
        let Some(first) = capture()? else {
            continue;
        };
        let Some(second) = capture()? else {
            continue;
        };
        if first == second {
            return Ok(second);
        }
    }
    bail!(
        "candidate repository state changed while it was being captured; retry after concurrent agent worktree activity stops"
    )
}

fn capture_candidate_snapshot_once(
    primary_repo: &Repository,
    agent_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
    local_git: MergeLocalGitOptions,
) -> Result<Option<CandidateRepositorySnapshot>> {
    let before = capture_candidate_boundary(primary_repo, agent_repo)?;
    let metadata = metadata_from_heads(
        primary_repo,
        record,
        primary_repo_root,
        before.primary_head,
        before.agent_head,
    )?;
    let base_oid = collection_base_oid(&metadata)?;
    let mut captured = snapshot_worktree_candidate_from_base_with_local_git_options(
        agent_repo,
        &record.path,
        before.agent_head,
        base_oid,
        local_git,
    )?;
    preserve_untracked_change_kinds(&before.worktree_status, &mut captured.changes)?;
    let after = capture_candidate_boundary(primary_repo, agent_repo)?;
    if before != after {
        return Ok(None);
    }

    Ok(Some(CandidateRepositorySnapshot {
        metadata,
        index_digest: after.index_digest,
        worktree_status: after.worktree_status,
        snapshot_tree: captured.oid,
        changes: captured.changes,
        raw_diff: captured.raw_diff,
    }))
}

fn preserve_untracked_change_kinds(porcelain_v2: &[u8], changes: &mut [ChangedPath]) -> Result<()> {
    let untracked = porcelain_v2
        .split(|byte| *byte == 0)
        .filter_map(|record| record.strip_prefix(b"? "))
        .map(path_buf_from_git_bytes)
        .collect::<Result<BTreeSet<_>>>()?;
    for change in changes {
        if change.kind == ChangeKind::Added && untracked.contains(&change.path) {
            change.kind = ChangeKind::Untracked;
        }
    }
    Ok(())
}

fn capture_candidate_boundary(
    primary_repo: &Repository,
    agent_repo: &Repository,
) -> Result<CandidateBoundaryState> {
    let primary_head = head_oid(primary_repo).context("failed to read primary HEAD")?;
    let agent_head = head_oid(agent_repo).context("failed to read agent HEAD")?;
    let index_digest = hash_optional_file(&agent_repo.path().join("index"))?;
    let worktree_status =
        capture_repository_status(agent_repo).context("failed to capture agent worktree status")?;
    Ok(CandidateBoundaryState {
        primary_head,
        agent_head,
        index_digest,
        worktree_status,
    })
}

fn capture_repository_status(repo: &Repository) -> Result<Vec<u8>> {
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true)
        .include_unmodified(false);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect repository status")?;
    if statuses.len() > VALIDATION_RAW_MAX_ENTRIES {
        return Err(CandidateCaptureQuotaError::EntryCountExceeded {
            limit: VALIDATION_RAW_MAX_ENTRIES,
        }
        .into());
    }
    let mut records = BTreeMap::<Vec<u8>, u32>::new();
    for entry in statuses.iter() {
        records.insert(entry.path_bytes().to_vec(), entry.status().bits());
    }
    let mut output = Vec::new();
    for (path, status) in records {
        if Status::from_bits_retain(status) == Status::WT_NEW {
            output.extend_from_slice(b"? ");
        } else {
            write!(&mut output, "{status:08x} ").context("failed to encode status bits")?;
        }
        output.extend_from_slice(&path);
        output.push(0);
    }
    Ok(output)
}

fn metadata_from_heads(
    primary_repo: &Repository,
    record: &WorktreeRecord,
    primary_repo_root: PathBuf,
    primary_head: Option<Oid>,
    agent_head: Option<Oid>,
) -> Result<WorktreeMergeMetadata> {
    let merge_base = match (primary_head, agent_head) {
        (Some(primary), Some(agent)) => merge_base_oid(primary_repo, primary, agent)?,
        _ => None,
    };
    let base_matches_primary = match (primary_head, merge_base) {
        (Some(primary), Some(base)) => Some(primary == base),
        _ => None,
    };

    Ok(WorktreeMergeMetadata {
        agent_id: record.name.clone(),
        worktree_path: record.path.clone(),
        branch: record.branch.clone(),
        primary_repo_root,
        primary_head: primary_head.map(|oid| oid.to_string()),
        agent_head: agent_head.map(|oid| oid.to_string()),
        merge_base: merge_base.map(|oid| oid.to_string()),
        base_matches_primary,
    })
}

pub(crate) fn candidate_validation_binding(
    metadata: &WorktreeMergeMetadata,
    full_diff: &[u8],
) -> Result<CandidateValidationBinding> {
    let diff_oid = Oid::hash_object(ObjectType::Blob, full_diff)
        .context("failed to hash merge candidate diff")?;
    CandidateValidationBinding {
        version: VALIDATION_BINDING_VERSION,
        agent_id: metadata.agent_id.clone(),
        primary_head: metadata.primary_head.clone(),
        agent_head: metadata.agent_head.clone(),
        merge_base: metadata.merge_base.clone(),
        diff_oid: diff_oid.to_string(),
    }
    .canonicalized()
}

fn canonical_optional_oid(value: Option<String>, field: &str) -> Result<Option<String>> {
    value.map(|value| canonical_oid(&value, field)).transpose()
}

fn canonical_oid(value: &str, field: &str) -> Result<String> {
    let oid = Oid::from_str(value)
        .with_context(|| format!("validation binding {field} must be a Git object id"))?;
    let canonical = oid.to_string();
    if canonical != value {
        bail!("validation binding {field} must use its canonical 40-character lowercase form");
    }
    Ok(canonical)
}

fn collection_base_oid(metadata: &WorktreeMergeMetadata) -> Result<Option<Oid>> {
    metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref())
        .map(|oid| Oid::from_str(oid).context("failed to parse collection base oid"))
        .transpose()
}

fn collect_changed_paths(repo: &Repository) -> Result<Vec<ChangedPath>> {
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect git status")?;
    let mut changes = BTreeMap::<PathBuf, ChangeKind>::new();

    for entry in statuses.iter() {
        let path = path_buf_from_git_bytes(entry.path_bytes())?;
        changes.insert(path, classify_status(entry.status()));
    }

    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn enforce_candidate_capture_quota(repo: &Repository, worktree_path: &Path) -> Result<()> {
    let changes = collect_changed_paths(repo)?;
    if changes.len() > VALIDATION_RAW_MAX_ENTRIES {
        return Err(CandidateCaptureQuotaError::EntryCountExceeded {
            limit: VALIDATION_RAW_MAX_ENTRIES,
        }
        .into());
    }
    let mut total_bytes = 0_u64;
    for change in changes {
        let absolute = worktree_path.join(&change.path);
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect candidate path {}", absolute.display())
                })
            }
        };
        let bytes = if metadata.file_type().is_file() {
            metadata.len()
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&absolute).with_context(|| {
                format!("failed to read candidate symlink {}", absolute.display())
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                target.as_os_str().as_bytes().len() as u64
            }
            #[cfg(not(unix))]
            {
                target.to_string_lossy().len() as u64
            }
        } else {
            0
        };
        if bytes > VALIDATION_RAW_MAX_SINGLE_FILE_BYTES {
            return Err(CandidateCaptureQuotaError::SingleFileTooLarge {
                path: change.path,
                limit: VALIDATION_RAW_MAX_SINGLE_FILE_BYTES,
            }
            .into());
        }
        total_bytes = total_bytes.checked_add(bytes).ok_or_else(|| {
            CandidateCaptureQuotaError::TotalContentTooLarge {
                path: change.path.clone(),
                limit: VALIDATION_RAW_MAX_TOTAL_BYTES,
            }
        })?;
        if total_bytes > VALIDATION_RAW_MAX_TOTAL_BYTES {
            return Err(CandidateCaptureQuotaError::TotalContentTooLarge {
                path: change.path,
                limit: VALIDATION_RAW_MAX_TOTAL_BYTES,
            }
            .into());
        }
    }
    Ok(())
}

fn snapshot_worktree_candidate(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
) -> Result<CapturedWorktreeTree> {
    snapshot_worktree_candidate_from_base(repo, worktree_path, head, head)
}

fn snapshot_worktree_candidate_with_local_git_options(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
    local_git: MergeLocalGitOptions,
) -> Result<CapturedWorktreeTree> {
    snapshot_worktree_candidate_from_base_with_local_git_options(
        repo,
        worktree_path,
        head,
        head,
        local_git,
    )
}

pub(crate) fn capture_worktree_diff_from_commit(
    repo: &Repository,
    worktree_path: &Path,
    base: Oid,
) -> Result<(Vec<PathBuf>, Vec<u8>)> {
    let captured =
        snapshot_worktree_candidate_from_base(repo, worktree_path, Some(base), Some(base))?;
    Ok((
        captured
            .changes
            .into_iter()
            .map(|change| change.path)
            .collect(),
        captured.raw_diff,
    ))
}

fn snapshot_worktree_candidate_from_base(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
    base_commit: Option<Oid>,
) -> Result<CapturedWorktreeTree> {
    snapshot_worktree_candidate_from_base_with_local_git_options(
        repo,
        worktree_path,
        head,
        base_commit,
        MergeLocalGitOptions::default(),
    )
}

fn snapshot_worktree_candidate_from_base_with_local_git_options(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
    base_commit: Option<Oid>,
    local_git: MergeLocalGitOptions,
) -> Result<CapturedWorktreeTree> {
    let index = TemporaryIndex::create(repo.commondir())?;
    snapshot_worktree_candidate_from_base_with_index_and_local_git_options(
        repo,
        worktree_path,
        head,
        base_commit,
        &index,
        local_git,
    )
}

fn snapshot_worktree_candidate_from_base_with_index_and_local_git_options(
    repo: &Repository,
    worktree_path: &Path,
    head: Option<Oid>,
    base_commit: Option<Oid>,
    index: &TemporaryIndex,
    local_git: MergeLocalGitOptions,
) -> Result<CapturedWorktreeTree> {
    enforce_candidate_capture_quota(repo, worktree_path)?;
    let head_text = head.map(|oid| oid.to_string());
    let read_tree_args = match head_text.as_deref() {
        Some(oid) => vec!["read-tree", oid],
        None => vec!["read-tree", "--empty"],
    };
    let output = run_isolated_git_process(
        index,
        worktree_path,
        &read_tree_args,
        StdinMode::Null,
        "initialize candidate snapshot index",
    )?;
    require_git_success(output, "initialize candidate snapshot index")?;

    let output = run_isolated_git_process(
        index,
        worktree_path,
        &["add", "--all", "--", "."],
        StdinMode::Null,
        "populate candidate snapshot index",
    )?;
    require_git_success(output, "populate candidate snapshot index")?;

    let output = run_isolated_git_process(
        index,
        worktree_path,
        &["write-tree"],
        StdinMode::Null,
        "write candidate snapshot tree",
    )?;
    if !output.success {
        bail!(
            "failed to write candidate snapshot tree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let oid =
        String::from_utf8(output.stdout).context("candidate snapshot tree id was not UTF-8")?;
    let oid = Oid::from_str(oid.trim()).context("candidate snapshot tree id was invalid")?;
    let base_tree = temporary_base_tree_oid(repo, worktree_path, base_commit, index)?;
    let changes = collect_snapshot_changes(worktree_path, base_tree, oid, index)?;
    let entries = collect_candidate_snapshot_entries(index, oid, &changes)?;
    let raw_diff = collect_snapshot_diff(worktree_path, base_tree, oid, index, local_git)?;
    Ok(CapturedWorktreeTree {
        oid,
        entries,
        changes,
        raw_diff,
    })
}

include!("merge/part2.rs");
include!("merge/part3.rs");

#[cfg(test)]
mod tests;
