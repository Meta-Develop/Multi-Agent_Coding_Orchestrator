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
    external_agent::{run_external_agent, ExternalAgentCommand},
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
        NeutralWorktreeCreateOptions, WorktreeManager, WorktreeRecord,
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
const LOCAL_GIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeApplyOptions {
    pub preview: MergePreviewOptions,
    pub candidate_validation_commands: Vec<CandidateValidationCommand>,
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
pub struct ArbitrationSideEvidence {
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
pub struct ArbitrationInput {
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
pub struct PreparedMergeArbitration {
    pub input: ArbitrationInput,
    pub input_json: Vec<u8>,
    pub input_sha256: String,
    pub primary_repo_root: PathBuf,
    pub primary_state_sha256: String,
    pub source_diffs: [Vec<u8>; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationProposalDisposition {
    Proposed,
    Rejected,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArbitrationProposal {
    pub version: u32,
    pub input_sha256: String,
    pub disposition: ArbitrationProposalDisposition,
    pub rationale: String,
    pub candidate_patch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArbitrationRunnerExecution {
    pub kind: String,
    pub trusted_local_boundary: bool,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbitrationRunnerResult {
    pub proposal: ArbitrationProposal,
    pub execution: ArbitrationRunnerExecution,
}

#[derive(Debug, Clone)]
pub struct ArbitrationRunnerRequest {
    pub input_sha256: String,
    pub prompt_path: PathBuf,
    pub output_schema_path: PathBuf,
    pub output_last_message_path: PathBuf,
    pub json_log_path: PathBuf,
    pub neutral_worktree_path: PathBuf,
    pub hidden_primary_root: PathBuf,
    pub run_id: String,
    pub arbiter_id: String,
}

pub trait ArbitrationRunner {
    fn run(&self, request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult>;
}

#[derive(Debug, Clone)]
pub struct ExternalArbitrationRunner {
    pub codex_bin: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct StaticArbitrationRunner {
    output: Vec<u8>,
}

impl StaticArbitrationRunner {
    pub fn from_bytes(output: impl Into<Vec<u8>>) -> Result<Self> {
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
    pub runner: ArbitrationRunnerExecution,
    pub reason: String,
}

pub trait ArbitrationEnvironment {
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
pub struct ProductionArbitrationEnvironment;

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
        );
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

pub fn parse_arbitration_proposal(bytes: &[u8]) -> Result<ArbitrationProposal> {
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

pub fn arbitrate_merge(options: MergeArbitrationOptions) -> Result<MergeArbitrationReport> {
    let runner = ExternalArbitrationRunner {
        codex_bin: options.codex_bin.clone(),
        timeout: options.timeout,
    };
    arbitrate_merge_with_runner(options, &runner)
}

pub fn arbitrate_merge_with_runner(
    options: MergeArbitrationOptions,
    runner: &dyn ArbitrationRunner,
) -> Result<MergeArbitrationReport> {
    arbitrate_merge_with_environment(options, runner, &ProductionArbitrationEnvironment)
}

pub fn arbitrate_merge_with_environment(
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
        input_sha256: prepared.input_sha256.clone(),
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
        let primary_repo = Repository::open(&repo_root).with_context(|| {
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
            let output = run_git_with_input(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyBlocker {
    DirtyPrimary,
    StaleBase,
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
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub recorded_collision_paths: Vec<PathBuf>,
    pub accepted_decomposition: Option<MegafileAssessment>,
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
struct PrimaryRepositoryState {
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

fn collect_agent_result_with_evidence_after_lease<F>(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
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
    )
}

fn collect_agent_result_from_verified_record(
    options: MergeCollectOptions,
    validation_evidence: ValidationEvidenceBundle,
    repo_root: PathBuf,
    record: &WorktreeRecord,
) -> Result<MergeCandidate> {
    let primary_repo = Repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let agent_repo = Repository::open(&record.path)
        .with_context(|| format!("failed to open agent worktree {}", record.path.display()))?;

    let claimed_paths = normalize_claim_paths(options.claimed_paths)?;
    let snapshot =
        capture_consistent_candidate_snapshot(&primary_repo, &agent_repo, record, repo_root)?;
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
    let mut collect = options.collect;
    collect.include_full_diff = true;
    let candidate = collect_agent_result_with_evidence(collect, validation_evidence)?;
    let mut preview =
        build_merge_apply_preview(candidate, options.forces, options.require_validation)?;
    assess_megafile_policy(&mut preview, &megafile_policy)?;
    Ok(preview)
}

/// Builds a merge preview without attempting to acquire a nested shared
/// worktree lease when the caller already holds verified write authority.
pub(crate) fn preview_merge_apply_with_evidence_and_write_lease(
    options: MergePreviewOptions,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<MergeApplyPreview> {
    let mut collect = options.collect;
    collect.include_full_diff = true;
    let candidate = collect_agent_result_with_evidence_and_write_lease(
        collect,
        validation_evidence,
        write_lease,
    )?;
    let mut preview =
        build_merge_apply_preview(candidate, options.forces, options.require_validation)?;
    assess_megafile_policy(&mut preview, &MegafileMergePolicy::default())?;
    Ok(preview)
}

pub(crate) fn build_merge_apply_preview(
    candidate: MergeCandidate,
    forces: MergeForceOptions,
    require_validation: bool,
) -> Result<MergeApplyPreview> {
    let patch = candidate.raw_diff.as_slice();
    let candidate_validation_commands = Vec::new();

    let primary_state_unchanged = passed_safety_check();
    let dirty_primary = dirty_primary_check(&candidate.metadata.primary_repo_root)?;
    let stale_base = stale_base_check(&candidate.metadata);
    let unclaimed_edits = unclaimed_edits_check(&candidate.unclaimed_changed_paths);
    let validation = validation_check(&candidate.validations, require_validation);
    let validation_evidence = validation_evidence_check(
        &candidate.validation_evidence,
        &candidate.validation_binding,
        require_validation,
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
        require_validation,
        validation_commands: &candidate_validation_commands,
        validation_related_paths: &candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &forces);

    Ok(MergeApplyPreview {
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
            validation_required: require_validation,
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
            verify_decomposition_candidate_structure(&preview.candidate, &evidence)?;
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

    let repo = Repository::open(&candidate.metadata.primary_repo_root).with_context(|| {
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
    let snapshot_entries = recapture_candidate_snapshot_entries(candidate)?;
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

fn recapture_candidate_snapshot_entries(
    candidate: &MergeCandidate,
) -> Result<BTreeMap<PathBuf, CandidateSnapshotEntry>> {
    let agent_repo = Repository::open(&candidate.metadata.worktree_path).with_context(|| {
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
    let captured = capture_two_matching(|| {
        snapshot_worktree_candidate_from_base(
            &agent_repo,
            &candidate.metadata.worktree_path,
            agent_head,
            base,
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

pub fn apply_merge_result(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.preview.collect.validations.clone());
    apply_merge_result_with_evidence(options, evidence)
}

pub fn apply_merge_result_with_evidence(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    let report = merge_apply_report_with_evidence(options, validation_evidence)?;
    if report.status == MergeApplyReportStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&report.preview.safety.readiness.blockers)
        );
    }

    Ok(report)
}

pub fn merge_apply_report(options: MergeApplyOptions) -> Result<MergeApplyReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.preview.collect.validations.clone());
    merge_apply_report_with_evidence(options, evidence)
}

pub fn merge_apply_report_with_evidence(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyReport> {
    merge_apply_report_with_megafile_policy(
        options,
        validation_evidence,
        MegafileMergePolicy::default(),
    )
}

pub fn merge_apply_report_with_megafile_policy(
    options: MergeApplyOptions,
    validation_evidence: ValidationEvidenceBundle,
    megafile_policy: MegafileMergePolicy,
) -> Result<MergeApplyReport> {
    let repo_root = discover_primary_repo_root(&options.preview.collect.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "merge-apply")?;
    let mut preview_options = options.preview;
    let require_validation_after_candidate = preview_options.require_validation;
    if !options.candidate_validation_commands.is_empty() {
        preview_options.require_validation = false;
    }
    let preview = preview_merge_apply_with_megafile_policy(
        preview_options,
        validation_evidence,
        megafile_policy.clone(),
    )?;
    let recorded_collision_paths =
        record_merge_collision_decision(&preview, &megafile_policy.thresholds)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        let mut report = blocked_merge_apply_report(preview);
        report.recorded_collision_paths = recorded_collision_paths;
        return Ok(report);
    }
    let expected_primary_state = PrimaryRepositoryState::capture(&repo_root)?;

    let mut report = apply_prechecked_merge_with_candidate_validation_locked(
        preview,
        options.candidate_validation_commands,
        require_validation_after_candidate,
        &expected_primary_state,
    )?;
    report.recorded_collision_paths = recorded_collision_paths;
    if report.recorded_collision_paths.is_empty() {
        report.recorded_collision_paths =
            record_merge_collision_decision(&report.preview, &megafile_policy.thresholds)?;
    }
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

pub fn blocked_merge_apply_report(preview: MergeApplyPreview) -> MergeApplyReport {
    let error = if preview.safety.readiness.blockers.is_empty() {
        None
    } else {
        Some(format!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        ))
    };

    MergeApplyReport {
        preview,
        status: MergeApplyReportStatus::Blocked,
        applied: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error,
        recorded_collision_paths: Vec::new(),
        accepted_decomposition: None,
    }
}

pub fn apply_prechecked_merge(preview: MergeApplyPreview) -> Result<MergeApplyReport> {
    apply_prechecked_merge_with_candidate_validation(preview, Vec::new(), false)
}

pub fn apply_prechecked_merge_with_candidate_validation(
    preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
) -> Result<MergeApplyReport> {
    let repo_root = preview.candidate.metadata.primary_repo_root.clone();
    let _lock = RepoCommonLock::acquire(&repo_root, "merge-apply")?;
    let expected_primary_state = PrimaryRepositoryState::capture(&repo_root)?;
    apply_prechecked_merge_with_candidate_validation_locked(
        preview,
        candidate_validation_commands,
        require_validation_after_candidate,
        &expected_primary_state,
    )
}

fn apply_prechecked_merge_with_candidate_validation_locked(
    mut preview: MergeApplyPreview,
    candidate_validation_commands: Vec<CandidateValidationCommand>,
    require_validation_after_candidate: bool,
    expected_primary_state: &PrimaryRepositoryState,
) -> Result<MergeApplyReport> {
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        bail!(
            "merge apply refused: {}",
            format_blockers(&preview.safety.readiness.blockers)
        );
    }

    let patch = preview.candidate.raw_diff.clone();
    if patch.is_empty() {
        return Ok(MergeApplyReport {
            preview,
            status: MergeApplyReportStatus::NothingToApply,
            applied: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
            recorded_collision_paths: Vec::new(),
            accepted_decomposition: None,
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
        let reports = run_candidate_validation_commands(&preview, &candidate_validation_commands)?;
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
        if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
            return Ok(blocked_merge_apply_report(preview));
        }
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
        if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
            return Ok(blocked_merge_apply_report(preview));
        }
    }

    refresh_apply_safety(&mut preview, expected_primary_state)?;
    if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        return Ok(blocked_merge_apply_report(preview));
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
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
            recorded_collision_paths: Vec::new(),
            accepted_decomposition: None,
        });
    }

    let output = run_git_with_input(&preview.candidate.metadata.primary_repo_root, &args, &patch)
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
        stdout: summarize_text(
            &String::from_utf8_lossy(&output.stdout),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        stderr: summarize_text(
            &String::from_utf8_lossy(&output.stderr),
            DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        ),
        error: None,
        recorded_collision_paths: Vec::new(),
        accepted_decomposition: None,
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
) -> Result<CandidateRepositorySnapshot> {
    capture_two_matching(|| {
        capture_candidate_snapshot_once(primary_repo, agent_repo, record, primary_repo_root.clone())
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
    let mut captured = snapshot_worktree_candidate_from_base(
        agent_repo,
        &record.path,
        before.agent_head,
        base_oid,
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
    enforce_candidate_capture_quota(repo, worktree_path)?;
    let index = TemporaryIndex::create(repo.commondir())?;
    let head_text = head.map(|oid| oid.to_string());
    let read_tree_args = match head_text.as_deref() {
        Some(oid) => vec!["read-tree", oid],
        None => vec!["read-tree", "--empty"],
    };
    let output = run_isolated_git_process(
        &index,
        worktree_path,
        &read_tree_args,
        StdinMode::Null,
        "initialize candidate snapshot index",
    )?;
    require_git_success(output, "initialize candidate snapshot index")?;

    let output = run_isolated_git_process(
        &index,
        worktree_path,
        &["add", "--all", "--", "."],
        StdinMode::Null,
        "populate candidate snapshot index",
    )?;
    require_git_success(output, "populate candidate snapshot index")?;

    let output = run_isolated_git_process(
        &index,
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
    let base_tree = temporary_base_tree_oid(repo, worktree_path, base_commit, &index)?;
    let changes = collect_snapshot_changes(worktree_path, base_tree, oid, &index)?;
    let entries = collect_candidate_snapshot_entries(&index, oid, &changes)?;
    let raw_diff = collect_snapshot_diff(worktree_path, base_tree, oid, &index)?;
    Ok(CapturedWorktreeTree {
        oid,
        entries,
        changes,
        raw_diff,
    })
}

fn collect_candidate_snapshot_entries(
    index: &TemporaryIndex,
    snapshot_tree: Oid,
    changes: &[ChangedPath],
) -> Result<BTreeMap<PathBuf, CandidateSnapshotEntry>> {
    let snapshot_repo = Repository::open_bare(&index.directory)
        .context("failed to open private candidate snapshot object database")?;
    let tree = snapshot_repo
        .find_tree(snapshot_tree)
        .context("failed to read private candidate snapshot tree")?;
    let mut entries = BTreeMap::new();
    for change in changes {
        let entry = match tree.get_path(&change.path) {
            Ok(entry) => entry,
            Err(error) if error.code() == ErrorCode::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect candidate snapshot path '{}'",
                        change.path.display()
                    )
                })
            }
        };
        let snapshot_entry = if entry.kind() == Some(ObjectType::Blob)
            && matches!(entry.filemode(), 0o100644 | 0o100755)
        {
            let blob = snapshot_repo.find_blob(entry.id()).with_context(|| {
                format!(
                    "failed to read candidate snapshot blob '{}'",
                    change.path.display()
                )
            })?;
            CandidateSnapshotEntry::RegularFile { bytes: blob.size() }
        } else {
            CandidateSnapshotEntry::Other {
                filemode: entry.filemode(),
            }
        };
        entries.insert(change.path.clone(), snapshot_entry);
    }
    Ok(entries)
}

fn temporary_base_tree_oid(
    repo: &Repository,
    worktree_path: &Path,
    base_commit: Option<Oid>,
    index: &TemporaryIndex,
) -> Result<Oid> {
    if let Some(commit) = base_commit {
        let tree_id = repo
            .find_commit(commit)
            .with_context(|| format!("failed to find base commit {commit}"))?
            .tree_id();
        return Ok(tree_id);
    }

    let output = run_isolated_git_process(
        index,
        worktree_path,
        &["mktree"],
        StdinMode::Null,
        "create empty base tree",
    )?;
    if !output.success {
        bail!(
            "failed to create empty base tree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let oid = String::from_utf8(output.stdout).context("empty tree id was not UTF-8")?;
    Oid::from_str(oid.trim()).context("empty tree id was invalid")
}

fn collect_snapshot_changes(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<ChangedPath>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let output = run_isolated_git_process(
        index,
        worktree_path,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            &base,
            &snapshot,
            "--",
        ],
        StdinMode::Null,
        "collect candidate snapshot paths",
    )?;
    if !output.success {
        bail!(
            "failed to collect candidate snapshot paths: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_name_status_z(&output.stdout)
}

fn parse_name_status_z(bytes: &[u8]) -> Result<Vec<ChangedPath>> {
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut changes = BTreeMap::new();
    while let Some(status) = fields.next() {
        let path = fields
            .next()
            .context("git diff --name-status returned a status without a path")?;
        let kind = match status.first().copied() {
            Some(b'A') => ChangeKind::Added,
            Some(b'M') => ChangeKind::Modified,
            Some(b'D') => ChangeKind::Deleted,
            Some(b'T') => ChangeKind::Typechange,
            Some(b'U') => ChangeKind::Conflicted,
            Some(_) => ChangeKind::Unknown,
            None => bail!("git diff --name-status returned an empty status"),
        };
        changes.insert(path_buf_from_git_bytes(path)?, kind);
    }
    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn collect_snapshot_diff(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<u8>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let output = run_isolated_git_process(
        index,
        worktree_path,
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            &base,
            &snapshot,
            "--",
        ],
        StdinMode::Null,
        "collect candidate snapshot diff",
    )?;
    if !output.success {
        bail!(
            "failed to collect candidate snapshot diff: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

impl TemporaryIndex {
    fn create(common_dir: &Path) -> Result<Self> {
        let runtime_directory =
            PrivateRuntimeDirectory::create(common_dir, PrivateRuntimeKind::CandidateCapture)?;
        let directory = runtime_directory.path().to_path_buf();
        Self::initialize_existing(&directory, common_dir, Some(runtime_directory))
            .map_err(anyhow::Error::from)
            .context("failed to initialize candidate capture directory")
    }

    fn create_in_managed(
        runtime_directory: &PrivateRuntimeDirectory,
        common_dir: &Path,
    ) -> std::io::Result<Self> {
        let directory = runtime_directory.path().join(".git");
        Self::initialize_existing(&directory, common_dir, None)
    }

    fn initialize_existing(
        directory: &Path,
        common_dir: &Path,
        runtime_directory: Option<PrivateRuntimeDirectory>,
    ) -> std::io::Result<Self> {
        let alternate_object_directory = fs::canonicalize(common_dir.join("objects"))?;
        let result = (|| -> Result<()> {
            let object_directory = directory.join("objects");
            let refs_heads = directory.join("refs/heads");
            let refs_tags = directory.join("refs/tags");
            create_private_directory(&object_directory)?;
            create_private_directory(&directory.join("refs"))?;
            create_private_directory(&refs_heads)?;
            create_private_directory(&refs_tags)?;
            write_git_alternates_file(&object_directory, &alternate_object_directory)?;
            write_private_file(&directory.join("HEAD"), b"ref: refs/heads/maco-isolated\n")?;
            let hooks = directory.join("disabled-hooks");
            create_private_directory(&hooks)?;
            let config_path = directory.join("config");
            write_private_file(&config_path, b"")?;
            let mut config =
                git2::Config::open(&config_path).context("failed to open isolated Git config")?;
            config
                .set_i32("core.repositoryformatversion", 0)
                .context("failed to set isolated repository version")?;
            config
                .set_bool("core.bare", false)
                .context("failed to set isolated repository worktree mode")?;
            config
                .set_bool("core.logallrefupdates", false)
                .context("failed to disable isolated reflogs")?;
            config
                .set_bool("core.fsmonitor", false)
                .context("failed to disable isolated fsmonitor")?;
            config
                .set_bool("core.untrackedcache", false)
                .context("failed to disable isolated untracked cache")?;
            config
                .set_str(
                    "core.hookspath",
                    hooks
                        .to_str()
                        .context("isolated hooks path was not UTF-8")?,
                )
                .context("failed to disable isolated hooks")?;
            config
                .set_str("protocol.ext.allow", "never")
                .context("failed to disable external Git transports")?;
            drop(config);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Self {
                directory: directory.to_path_buf(),
                alternate_object_directory,
                _runtime_directory: runtime_directory,
            }),
            Err(error) => Err(std::io::Error::other(error.to_string())),
        }
    }

    fn command_args(&self, worktree_path: &Path, operation: &[&str]) -> Vec<OsString> {
        self.command_args_os(
            worktree_path,
            operation.iter().map(OsString::from).collect(),
        )
    }

    fn command_args_os(&self, worktree_path: &Path, operation: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--git-dir"),
            self.directory.as_os_str().to_os_string(),
            OsString::from("--work-tree"),
            worktree_path.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("core.fsmonitor=false"),
            OsString::from("-c"),
            OsString::from("core.untrackedCache=false"),
            OsString::from("-c"),
            OsString::from("protocol.ext.allow=never"),
        ];
        args.extend(operation);
        args
    }

    fn set_detached_head(&self, oid: Oid) -> Result<()> {
        fs::write(self.directory.join("HEAD"), format!("{oid}\n"))
            .context("failed to set isolated detached HEAD")
    }
}

impl PrivateRuntimeDirectory {
    pub(crate) fn create(repo_root: &Path, kind: PrivateRuntimeKind) -> Result<Self> {
        let runtime_root = trusted_runtime_root(repo_root)?;
        Self::create_in_root(&runtime_root, kind)
    }

    #[cfg(unix)]
    fn create_in_root(runtime_root: &Path, kind: PrivateRuntimeKind) -> Result<Self> {
        validate_private_runtime_root(runtime_root)?;
        let _runtime_lock = PrivateRuntimeRootLock::acquire(runtime_root)?;
        let current_boot_id = private_runtime_boot_id()?;
        scavenge_private_runtime_orphans_locked_with(
            runtime_root,
            current_boot_id.as_deref(),
            process_start_identity,
        )?;
        let pid = std::process::id();
        let process_start = private_runtime_current_process_start_identity()?;
        let boot_id = current_boot_id;
        let created_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch while reserving private runtime")?
            .as_secs();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch while naming private runtime")?
            .as_nanos();
        for attempt in 0..32_u32 {
            let nonce = format!("{nanos}-{attempt}");
            let path = runtime_root.join(format!("{}{pid}-{nonce}", kind.prefix()));
            match reserve_owner_only_directory(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to reserve private runtime {}", path.display())
                    })
                }
            }
            let owner = PrivateRuntimeOwner {
                version: PRIVATE_RUNTIME_OWNER_VERSION,
                pid,
                process_start: process_start.clone(),
                boot_id: boot_id.clone(),
                created_unix_seconds,
                kind,
                nonce,
            };
            let directory_metadata = validate_private_runtime_directory(&path)?;
            if let Err(error) = write_private_runtime_owner(&path, &owner) {
                let _ = remove_private_runtime_directory_by_identity(
                    runtime_root,
                    &path,
                    &directory_metadata,
                );
                return Err(error);
            }
            return Ok(Self {
                runtime_root: runtime_root.to_path_buf(),
                path,
                owner,
                directory_metadata,
                closed: false,
            });
        }
        bail!("failed to reserve a unique private runtime directory")
    }

    #[cfg(not(unix))]
    fn create_in_root(_runtime_root: &Path, _kind: PrivateRuntimeKind) -> Result<Self> {
        bail!(
            "safe handle-relative private runtime cleanup is unavailable on this platform; refusing temporary context creation"
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify_identity(&self) -> Result<()> {
        if self.closed {
            bail!("managed private runtime was already closed");
        }
        let directory_metadata = validate_private_runtime_directory(&self.path)?;
        if !same_filesystem_identity(&self.directory_metadata, &directory_metadata) {
            bail!(
                "managed private runtime {} changed identity while in use",
                self.path.display()
            );
        }
        let (owner, _) = read_private_runtime_owner(&self.path, self.owner.kind)?;
        if owner != self.owner {
            bail!(
                "managed private runtime {} owner record changed while in use",
                self.path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.verify_identity()?;
        let _runtime_lock = PrivateRuntimeRootLock::acquire(&self.runtime_root)?;
        remove_owned_private_runtime_directory(
            &self.runtime_root,
            &self.path,
            &self.owner,
            &self.directory_metadata,
        )?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for PrivateRuntimeDirectory {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let Ok(_runtime_lock) = PrivateRuntimeRootLock::acquire(&self.runtime_root) else {
            return;
        };
        let _ = remove_owned_private_runtime_directory(
            &self.runtime_root,
            &self.path,
            &self.owner,
            &self.directory_metadata,
        );
    }
}

impl PrivateRuntimeRootLock {
    fn acquire(runtime_root: &Path) -> Result<Self> {
        validate_private_runtime_root(runtime_root)?;
        let path = runtime_root.join(PRIVATE_RUNTIME_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open private runtime lock {}", path.display()))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    bail!(
                        "timed out acquiring private runtime lock {}; refusing concurrent cleanup",
                        path.display()
                    );
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("failed to acquire private runtime lock {}", path.display())
                    });
                }
            }
        }
        let path_metadata = fs::symlink_metadata(&path).with_context(|| {
            format!("failed to inspect private runtime lock {}", path.display())
        })?;
        let file_metadata = file.metadata().with_context(|| {
            format!(
                "failed to inspect open private runtime lock {}",
                path.display()
            )
        })?;
        if path_metadata.file_type().is_symlink()
            || metadata_is_windows_reparse_point(&path_metadata)
            || !path_metadata.file_type().is_file()
            || !same_filesystem_identity(&path_metadata, &file_metadata)
        {
            bail!(
                "private runtime lock {} changed while it was opened",
                path.display()
            );
        }
        validate_private_runtime_owner_file_metadata(&path, &path_metadata)?;
        validate_private_runtime_owner_file_metadata(&path, &file_metadata)?;
        Ok(Self { file })
    }
}

impl Drop for PrivateRuntimeRootLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn reserve_owner_only_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn write_private_runtime_owner(directory: &Path, owner: &PrivateRuntimeOwner) -> Result<()> {
    let owner_path = owner.kind.owner_path(directory);
    let owner_parent = owner_path
        .parent()
        .context("private runtime owner path omitted parent")?;
    if owner.kind == PrivateRuntimeKind::CandidateValidation {
        create_private_directory(owner_parent)?;
    }
    let mut bytes =
        serde_json::to_vec(owner).context("failed to serialize private runtime owner")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!("private runtime owner record exceeded its size limit");
    }
    let temporary = owner_parent.join(format!(".{PRIVATE_RUNTIME_OWNER_FILE}.{}.tmp", owner.nonce));
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, &owner_path).with_context(|| {
        format!(
            "failed to publish private runtime owner {}",
            owner_path.display()
        )
    })?;
    sync_managed_directory(owner_parent)?;
    if owner_parent != directory {
        sync_managed_directory(directory)?;
    }
    Ok(())
}

#[cfg(test)]
fn scavenge_private_runtime_orphans(runtime_root: &Path) -> Result<PrivateRuntimeScavengeReport> {
    let boot_id = private_runtime_boot_id()?;
    scavenge_private_runtime_orphans_with(runtime_root, boot_id.as_deref(), |pid| {
        process_start_identity(pid)
    })
}

#[cfg(test)]
fn scavenge_private_runtime_orphans_with(
    runtime_root: &Path,
    current_boot_id: Option<&str>,
    process_identity: impl FnMut(u32) -> Result<Option<ProcessStartIdentity>>,
) -> Result<PrivateRuntimeScavengeReport> {
    validate_private_runtime_root(runtime_root)?;
    let _runtime_lock = PrivateRuntimeRootLock::acquire(runtime_root)?;
    scavenge_private_runtime_orphans_locked_with(runtime_root, current_boot_id, process_identity)
}

fn scavenge_private_runtime_orphans_locked_with(
    runtime_root: &Path,
    current_boot_id: Option<&str>,
    mut process_identity: impl FnMut(u32) -> Result<Option<ProcessStartIdentity>>,
) -> Result<PrivateRuntimeScavengeReport> {
    let mut managed = Vec::new();
    for entry in fs::read_dir(runtime_root)
        .with_context(|| format!("failed to scan private runtime {}", runtime_root.display()))?
    {
        let entry = entry.context("failed to read private runtime entry")?;
        let Some(kind) = private_runtime_kind_for_name(&entry.file_name())? else {
            continue;
        };
        managed.push((entry.path(), kind));
        if managed.len() > PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES {
            bail!(
                "private runtime contains more than {} managed directories; refusing unbounded scavenging",
                PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES
            );
        }
    }
    managed.sort_by(|left, right| left.0.cmp(&right.0));

    let mut report = PrivateRuntimeScavengeReport {
        removed: 0,
        retained: 0,
    };
    for (path, expected_kind) in managed {
        let outcome = (|| -> Result<bool> {
            let directory_metadata = validate_private_runtime_directory(&path)?;
            let owner_path = expected_kind.owner_path(&path);
            match fs::symlink_metadata(&owner_path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    validate_incomplete_private_runtime_name(&path, expected_kind)?;
                    remove_private_runtime_directory_by_identity(
                        runtime_root,
                        &path,
                        &directory_metadata,
                    )?;
                    return Ok(true);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect private runtime owner {}",
                            owner_path.display()
                        )
                    })
                }
            }
            let (owner, owner_metadata) = read_private_runtime_owner(&path, expected_kind)?;
            validate_private_runtime_owner(&path, &owner, expected_kind, current_boot_id)?;

            let owner_is_live = if private_runtime_owner_boot_matches(&owner, current_boot_id)? {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    match process_identity(owner.pid).with_context(|| {
                        format!(
                            "failed to verify owner process {} for private runtime {}",
                            owner.pid,
                            path.display()
                        )
                    })? {
                        Some(identity) => owner.process_start.as_ref() == Some(&identity),
                        None => false,
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    if owner.pid == std::process::id() {
                        true
                    } else {
                        bail!(
                            "cannot safely reclaim private runtime {} without process start identity support",
                            path.display()
                        );
                    }
                }
            } else {
                false
            };
            if owner_is_live {
                return Ok(false);
            }

            let current_directory_metadata = validate_private_runtime_directory(&path)?;
            if !same_filesystem_identity(&directory_metadata, &current_directory_metadata) {
                bail!(
                    "private runtime directory {} changed while it was being reclaimed",
                    path.display()
                );
            }
            let (current_owner, current_owner_metadata) =
                read_private_runtime_owner(&path, expected_kind)?;
            if current_owner != owner
                || !same_filesystem_identity(&owner_metadata, &current_owner_metadata)
            {
                bail!(
                    "private runtime owner {} changed while it was being reclaimed",
                    expected_kind.owner_path(&path).display()
                );
            }
            remove_owned_private_runtime_directory(
                runtime_root,
                &path,
                &owner,
                &directory_metadata,
            )?;
            Ok(true)
        })();
        match outcome {
            Ok(true) => report.removed += 1,
            Ok(false) => {}
            Err(error) => {
                report.retained += 1;
                tracing::warn!(
                    kind = ?expected_kind,
                    error = %error,
                    "retained unsafe or unverifiable private runtime entry"
                );
            }
        }
    }
    if report.removed > 0 {
        sync_managed_directory(runtime_root)?;
    }
    if report.retained > 0 {
        tracing::warn!(
            removed = report.removed,
            retained = report.retained,
            "private runtime scavenger completed with retained entries"
        );
    }
    Ok(report)
}

fn validate_incomplete_private_runtime_name(path: &Path, kind: PrivateRuntimeKind) -> Result<()> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("incomplete private runtime name was not UTF-8")?;
    let remainder = name
        .strip_prefix(kind.prefix())
        .context("incomplete private runtime kind prefix changed")?;
    let (pid, nonce) = remainder
        .split_once('-')
        .context("incomplete private runtime name omitted owner identity")?;
    let pid = pid
        .parse::<u32>()
        .context("incomplete private runtime PID was invalid")?;
    let mut nonce_fields = nonce.split('-');
    let nanos = nonce_fields.next().unwrap_or_default();
    let attempt = nonce_fields.next().unwrap_or_default();
    if pid == 0
        || nanos.is_empty()
        || attempt.is_empty()
        || nonce_fields.next().is_some()
        || !nanos.bytes().all(|byte| byte.is_ascii_digit())
        || !attempt.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!(
            "incomplete private runtime {} has an invalid reservation name; refusing reclamation",
            path.display()
        );
    }
    Ok(())
}

fn private_runtime_kind_for_name(name: &OsStr) -> Result<Option<PrivateRuntimeKind>> {
    let kinds = [
        PrivateRuntimeKind::CandidateCapture,
        PrivateRuntimeKind::CandidateValidation,
        PrivateRuntimeKind::PublicationGit,
        PrivateRuntimeKind::GhConfig,
    ];
    let Some(name) = name.to_str() else {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            return Ok(kinds
                .iter()
                .copied()
                .find(|kind| name.as_bytes().starts_with(kind.prefix().as_bytes())));
        }
        #[cfg(not(unix))]
        return Ok(None);
    };
    Ok(kinds
        .into_iter()
        .find(|kind| name.starts_with(kind.prefix())))
}

fn validate_private_runtime_root(runtime_root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(runtime_root).with_context(|| {
        format!(
            "failed to inspect private runtime root {}",
            runtime_root.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "private runtime root {} is not a real directory",
            runtime_root.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "private runtime root {} is not owner-only",
                runtime_root.display()
            );
        }
    }
    Ok(())
}

fn validate_private_runtime_directory(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "managed private runtime {} is not a real directory; refusing reclamation",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "managed private runtime {} has a foreign owner or unsafe mode; refusing reclamation",
                path.display()
            );
        }
    }
    Ok(metadata)
}

fn read_private_runtime_owner(
    directory: &Path,
    kind: PrivateRuntimeKind,
) -> Result<(PrivateRuntimeOwner, fs::Metadata)> {
    let path = kind.owner_path(directory);
    let path_metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("private runtime owner {} is missing", path.display()))?;
    if path_metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&path_metadata)
        || !path_metadata.file_type().is_file()
    {
        bail!(
            "private runtime owner {} is not a regular file; refusing reclamation",
            path.display()
        );
    }
    validate_private_runtime_owner_file_metadata(&path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open private runtime owner {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect private runtime owner {}", path.display()))?;
    validate_private_runtime_owner_file_metadata(&path, &file_metadata)?;
    if !same_filesystem_identity(&path_metadata, &file_metadata) {
        bail!(
            "private runtime owner {} changed while it was opened",
            path.display()
        );
    }
    if file_metadata.len() == 0 || file_metadata.len() > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!(
            "private runtime owner {} has an invalid size",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(PRIVATE_RUNTIME_OWNER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read private runtime owner {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!(
            "private runtime owner {} changed size while read",
            path.display()
        );
    }
    let owner = serde_json::from_slice(&bytes)
        .with_context(|| format!("private runtime owner {} is malformed", path.display()))?;
    Ok((owner, file_metadata))
}

fn validate_private_runtime_owner_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "private runtime owner {} has a foreign owner, unsafe mode, or multiple links",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "private runtime owner {} has multiple links",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_private_runtime_owner(
    directory: &Path,
    owner: &PrivateRuntimeOwner,
    expected_kind: PrivateRuntimeKind,
    current_boot_id: Option<&str>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch while validating private runtime")?
        .as_secs();
    let expected_name = format!("{}{}-{}", owner.kind.prefix(), owner.pid, owner.nonce);
    if owner.version != PRIVATE_RUNTIME_OWNER_VERSION
        || owner.pid == 0
        || owner.kind != expected_kind
        || owner.nonce.is_empty()
        || owner.nonce.len() > 96
        || !owner
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        || owner.created_unix_seconds == 0
        || owner.created_unix_seconds > now.saturating_add(300)
        || !valid_process_start_identity(owner.process_start.as_ref())
        || directory.file_name().and_then(OsStr::to_str) != Some(expected_name.as_str())
    {
        bail!(
            "private runtime owner for {} is invalid; refusing reclamation",
            directory.display()
        );
    }
    private_runtime_owner_boot_matches(owner, current_boot_id)?;
    Ok(())
}

fn private_runtime_owner_boot_matches(
    owner: &PrivateRuntimeOwner,
    current_boot_id: Option<&str>,
) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let recorded = owner
            .boot_id
            .as_deref()
            .context("Linux private runtime owner omitted boot identity")?;
        let current = current_boot_id.context("current Linux boot identity is unavailable")?;
        validate_linux_boot_id(recorded)?;
        validate_linux_boot_id(current)?;
        Ok(recorded == current)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if owner.boot_id.is_some() || current_boot_id.is_some() {
            bail!("private runtime owner contained an unsupported boot identity");
        }
        Ok(true)
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_boot_id(value: &str) -> Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        bail!("Linux boot identity was invalid");
    }
    Ok(())
}

fn remove_owned_private_runtime_directory(
    runtime_root: &Path,
    path: &Path,
    expected_owner: &PrivateRuntimeOwner,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    let expected_kind = expected_owner.kind;
    let current_directory_metadata = validate_private_runtime_directory(path)?;
    if !same_filesystem_identity(expected_directory_metadata, &current_directory_metadata) {
        bail!(
            "private runtime directory {} changed before cleanup",
            path.display()
        );
    }
    let (current_owner, _) = read_private_runtime_owner(path, expected_kind)?;
    if &current_owner != expected_owner {
        bail!(
            "private runtime owner {} changed before cleanup",
            expected_kind.owner_path(path).display()
        );
    }
    remove_private_runtime_directory_by_identity(runtime_root, path, expected_directory_metadata)
}

fn remove_private_runtime_directory_by_identity(
    runtime_root: &Path,
    path: &Path,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    let parent = path
        .parent()
        .context("private runtime directory omitted parent")?;
    if parent != runtime_root {
        bail!(
            "private runtime {} is not a direct child of {}",
            path.display(),
            runtime_root.display()
        );
    }
    validate_private_runtime_root(runtime_root)?;
    #[cfg(unix)]
    {
        remove_private_runtime_directory_unix(runtime_root, path, expected_directory_metadata)?;
    }
    #[cfg(not(unix))]
    {
        let _ = expected_directory_metadata;
        bail!(
            "safe handle-relative private runtime cleanup is unavailable on this platform; preserving {}",
            path.display()
        );
    }
    sync_managed_directory(runtime_root)?;
    Ok(())
}

#[cfg(unix)]
fn remove_private_runtime_directory_unix(
    runtime_root: &Path,
    path: &Path,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    };

    let mut root_options = OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let root_file = root_options.open(runtime_root).with_context(|| {
        format!(
            "failed to open private runtime root {} for cleanup",
            runtime_root.display()
        )
    })?;
    let name = path
        .file_name()
        .context("private runtime directory omitted name")?;
    let name = std::ffi::CString::new(name.as_bytes())
        .context("private runtime directory name contained NUL")?;
    let raw = unsafe {
        libc::openat(
            root_file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open private runtime {}", path.display()));
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let directory = unsafe { fs::File::from_raw_fd(raw) };
    let opened_metadata = directory.metadata().with_context(|| {
        format!(
            "failed to inspect opened private runtime {}",
            path.display()
        )
    })?;
    if opened_metadata.dev() != expected_directory_metadata.dev()
        || opened_metadata.ino() != expected_directory_metadata.ino()
    {
        bail!(
            "private runtime directory {} changed while it was opened for cleanup",
            path.display()
        );
    }

    let mut validation_entries = 1_usize;
    validate_private_runtime_contents_unix(
        directory.as_raw_fd(),
        opened_metadata.dev() as libc::dev_t,
        &mut validation_entries,
        PRIVATE_RUNTIME_REMOVAL_MAX_ENTRIES,
        PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH,
        0,
    )?;
    let mut entries = 1_usize;
    remove_private_runtime_contents_unix(
        directory.as_raw_fd(),
        opened_metadata.dev() as libc::dev_t,
        &mut entries,
        0,
    )?;

    let current = fstatat_unix(root_file.as_raw_fd(), &name)?;
    if current.st_dev != opened_metadata.dev() as libc::dev_t
        || current.st_ino != opened_metadata.ino() as libc::ino_t
        || (current.st_mode & libc::S_IFMT) != libc::S_IFDIR
    {
        bail!(
            "private runtime directory {} changed before final unlink",
            path.display()
        );
    }
    let result =
        unsafe { libc::unlinkat(root_file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to unlink private runtime {}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_runtime_contents_unix(
    directory_fd: i32,
    root_device: libc::dev_t,
    entries: &mut usize,
    max_entries: usize,
    max_depth: usize,
    depth: usize,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let remaining = max_entries.saturating_sub(*entries);
    let names = read_directory_names_unix(directory_fd, remaining)?;
    for name in names {
        *entries += 1;
        let name = std::ffi::CString::new(name.as_bytes())
            .context("private runtime entry name contained NUL")?;
        let before = fstatat_unix(directory_fd, &name)?;
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if before.st_uid != uid || before.st_dev != root_device {
            bail!("private runtime entry has a foreign owner or filesystem; refusing cleanup");
        }
        if (before.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            if depth >= max_depth {
                bail!("private runtime exceeded the {max_depth}-level cleanup depth limit");
            }
            let raw = unsafe {
                libc::openat(
                    directory_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open private runtime child during bounded validation");
            }
            // SAFETY: openat returned a new owned descriptor on success.
            let child = unsafe { fs::File::from_raw_fd(raw) };
            let opened = fstat_unix(child.as_raw_fd())?;
            if opened.st_dev != root_device
                || opened.st_dev != before.st_dev
                || opened.st_ino != before.st_ino
            {
                bail!("private runtime child changed during bounded validation");
            }
            validate_private_runtime_contents_unix(
                child.as_raw_fd(),
                root_device,
                entries,
                max_entries,
                max_depth,
                depth + 1,
            )?;
            let current = fstatat_unix(directory_fd, &name)?;
            if current.st_dev != opened.st_dev || current.st_ino != opened.st_ino {
                bail!("private runtime child changed during bounded validation");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn remove_private_runtime_contents_unix(
    directory_fd: i32,
    root_device: libc::dev_t,
    entries: &mut usize,
    depth: usize,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let remaining = PRIVATE_RUNTIME_REMOVAL_MAX_ENTRIES.saturating_sub(*entries);
    let names = read_directory_names_unix(directory_fd, remaining)?;
    for name in names {
        *entries += 1;
        let name = std::ffi::CString::new(name.as_bytes())
            .context("private runtime entry name contained NUL")?;
        let before = fstatat_unix(directory_fd, &name)?;
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if before.st_uid != uid || before.st_dev != root_device {
            bail!("private runtime entry has a foreign owner or filesystem; refusing cleanup");
        }
        if (before.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            if depth >= PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH {
                bail!(
                    "private runtime exceeded the {}-level cleanup depth limit",
                    PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH
                );
            }
            let raw = unsafe {
                libc::openat(
                    directory_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open private runtime child directory");
            }
            // SAFETY: openat returned a new owned descriptor on success.
            let child = unsafe { fs::File::from_raw_fd(raw) };
            let opened = fstat_unix(child.as_raw_fd())?;
            if opened.st_dev != root_device
                || opened.st_dev != before.st_dev
                || opened.st_ino != before.st_ino
            {
                bail!("private runtime child changed while it was opened");
            }
            remove_private_runtime_contents_unix(
                child.as_raw_fd(),
                root_device,
                entries,
                depth + 1,
            )?;
            let current = fstatat_unix(directory_fd, &name)?;
            if current.st_dev != opened.st_dev
                || current.st_ino != opened.st_ino
                || (current.st_mode & libc::S_IFMT) != libc::S_IFDIR
            {
                bail!("private runtime child changed before directory unlink");
            }
            let result = unsafe { libc::unlinkat(directory_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to unlink private runtime child directory");
            }
        } else {
            let result = unsafe { libc::unlinkat(directory_fd, name.as_ptr(), 0) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to unlink private runtime child entry");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
struct UnixDirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for UnixDirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir returned this stream and closedir consumes it once.
        let _ = unsafe { libc::closedir(self.0) };
    }
}

#[cfg(unix)]
fn read_directory_names_unix(directory_fd: i32, max_names: usize) -> Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStringExt;

    let current = c".";
    // SAFETY: openat creates a new file description with an independent
    // directory-stream offset while remaining anchored to directory_fd.
    let duplicate = unsafe {
        libc::openat(
            directory_fd,
            current.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to reopen private runtime directory descriptor");
    }
    // SAFETY: fdopendir takes ownership of duplicate on success.
    let raw_stream = unsafe { libc::fdopendir(duplicate) };
    if raw_stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: fdopendir did not take ownership on failure.
        let _ = unsafe { libc::close(duplicate) };
        return Err(error).context("failed to open private runtime directory stream");
    }
    let stream = UnixDirectoryStream(raw_stream);
    let mut names = Vec::new();
    loop {
        set_unix_errno(0);
        // SAFETY: stream remains valid for the duration of this loop.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_unix_errno();
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno))
                    .context("failed to enumerate private runtime directory");
            }
            break;
        }
        // SAFETY: readdir returns a dirent whose d_name is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if names.len() >= max_names {
            bail!("private runtime exceeded the bounded directory-entry limit");
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    names.sort();
    Ok(names)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_unix_errno(value: i32) {
    // SAFETY: errno is thread-local writable process state.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_unix_errno() -> i32 {
    // SAFETY: errno is thread-local readable process state.
    unsafe { *libc::__errno_location() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn set_unix_errno(value: i32) {
    // SAFETY: errno is thread-local writable process state.
    unsafe { *libc::__error() = value };
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn get_unix_errno() -> i32 {
    // SAFETY: errno is thread-local readable process state.
    unsafe { *libc::__error() }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn set_unix_errno(_value: i32) {}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn get_unix_errno() -> i32 {
    0
}

#[cfg(unix)]
fn fstatat_unix(directory_fd: i32, name: &std::ffi::CStr) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect private runtime entry");
    }
    // SAFETY: fstatat initialized metadata when it returned success.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn fstat_unix(fd: i32) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(fd, metadata.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect opened private runtime entry");
    }
    // SAFETY: fstat initialized metadata when it returned success.
    Ok(unsafe { metadata.assume_init() })
}

fn same_filesystem_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (left, right);
        false
    }
}

fn private_runtime_current_process_start_identity() -> Result<Option<ProcessStartIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        process_start_identity(std::process::id())?
            .context("current process identity disappeared while reserving private runtime")
            .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn private_runtime_boot_id() -> Result<Option<String>> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("failed to read Linux boot identity")?;
    let value = value.trim().to_ascii_lowercase();
    validate_linux_boot_id(&value)?;
    Ok(Some(value))
}

#[cfg(not(target_os = "linux"))]
fn private_runtime_boot_id() -> Result<Option<String>> {
    Ok(None)
}

pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create private file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write private file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist private file {}", path.display()))
}

pub(crate) fn write_git_alternates_file(object_directory: &Path, alternate: &Path) -> Result<()> {
    let alternate = fs::canonicalize(alternate).with_context(|| {
        format!(
            "failed to resolve Git object alternate {}",
            alternate.display()
        )
    })?;
    let info = object_directory.join("info");
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&info)
        .with_context(|| format!("failed to create Git object info dir {}", info.display()))?;
    let path = info.join("alternates");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("failed to create Git alternates file {}", path.display()))?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        alternate.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = alternate.to_string_lossy().as_bytes().to_vec();
    if bytes.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        bail!("Git object alternate path contains an unsupported control byte");
    }
    file.write_all(&bytes)
        .context("failed to write Git object alternate")?;
    file.write_all(b"\n")
        .context("failed to terminate Git object alternate")?;
    file.sync_all()
        .context("failed to persist Git object alternate")
}

fn require_git_success(output: GitCommandOutput, label: &str) -> Result<()> {
    if !output.success {
        bail!(
            "failed to {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn hash_optional_file(path: &Path) -> Result<Option<Oid>> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    validate_repository_index_metadata(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {}", path.display()))?;
    validate_repository_index_metadata(path, &file_metadata)?;
    if !same_filesystem_identity(&path_metadata, &file_metadata) {
        bail!(
            "repository index {} changed while it was opened",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(REPOSITORY_INDEX_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > REPOSITORY_INDEX_MAX_BYTES || bytes.len() as u64 != file_metadata.len()
    {
        bail!(
            "repository index {} changed size while read",
            path.display()
        );
    }
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck {}", path.display()))?;
    validate_repository_index_metadata(path, &after)?;
    if !same_filesystem_identity(&file_metadata, &after) || after.len() != file_metadata.len() {
        bail!(
            "repository index {} changed after it was read",
            path.display()
        );
    }
    Oid::hash_object(ObjectType::Blob, &bytes)
        .context("failed to hash repository state file")
        .map(Some)
}

fn validate_repository_index_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > REPOSITORY_INDEX_MAX_BYTES
    {
        bail!(
            "repository index {} is not a bounded real regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!(
                "repository index {} has a foreign owner, multiple links, or unsafe write mode",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!("repository index {} has multiple links", path.display());
        }
    }
    Ok(())
}

fn passed_safety_check() -> SafetyCheck {
    SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    }
}

fn validation_evidence_check(
    evidence: &ValidationEvidenceBundle,
    expected: &CandidateValidationBinding,
    require_validation: bool,
    changed_paths: &[PathBuf],
) -> ValidationEvidenceCheck {
    if !require_validation {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NotRequired,
            message: Some("candidate-bound validation evidence was not required".to_string()),
            paths: Vec::new(),
        };
    }

    let passing_groups = evidence
        .groups
        .iter()
        .filter(|group| {
            group
                .reports
                .iter()
                .any(|report| report.status == ValidationStatus::Passed)
        })
        .collect::<Vec<_>>();
    if passing_groups.is_empty() {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NoPassedReport,
            message: Some("no passed validation report was available to bind".to_string()),
            paths: Vec::new(),
        };
    }
    if passing_groups
        .iter()
        .any(|group| group.binding.as_ref() == Some(expected))
    {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Passed,
            binding_status: ValidationBindingStatus::Bound,
            message: None,
            paths: Vec::new(),
        };
    }
    if passing_groups.iter().any(|group| group.binding.is_some()) {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Failed,
            binding_status: ValidationBindingStatus::Mismatched,
            message: Some(
                "passed validation evidence is bound to a different candidate; rerun validation for the current candidate.validation_binding"
                    .to_string(),
            ),
            paths: changed_paths.to_vec(),
        };
    }

    ValidationEvidenceCheck {
        status: SafetyCheckStatus::Failed,
        binding_status: ValidationBindingStatus::Unbound,
        message: Some(
            "passed validation evidence uses the legacy unbound format; include the current candidate.validation_binding in the validation report envelope"
                .to_string(),
        ),
        paths: changed_paths.to_vec(),
    }
}

fn dirty_primary_check(repo_root: &Path) -> Result<SafetyCheck> {
    let repo = Repository::open(repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let paths = collect_changed_paths(&repo)?
        .into_iter()
        .map(|change| change.path)
        .filter(|path| !is_local_runtime_path(path))
        .collect::<Vec<_>>();

    if paths.is_empty() {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths,
        })
    } else {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("primary worktree has local changes".to_string()),
            paths,
        })
    }
}

fn is_local_runtime_path(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(std::path::Component::Normal(name))
            if name == OsStr::new(".maco") || name == OsStr::new(".maco-cache")
    )
}

fn stale_base_check(metadata: &WorktreeMergeMetadata) -> SafetyCheck {
    match metadata.base_matches_primary {
        Some(true) => SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        },
        Some(false) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent base is stale relative to primary HEAD".to_string()),
            paths: Vec::new(),
        },
        None => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn stale_base_check_for_current_head(
    metadata: &WorktreeMergeMetadata,
    current_head: Option<Oid>,
) -> SafetyCheck {
    let candidate_base = metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref());
    let current_head = current_head.map(|oid| oid.to_string());
    match (candidate_base, current_head.as_deref()) {
        (Some(base), Some(current)) if base == current => passed_safety_check(),
        (None, None) => passed_safety_check(),
        (Some(_), Some(_)) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "candidate base is stale relative to the current primary HEAD".to_string(),
            ),
            paths: Vec::new(),
        },
        _ => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn primary_state_check(
    expected: &PrimaryRepositoryState,
    current: &PrimaryRepositoryState,
) -> SafetyCheck {
    if expected == current {
        return passed_safety_check();
    }
    let mut changed = Vec::new();
    if expected.head != current.head {
        changed.push("HEAD");
    }
    if expected.index_digest != current.index_digest {
        changed.push("index");
    }
    if expected.worktree_digest != current.worktree_digest {
        changed.push("worktree");
    }
    SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: Some(format!(
            "primary repository state changed after the merge safety preview ({})",
            changed.join(", ")
        )),
        paths: Vec::new(),
    }
}

fn refresh_apply_safety(
    preview: &mut MergeApplyPreview,
    expected_primary_state: &PrimaryRepositoryState,
) -> Result<()> {
    let repo_root = &preview.candidate.metadata.primary_repo_root;
    let current_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let dirty_primary = dirty_primary_check(repo_root)?;
    let stale_base =
        stale_base_check_for_current_head(&preview.candidate.metadata, current_primary_state.head);
    let unclaimed_edits = unclaimed_edits_check(&preview.candidate.unclaimed_changed_paths);
    let validation_required = preview.safety.validation_required;
    let validation = validation_check(&preview.candidate.validations, validation_required);
    let validation_evidence = validation_evidence_check(
        &preview.candidate.validation_evidence,
        &preview.candidate.validation_binding,
        validation_required,
        &preview.candidate.changed_paths,
    );
    let patch = preview.candidate.raw_diff.clone();
    let (apply_check, apply_mode) = apply_check(
        repo_root,
        &patch,
        preview.safety.force_options.allow_apply_conflicts,
    )?;
    let semantic_conflicts = classify_semantic_conflicts(&preview.candidate, &apply_check);
    let verified_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let primary_state_unchanged = if current_primary_state == verified_primary_state {
        primary_state_check(expected_primary_state, &verified_primary_state)
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "primary repository state changed while apply-time safety checks were running"
                    .to_string(),
            ),
            paths: Vec::new(),
        }
    };
    let checks = SafetyChecks {
        primary_state_unchanged: &primary_state_unchanged,
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validation_evidence: &validation_evidence,
        megafile: &preview.safety.megafile,
        validations: &preview.candidate.validations,
        require_validation: validation_required,
        validation_commands: &preview.safety.candidate_validation_commands,
        validation_related_paths: &preview.candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &preview.safety.force_options);

    preview.safety.primary_state_unchanged = primary_state_unchanged;
    preview.safety.dirty_primary = dirty_primary;
    preview.safety.stale_base = stale_base;
    preview.safety.apply_check = apply_check;
    preview.safety.unclaimed_edits = unclaimed_edits;
    preview.safety.validation = validation;
    preview.safety.validation_evidence = validation_evidence;
    preview.safety.apply_mode = apply_mode;
    preview.safety.semantic_conflicts = semantic_conflicts;
    preview.safety.readiness = readiness;
    Ok(())
}

fn unclaimed_edits_check(paths: &[PathBuf]) -> SafetyCheck {
    if paths.is_empty() {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent changed paths outside its claims".to_string()),
            paths: paths.to_vec(),
        }
    }
}

fn validation_check(validations: &[ValidationReport], require_validation: bool) -> SafetyCheck {
    let failed = failed_validation_paths(validations);

    if !failed.is_empty() {
        return SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("one or more validation checks failed".to_string()),
            paths: failed,
        };
    }
    if require_validation {
        if validations.is_empty() {
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some("required validation evidence was not supplied".to_string()),
                paths: Vec::new(),
            };
        }
        if validations
            .iter()
            .all(|validation| validation.status != ValidationStatus::Passed)
        {
            let message = if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::NotRun)
            {
                "required validation evidence has not run"
            } else if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::Skipped)
            {
                "required validation evidence was skipped"
            } else {
                "required validation evidence has no passing checks"
            };
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(message.to_string()),
                paths: failed_validation_paths(validations),
            };
        }
    }
    if validations
        .iter()
        .any(|validation| validation.status == ValidationStatus::Passed)
    {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("no passing validation checks were supplied".to_string()),
            paths: Vec::new(),
        }
    }
}

fn failed_validation_paths(validations: &[ValidationReport]) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    let mut failed_without_paths = Vec::new();

    for validation in validations
        .iter()
        .filter(|validation| validation.status == ValidationStatus::Failed)
    {
        if validation.paths.is_empty() {
            failed_without_paths.push(PathBuf::from(&validation.name));
        } else {
            paths.extend(validation.paths.iter().cloned());
        }
    }

    if paths.is_empty() {
        failed_without_paths.sort();
        failed_without_paths.dedup();
        return failed_without_paths;
    }

    paths.into_iter().collect()
}

fn apply_check(
    repo_root: &Path,
    patch: &[u8],
    allow_apply_conflicts: bool,
) -> Result<(SafetyCheck, ApplyMode)> {
    if patch.is_empty() {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Skipped,
                message: Some("candidate has no diff to apply".to_string()),
                paths: Vec::new(),
            },
            ApplyMode::None,
        ));
    }

    let direct = run_git_with_input(repo_root, &["apply", "--check", "--binary"], patch)
        .context("failed to run git apply --check")?;
    let direct_stderr = git_stderr_text(&direct);
    let direct_paths = parse_git_apply_error_paths(&direct_stderr);
    if direct.success {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Passed,
                message: None,
                paths: Vec::new(),
            },
            ApplyMode::Direct,
        ));
    }

    if allow_apply_conflicts {
        let three_way = run_git_with_input(
            repo_root,
            &["apply", "--3way", "--check", "--binary"],
            patch,
        )
        .context("failed to run git apply --3way --check")?;
        let three_way_stderr = git_stderr_text(&three_way);
        let paths = merge_path_sets(
            &direct_paths,
            &parse_git_apply_error_paths(&three_way_stderr),
        );
        if three_way.success {
            return Ok((
                SafetyCheck {
                    status: SafetyCheckStatus::Passed,
                    message: Some(
                        "direct apply check failed; three-way apply check passed".to_string(),
                    ),
                    paths,
                },
                ApplyMode::ThreeWay,
            ));
        }

        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(format!(
                    "direct check failed: {}; three-way check failed: {}",
                    direct_stderr.trim(),
                    three_way_stderr.trim()
                )),
                paths,
            },
            ApplyMode::None,
        ));
    }

    Ok((
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(direct_stderr.trim().to_string()),
            paths: direct_paths,
        },
        ApplyMode::None,
    ))
}

fn run_candidate_validation_commands(
    preview: &MergeApplyPreview,
    commands: &[CandidateValidationCommand],
) -> Result<Vec<ValidationReport>> {
    let mut reports = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        let sandbox = CandidateValidationSandbox::create(preview)?;
        let environment_root = sandbox.validation_environment_root();
        let redactor = validation_diagnostics_redactor(&environment_root);
        let report = run_candidate_validation_command(
            sandbox.path(),
            &environment_root,
            command,
            index,
            &preview.candidate.changed_paths,
        );
        let mut report = sandbox.enforce_candidate_integrity(preview, report);
        if let Some(message) = report.message.as_mut() {
            *message = redact_validation_diagnostic(&redactor, message);
        }
        reports.push(report);
    }
    Ok(reports)
}

struct CandidateValidationSandbox {
    runtime_directory: PrivateRuntimeDirectory,
    git_context: TemporaryIndex,
    baseline_integrity: Option<CandidateValidationSandboxIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateValidationSandboxIntegrity {
    binding: CandidateValidationBinding,
    repository: ValidationRepositoryFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationRepositoryFingerprint {
    head: Option<Oid>,
    index_digest: Option<Oid>,
    status: Vec<u8>,
    snapshot_tree: Oid,
    submodules: Vec<ValidationSubmoduleFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationSubmoduleFingerprint {
    path: PathBuf,
    expected_gitlink: Oid,
    initialized: bool,
    filesystem: ValidationFilesystemFingerprint,
    repository: Option<Box<ValidationRepositoryFingerprint>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemFingerprint {
    exists: bool,
    entries: Vec<ValidationFilesystemEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemEntry {
    path: PathBuf,
    kind: ValidationFilesystemEntryKind,
    mode: u32,
    content_digest: Option<Oid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationFilesystemEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, thiserror::Error)]
enum ValidationFilesystemFingerprintError {
    #[error("validation submodule raw fingerprint exceeded the {limit}-entry limit at {path:?}")]
    EntryCountExceeded { path: PathBuf, limit: usize },
    #[error(
        "validation submodule raw fingerprint file {path:?} exceeded the {limit}-byte single-file limit"
    )]
    SingleFileTooLarge { path: PathBuf, limit: u64 },
    #[error(
        "validation submodule raw fingerprint exceeded the {limit}-byte total-content limit at {path:?}"
    )]
    TotalContentTooLarge { path: PathBuf, limit: u64 },
}

#[derive(Debug, thiserror::Error)]
enum CandidateCaptureQuotaError {
    #[error("candidate capture exceeded the {limit}-entry limit")]
    EntryCountExceeded { limit: usize },
    #[error("candidate file {path:?} exceeded the {limit}-byte single-file limit")]
    SingleFileTooLarge { path: PathBuf, limit: u64 },
    #[error("candidate capture exceeded the {limit}-byte total-content limit at {path:?}")]
    TotalContentTooLarge { path: PathBuf, limit: u64 },
}

struct ValidationFilesystemBudget {
    entries: usize,
    total_bytes: u64,
    max_entries: usize,
    max_total_bytes: u64,
    max_single_file_bytes: u64,
}

impl CandidateValidationSandbox {
    fn create(preview: &MergeApplyPreview) -> Result<Self> {
        let primary_repo_root = preview.candidate.metadata.primary_repo_root.clone();
        let runtime_directory = PrivateRuntimeDirectory::create(
            &primary_repo_root,
            PrivateRuntimeKind::CandidateValidation,
        )?;
        let primary_repo = Repository::open(&primary_repo_root).with_context(|| {
            format!(
                "failed to open primary repository {}",
                primary_repo_root.display()
            )
        })?;
        let base_oid = preview
            .candidate
            .metadata
            .primary_head
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("candidate validation base OID was invalid")?;
        let git_context =
            TemporaryIndex::create_in_managed(&runtime_directory, primary_repo.commondir())
                .map_err(anyhow::Error::from)
                .context("failed to create isolated candidate validation repository")?;
        let mut sandbox = Self {
            runtime_directory,
            git_context,
            baseline_integrity: None,
        };
        initialize_isolated_index(&sandbox.git_context, sandbox.path(), base_oid)?;
        if let Some(base_oid) = base_oid {
            sandbox.git_context.set_detached_head(base_oid)?;
        }
        let checkout = run_isolated_git_process(
            &sandbox.git_context,
            sandbox.path(),
            &["checkout-index", "--all", "--force"],
            StdinMode::Null,
            "materialize candidate validation base",
        )?;
        require_git_success(checkout, "materialize candidate validation base")?;

        let patch = preview.candidate.raw_diff.as_slice();
        let args = match preview.safety.apply_mode {
            ApplyMode::Direct => vec!["apply", "--binary"],
            ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
            ApplyMode::None => Vec::new(),
        };
        if !args.is_empty() {
            let apply_output = run_isolated_git_process(
                &sandbox.git_context,
                sandbox.path(),
                &args,
                StdinMode::Bytes(patch.to_vec()),
                "apply candidate patch to validation repository",
            )
            .context("failed to apply candidate patch to validation worktree")?;
            if !apply_output.success {
                bail!(
                    "failed to apply candidate patch to validation worktree: {}",
                    String::from_utf8_lossy(&apply_output.stderr).trim()
                );
            }
        }

        sandbox.baseline_integrity = Some(sandbox.current_integrity(preview)?);

        Ok(sandbox)
    }

    fn path(&self) -> &Path {
        self.runtime_directory.path()
    }

    fn validation_environment_root(&self) -> PathBuf {
        self.git_context.directory.join("validation-environment")
    }

    fn enforce_candidate_integrity(
        &self,
        preview: &MergeApplyPreview,
        mut report: ValidationReport,
    ) -> ValidationReport {
        let integrity = self.current_integrity(preview);
        match integrity {
            Ok(integrity) if Some(&integrity) == self.baseline_integrity.as_ref() => report,
            Ok(_) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    "validation command mutated tracked or non-ignored candidate state; its result was rejected",
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
            Err(error) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    &format!("failed to verify validation sandbox integrity: {error}"),
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
        }
    }

    fn current_integrity(
        &self,
        preview: &MergeApplyPreview,
    ) -> Result<CandidateValidationSandboxIntegrity> {
        let repo = Repository::open(self.path()).with_context(|| {
            format!(
                "failed to open validation sandbox {}",
                self.path().display()
            )
        })?;
        let base = collection_base_oid(&preview.candidate.metadata)?;
        capture_two_matching(|| {
            let head = head_oid(&repo).context("failed to read validation sandbox HEAD")?;
            let captured = snapshot_worktree_candidate_from_base(&repo, self.path(), head, base)?;
            let binding =
                candidate_validation_binding(&preview.candidate.metadata, &captured.raw_diff)?;
            let repository =
                validation_repository_fingerprint(&repo, self.path(), Some(captured.oid), 0)?;
            Ok(Some(CandidateValidationSandboxIntegrity {
                binding,
                repository,
            }))
        })
    }
}

fn validation_repository_fingerprint(
    repo: &Repository,
    worktree_path: &Path,
    known_snapshot_tree: Option<Oid>,
    depth: usize,
) -> Result<ValidationRepositoryFingerprint> {
    if depth > 32 {
        bail!("validation sandbox submodule nesting exceeded 32 levels");
    }
    let head = head_oid(repo).context("failed to read validation repository HEAD")?;
    let index_digest = hash_optional_file(&repo.path().join("index"))?;
    let status = capture_repository_status(repo)
        .context("failed to capture recursive validation repository status")?;
    let snapshot_tree = match known_snapshot_tree {
        Some(snapshot_tree) => snapshot_tree,
        None => snapshot_worktree_candidate(repo, worktree_path, head)?.oid,
    };

    let mut submodules = Vec::new();
    for (path, expected_gitlink) in validation_gitlinks(worktree_path)? {
        let submodule_path = worktree_path.join(&path);
        let marker = submodule_path.join(".git");
        let marker_present = match fs::symlink_metadata(&marker) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect submodule marker {}", marker.display())
                })
            }
        };
        if !marker_present {
            let filesystem = validation_filesystem_fingerprint(&submodule_path)?;
            submodules.push(ValidationSubmoduleFingerprint {
                path,
                expected_gitlink,
                initialized: false,
                filesystem,
                repository: None,
            });
            continue;
        }
        let filesystem = validation_submodule_marker_fingerprint(&marker)?;
        let submodule_repo = Repository::open(&submodule_path).with_context(|| {
            format!(
                "initialized validation submodule {} could not be opened",
                path_json_text(&path)
            )
        })?;
        let repository =
            validation_repository_fingerprint(&submodule_repo, &submodule_path, None, depth + 1)?;
        submodules.push(ValidationSubmoduleFingerprint {
            path,
            expected_gitlink,
            initialized: true,
            filesystem,
            repository: Some(Box::new(repository)),
        });
    }

    Ok(ValidationRepositoryFingerprint {
        head,
        index_digest,
        status,
        snapshot_tree,
        submodules,
    })
}

fn validation_gitlinks(worktree_path: &Path) -> Result<Vec<(PathBuf, Oid)>> {
    let repo = Repository::open(worktree_path).with_context(|| {
        format!(
            "failed to open validation repository {}",
            worktree_path.display()
        )
    })?;
    let index = repo
        .index()
        .context("failed to read validation repository index")?;
    let mut gitlinks = BTreeMap::new();
    for entry in index.iter() {
        if entry.mode != 0o160000 {
            continue;
        }
        let stage = (entry.flags >> 12) & 0x3;
        if stage != 0 {
            bail!(
                "validation repository contains a conflicted submodule gitlink; refusing incomplete integrity capture"
            );
        }
        let path = normalize_repo_relative_path(path_buf_from_git_bytes(&entry.path)?)?;
        if gitlinks.insert(path.clone(), entry.id).is_some() {
            bail!(
                "validation repository reported duplicate gitlink {}",
                path_json_text(&path)
            );
        }
    }
    Ok(gitlinks.into_iter().collect())
}

fn validation_filesystem_fingerprint(root: &Path) -> Result<ValidationFilesystemFingerprint> {
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationFilesystemFingerprint {
                exists: false,
                entries: Vec::new(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect submodule filesystem {}", root.display())
            })
        }
    }
    let mut entries = Vec::new();
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: VALIDATION_RAW_MAX_ENTRIES,
        max_total_bytes: VALIDATION_RAW_MAX_TOTAL_BYTES,
        max_single_file_bytes: VALIDATION_RAW_MAX_SINGLE_FILE_BYTES,
    };
    collect_validation_filesystem_entries(root, root, &mut entries, &mut budget)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries,
    })
}

fn validation_submodule_marker_fingerprint(
    marker: &Path,
) -> Result<ValidationFilesystemFingerprint> {
    let metadata = fs::symlink_metadata(marker)
        .with_context(|| format!("failed to inspect submodule marker {}", marker.display()))?;
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: 1,
        max_total_bytes: VALIDATION_MARKER_MAX_BYTES,
        max_single_file_bytes: VALIDATION_MARKER_MAX_BYTES,
    };
    let entry = validation_filesystem_entry(marker, PathBuf::from(".git"), &metadata, &mut budget)?;
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries: vec![entry],
    })
}

fn collect_validation_filesystem_entries(
    root: &Path,
    path: &Path,
    entries: &mut Vec<ValidationFilesystemEntry>,
    budget: &mut ValidationFilesystemBudget,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect validation path {}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .context("validation filesystem path escaped submodule root")?
        .to_path_buf();
    let file_type = metadata.file_type();
    entries.push(validation_filesystem_entry(
        path, relative, &metadata, budget,
    )?);

    if file_type.is_dir() {
        let mut children = Vec::new();
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to list validation directory {}", path.display()))?
        {
            let child = entry
                .with_context(|| {
                    format!(
                        "failed to read validation directory entry in {}",
                        path.display()
                    )
                })?
                .path();
            if budget
                .entries
                .saturating_add(children.len())
                .saturating_add(1)
                > budget.max_entries
            {
                return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
                    path: child,
                    limit: budget.max_entries,
                }
                .into());
            }
            children.push(child);
        }
        children.sort();
        for child in children {
            collect_validation_filesystem_entries(root, &child, entries, budget)?;
        }
    }
    Ok(())
}

fn validation_filesystem_entry(
    path: &Path,
    relative: PathBuf,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<ValidationFilesystemEntry> {
    budget.entries = budget.entries.saturating_add(1);
    if budget.entries > budget.max_entries {
        return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
            path: relative,
            limit: budget.max_entries,
        }
        .into());
    }
    let file_type = metadata.file_type();
    let (kind, content_digest) = if file_type.is_dir() {
        (ValidationFilesystemEntryKind::Directory, None)
    } else if file_type.is_file() {
        (
            ValidationFilesystemEntryKind::File,
            Some(validation_file_content_digest(
                path, &relative, metadata, budget,
            )?),
        )
    } else if file_type.is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("failed to read validation symlink {}", path.display()))?;
        let target = raw_path_bytes(&target);
        budget.add_content_bytes(&relative, target.len() as u64)?;
        (
            ValidationFilesystemEntryKind::Symlink,
            Some(
                Oid::hash_object(ObjectType::Blob, &target)
                    .context("failed to hash validation symlink target")?,
            ),
        )
    } else {
        (ValidationFilesystemEntryKind::Other, None)
    };
    Ok(ValidationFilesystemEntry {
        path: relative,
        kind,
        mode: validation_file_mode(metadata),
        content_digest,
    })
}

fn validation_file_content_digest(
    path: &Path,
    relative: &Path,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<Oid> {
    if metadata.len() > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    let remaining_total = budget.max_total_bytes.saturating_sub(budget.total_bytes);
    let read_limit = budget
        .max_single_file_bytes
        .min(remaining_total)
        .saturating_add(1);
    let mut content = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open validation file {}", path.display()))?
        .take(read_limit)
        .read_to_end(&mut content)
        .with_context(|| format!("failed to read validation file {}", path.display()))?;
    let content_len = content.len() as u64;
    if content_len > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    budget.add_content_bytes(relative, content_len)?;
    Oid::hash_object(ObjectType::Blob, &content).context("failed to hash validation file content")
}

impl ValidationFilesystemBudget {
    fn add_content_bytes(&mut self, path: &Path, bytes: u64) -> Result<()> {
        if bytes > self.max_single_file_bytes {
            return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
                path: path.to_path_buf(),
                limit: self.max_single_file_bytes,
            }
            .into());
        }
        let Some(total) = self.total_bytes.checked_add(bytes) else {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        };
        if total > self.max_total_bytes {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        }
        self.total_bytes = total;
        Ok(())
    }
}

fn validation_file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

fn run_candidate_validation_command(
    worktree_path: &Path,
    environment_root: &Path,
    validation: &CandidateValidationCommand,
    index: usize,
    changed_paths: &[PathBuf],
) -> ValidationReport {
    run_candidate_validation_command_with_timeout(
        worktree_path,
        environment_root,
        validation,
        index,
        changed_paths,
        CANDIDATE_VALIDATION_PROCESS_TIMEOUT,
    )
}

fn run_candidate_validation_command_with_timeout(
    worktree_path: &Path,
    environment_root: &Path,
    validation: &CandidateValidationCommand,
    index: usize,
    changed_paths: &[PathBuf],
    timeout: Duration,
) -> ValidationReport {
    let redactor = validation_diagnostics_redactor(environment_root);
    let environment = match validation_command_environment(environment_root) {
        Ok(environment) => environment,
        Err(error) => {
            return failed_candidate_validation_report(
                index,
                changed_paths,
                &redactor,
                format!("failed to prepare validation environment: {error:#}"),
            )
        }
    };
    let output = run_process(
        ProcessSpec::shell(
            "candidate validation command",
            Shell::for_current_platform(),
            &validation.command,
            worktree_path,
            VALIDATION_CAPTURE_LIMIT_BYTES,
        )
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(timeout)),
    );

    match output {
        Ok(output) => {
            let evidence = require_verified_process_output(
                "candidate validation command",
                &output,
                SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            );
            let passed = evidence.is_ok()
                && output.status.is_some_and(|status| status.success())
                && !output.timed_out;
            ValidationReport {
                name: format!("candidate validation {}", index + 1),
                status: if passed {
                    ValidationStatus::Passed
                } else {
                    ValidationStatus::Failed
                },
                message: evidence
                    .err()
                    .map(|error| redact_validation_diagnostic(&redactor, &error.to_string()))
                    .or_else(|| candidate_validation_message(&output, &redactor)),
                paths: if passed {
                    Vec::new()
                } else {
                    changed_paths.to_vec()
                },
            }
        }
        Err(error) => failed_candidate_validation_report(
            index,
            changed_paths,
            &redactor,
            format!("failed to run validation command: {error}"),
        ),
    }
}

fn failed_candidate_validation_report(
    index: usize,
    changed_paths: &[PathBuf],
    redactor: &Redactor,
    message: String,
) -> ValidationReport {
    ValidationReport {
        name: format!("candidate validation {}", index + 1),
        status: ValidationStatus::Failed,
        message: Some(redact_validation_diagnostic(redactor, &message)),
        paths: changed_paths.to_vec(),
    }
}

fn candidate_validation_message(output: &ProcessOutput, redactor: &Redactor) -> Option<String> {
    if output.status.is_some_and(|status| status.success()) {
        return None;
    }
    let stderr = String::from_utf8_lossy(output.stderr.as_bytes());
    let stdout = String::from_utf8_lossy(output.stdout.as_bytes());
    let text = if !stderr.trim().is_empty() {
        stderr.trim()
    } else if !stdout.trim().is_empty() {
        stdout.trim()
    } else {
        "candidate validation command failed"
    };
    let exit = output
        .status
        .and_then(|status| status.code())
        .map(|code| format!("exited with status {code}"))
        .unwrap_or_else(|| "terminated without an exit code".to_string());
    let text = redact_validation_diagnostic(redactor, text);
    Some(format!("{exit}: {}", summarize_text(&text, 1024).text))
}

fn redact_validation_diagnostic(redactor: &Redactor, message: &str) -> String {
    redactor.redact(message).text
}

fn append_validation_message(existing: Option<String>, next: &str) -> Option<String> {
    Some(match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next.to_string(),
    })
}

struct SafetyChecks<'a> {
    primary_state_unchanged: &'a SafetyCheck,
    dirty_primary: &'a SafetyCheck,
    stale_base: &'a SafetyCheck,
    apply_check: &'a SafetyCheck,
    unclaimed_edits: &'a SafetyCheck,
    validation: &'a SafetyCheck,
    validation_evidence: &'a ValidationEvidenceCheck,
    megafile: &'a SafetyCheck,
    validations: &'a [ValidationReport],
    require_validation: bool,
    validation_commands: &'a [String],
    validation_related_paths: &'a [PathBuf],
}

fn classify_apply_safety(checks: SafetyChecks<'_>, forces: &MergeForceOptions) -> ApplyReadiness {
    let candidates = [
        (
            checks.primary_state_unchanged,
            ApplyBlocker::ApplyCheckFailed,
            false,
        ),
        (
            checks.dirty_primary,
            ApplyBlocker::DirtyPrimary,
            forces.allow_dirty_primary,
        ),
        (
            checks.stale_base,
            ApplyBlocker::StaleBase,
            forces.allow_stale_base,
        ),
        (checks.apply_check, ApplyBlocker::ApplyCheckFailed, false),
        (
            checks.unclaimed_edits,
            ApplyBlocker::UnclaimedEdits,
            forces.allow_unclaimed_edits,
        ),
    ];
    let mut blockers = Vec::new();
    let mut forced = Vec::new();
    let mut details = Vec::new();

    for (check, blocker, force_allowed) in candidates {
        if check.status != SafetyCheckStatus::Failed {
            continue;
        }
        let disposition = if force_allowed {
            forced.push(blocker);
            ApplyBlockerDisposition::Forced
        } else {
            blockers.push(blocker);
            ApplyBlockerDisposition::Blocked
        };
        details.push(ApplyBlockerDetail {
            kind: blocker,
            disposition,
            check_status: check.status,
            paths: check.paths.clone(),
            message: check.message.clone(),
            validation_reports: Vec::new(),
            validation_commands: Vec::new(),
            next_safe_operation: None,
        });
    }

    if checks.megafile.status == SafetyCheckStatus::Failed {
        blockers.push(ApplyBlocker::ExcludedReference);
        details.push(ApplyBlockerDetail {
            kind: ApplyBlocker::ExcludedReference,
            disposition: ApplyBlockerDisposition::Blocked,
            check_status: checks.megafile.status,
            paths: checks.megafile.paths.clone(),
            message: checks.megafile.message.clone(),
            validation_reports: checks.validations.to_vec(),
            validation_commands: checks.validation_commands.to_vec(),
            next_safe_operation: Some(
                "run an isolated megafile_decomposition assignment for the exact blocked path through the normal claim, validation, review, and merge gates"
                    .to_string(),
            ),
        });
    }

    if let Some(detail) = validation_evidence_blocker_detail(&checks) {
        blockers.push(detail.kind);
        details.push(detail);
    }

    for detail in validation_blocker_details(&checks, forces) {
        match detail.disposition {
            ApplyBlockerDisposition::Blocked => blockers.push(detail.kind),
            ApplyBlockerDisposition::Forced => forced.push(detail.kind),
        }
        details.push(detail);
    }

    blockers.sort();
    blockers.dedup();
    forced.sort();
    forced.dedup();

    let status = if !blockers.is_empty() {
        ApplyReadinessStatus::Blocked
    } else if !forced.is_empty() {
        ApplyReadinessStatus::Forced
    } else {
        ApplyReadinessStatus::Safe
    };

    ApplyReadiness {
        status,
        blockers,
        forced,
        details,
    }
}

fn validation_evidence_blocker_detail(checks: &SafetyChecks<'_>) -> Option<ApplyBlockerDetail> {
    if checks.validation_evidence.status != SafetyCheckStatus::Failed {
        return None;
    }
    let (kind, next_safe_operation) = match checks.validation_evidence.binding_status {
        ValidationBindingStatus::Unbound => (
            ApplyBlocker::ValidationMissing,
            "regenerate the validation report as an envelope containing the current candidate.validation_binding and its reports",
        ),
        ValidationBindingStatus::Mismatched => (
            ApplyBlocker::ValidationMissing,
            "rerun validation for the current candidate.validation_binding and replace stale evidence",
        ),
        _ => return None,
    };
    Some(ApplyBlockerDetail {
        kind,
        disposition: ApplyBlockerDisposition::Blocked,
        check_status: checks.validation_evidence.status,
        paths: checks.validation_evidence.paths.clone(),
        message: checks.validation_evidence.message.clone(),
        validation_reports: checks
            .validations
            .iter()
            .filter(|report| report.status == ValidationStatus::Passed)
            .cloned()
            .collect(),
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    })
}

fn validation_blocker_details(
    checks: &SafetyChecks<'_>,
    forces: &MergeForceOptions,
) -> Vec<ApplyBlockerDetail> {
    if checks.validation.status != SafetyCheckStatus::Failed {
        return Vec::new();
    }

    let mut details = Vec::new();
    let failed = reports_with_status(checks.validations, ValidationStatus::Failed);
    if !failed.is_empty() {
        details.push(validation_blocker_detail(
            ApplyBlocker::ValidationFailed,
            checks,
            failed,
            !checks.require_validation && forces.allow_validation_failures,
            "run the failing validation command again after fixing the reported paths",
        ));
    }

    if checks.require_validation {
        if checks.validations.is_empty() {
            details.push(validation_blocker_detail(
                ApplyBlocker::ValidationMissing,
                checks,
                Vec::new(),
                false,
                "supply --validation-report with at least one passed check or run merge apply --validation-command <command>",
            ));
            return details;
        }

        if !checks
            .validations
            .iter()
            .any(|validation| validation.status == ValidationStatus::Passed)
        {
            let not_run = reports_with_status(checks.validations, ValidationStatus::NotRun);
            if !not_run.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationNotRun,
                    checks,
                    not_run,
                    false,
                    "run the pending validation command and provide a passed validation report",
                ));
            }
            let skipped = reports_with_status(checks.validations, ValidationStatus::Skipped);
            if !skipped.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationSkipped,
                    checks,
                    skipped,
                    false,
                    "run the skipped validation command and provide a passed validation report",
                ));
            }
            if details.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationMissing,
                    checks,
                    checks.validations.to_vec(),
                    false,
                    "provide at least one passed validation report",
                ));
            }
        }
    }

    details
}

fn validation_blocker_detail(
    kind: ApplyBlocker,
    checks: &SafetyChecks<'_>,
    reports: Vec<ValidationReport>,
    force_allowed: bool,
    next_safe_operation: &str,
) -> ApplyBlockerDetail {
    let paths = validation_detail_paths(&reports, checks.validation_related_paths);
    ApplyBlockerDetail {
        kind,
        disposition: if force_allowed {
            ApplyBlockerDisposition::Forced
        } else {
            ApplyBlockerDisposition::Blocked
        },
        check_status: checks.validation.status,
        paths,
        message: checks.validation.message.clone(),
        validation_reports: reports,
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    }
}

fn validation_detail_paths(
    reports: &[ValidationReport],
    validation_related_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut paths = reports
        .iter()
        .flat_map(|report| report.paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    if paths.is_empty() {
        paths.extend(validation_related_paths.iter().cloned());
    }
    paths.into_iter().collect()
}

fn reports_with_status(
    validations: &[ValidationReport],
    status: ValidationStatus,
) -> Vec<ValidationReport> {
    validations
        .iter()
        .filter(|validation| validation.status == status)
        .cloned()
        .collect()
}

pub(crate) fn unclaimed_paths(
    changed_paths: &[PathBuf],
    claimed_paths: &[PathBuf],
) -> Vec<PathBuf> {
    changed_paths
        .iter()
        .filter(|path| {
            !claimed_paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect()
}

pub(crate) fn normalize_claim_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(collapse_covered_paths(paths))
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }

    collapsed
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn classify_status(status: Status) -> ChangeKind {
    if status.contains(Status::CONFLICTED) {
        ChangeKind::Conflicted
    } else if status.contains(Status::WT_NEW) {
        ChangeKind::Untracked
    } else if status.contains(Status::INDEX_RENAMED) || status.contains(Status::WT_RENAMED) {
        ChangeKind::Renamed
    } else if status.contains(Status::INDEX_DELETED) || status.contains(Status::WT_DELETED) {
        ChangeKind::Deleted
    } else if status.contains(Status::INDEX_NEW) {
        ChangeKind::Added
    } else if status.contains(Status::INDEX_TYPECHANGE) || status.contains(Status::WT_TYPECHANGE) {
        ChangeKind::Typechange
    } else if status.contains(Status::INDEX_MODIFIED) || status.contains(Status::WT_MODIFIED) {
        ChangeKind::Modified
    } else {
        ChangeKind::Unknown
    }
}

pub(crate) fn serialize_path<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&path_json_text(path))
}

pub(crate) fn serialize_paths<S>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn serialize_optional_path<S>(
    path: &Option<PathBuf>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    path.as_deref().map(path_json_text).serialize(serializer)
}

pub(crate) fn path_json_text(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return escape_bytes_ascii(path.as_os_str().as_bytes());
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut escaped = String::new();
        for unit in path.as_os_str().encode_wide() {
            if matches!(unit, 0x20..=0x7e) && unit != u16::from(b'\\') {
                escaped.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
            } else {
                let _ = write!(&mut escaped, "\\u{unit:04X}");
            }
        }
        return escaped;
    }

    #[allow(unreachable_code)]
    "<non-unicode-path>".to_string()
}

pub(crate) fn raw_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return path.as_os_str().as_bytes().to_vec();
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        return path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
    }

    #[allow(unreachable_code)]
    path.as_os_str()
        .to_str()
        .map(str::as_bytes)
        .unwrap_or_default()
        .to_vec()
}

fn path_buf_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    #[cfg(not(unix))]
    {
        let path = String::from_utf8(bytes.to_vec())
            .context("Git returned a repository path that is not valid UTF-8 on this platform")?;
        Ok(PathBuf::from(path))
    }
}

pub(crate) fn patch_text_for_json(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|error| escape_bytes_ascii(error.as_bytes()))
}

fn escape_bytes_ascii(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for byte in bytes {
        match *byte {
            b'\n' => escaped.push('\n'),
            b'\r' => escaped.push('\r'),
            b'\t' => escaped.push('\t'),
            0x20..=0x7e if *byte != b'\\' => escaped.push(char::from(*byte)),
            b'\\' => escaped.push_str("\\\\"),
            _ => {
                let _ = write!(&mut escaped, "\\x{byte:02X}");
            }
        }
    }
    escaped
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn head_oid(repo: &Repository) -> Result<Option<Oid>, git2::Error> {
    match repo.head() {
        Ok(head) => head.peel_to_commit().map(|commit| Some(commit.id())),
        Err(error) if error.code() == ErrorCode::UnbornBranch => Ok(None),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn merge_base_oid(repo: &Repository, primary: Oid, agent: Oid) -> Result<Option<Oid>> {
    match repo.merge_base(primary, agent) {
        Ok(oid) => Ok(Some(oid)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to compute merge base"),
    }
}

fn discover_primary_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("merge operations require a non-bare primary repository")
}

impl RepoCommonLock {
    pub(crate) fn acquire(repo_root: &Path, operation: &str) -> Result<Self> {
        if operation.is_empty()
            || !operation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("repository lock operation name is invalid");
        }
        let repo = Repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for {operation} lock {}",
                repo_root.display()
            )
        })?;
        let state_dir = ensure_repo_common_state_directory(&repo)
            .with_context(|| format!("failed to prepare {operation} lock directory"))?;
        let path = state_dir.join(REPOSITORY_MUTATION_LOCK_FILE);
        let mut file = open_repo_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return repository_lock_contention(&mut file, &path, operation)
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "{operation} could not acquire kernel repository mutation lock {}; refusing to continue",
                        path.display()
                    )
                })
            }
        }

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        let process_start = lock_owner_process_start_identity()?;
        let owner = RepoLockOwner {
            version: LOCK_RECORD_VERSION,
            pid: std::process::id(),
            nonce: format!("{}-{}", std::process::id(), duration.as_nanos()),
            created_unix_seconds: duration.as_secs(),
            operation: operation.to_string(),
            process_start,
        };
        let mut owner_bytes = serde_json::to_vec(&owner).context("failed to encode lock owner")?;
        owner_bytes.push(b'\n');
        write_lock_owner(&mut file, &path, operation, &owner_bytes)?;
        Ok(Self { file })
    }
}

fn open_repo_lock_file(path: &Path) -> Result<fs::File> {
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let (file, created) = match create_options.open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_lock_path(path)?;
            let mut existing_options = OpenOptions::new();
            existing_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing_options
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                existing_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            (
                existing_options.open(path).with_context(|| {
                    format!("failed to open repository lock {}", path.display())
                })?,
                false,
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create repository lock {}", path.display()))
        }
    };
    validate_open_lock_file(path, &file)?;
    if created {
        let parent = path
            .parent()
            .context("repository mutation lock has no parent directory")?;
        sync_managed_directory(parent)?;
    }
    Ok(file)
}

pub(crate) fn ensure_repo_common_state_directory(repo: &Repository) -> Result<PathBuf> {
    let common_dir = repo.commondir();
    validate_managed_directory(common_dir).with_context(|| {
        format!(
            "repository common directory {} is unsafe",
            common_dir.display()
        )
    })?;
    let maco = ensure_private_managed_directory(common_dir, "maco")?;
    ensure_private_managed_directory(&maco, "state")
}

pub(crate) fn ensure_private_managed_directory(parent: &Path, name: &str) -> Result<PathBuf> {
    validate_managed_directory(parent)?;
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("managed directory component is invalid");
    }
    let path = parent.join(name);
    let created = match fs::create_dir(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create managed directory {}", path.display()))
        }
    };
    validate_managed_directory(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure managed directory {}", path.display()))?;
        validate_managed_directory(&path)?;
    }
    sync_managed_directory(&path)?;
    if created {
        sync_managed_directory(parent)?;
    }
    Ok(path)
}

fn validate_managed_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect managed directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "managed directory {} is not a real directory; refusing symbolic links and non-directory paths",
            path.display()
        );
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn sync_managed_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("failed to open managed directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to persist managed directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_managed_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn reject_unsafe_lock_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
    {
        bail!(
            "repository mutation lock {} is not a regular file; refusing to follow it",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_open_lock_file(path: &Path, file: &fs::File) -> Result<()> {
    reject_unsafe_lock_path(path)?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect repository lock {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open repository lock {}", path.display()))?;
    if !file_metadata.file_type().is_file() || metadata_is_windows_reparse_point(&file_metadata) {
        bail!(
            "repository mutation lock {} changed type while being opened",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
            || file_metadata.nlink() != 1
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        let path_volume = path_metadata
            .volume_serial_number()
            .context("repository lock path omitted volume identity")?;
        let file_volume = file_metadata
            .volume_serial_number()
            .context("open repository lock omitted volume identity")?;
        let path_index = path_metadata
            .file_index()
            .context("repository lock path omitted file identity")?;
        let file_index = file_metadata
            .file_index()
            .context("open repository lock omitted file identity")?;
        if path_volume != file_volume
            || path_index != file_index
            || file_metadata.number_of_links() != Some(1)
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    Ok(())
}

fn write_lock_owner(
    file: &mut fs::File,
    path: &Path,
    operation: &str,
    owner_bytes: &[u8],
) -> Result<()> {
    file.set_len(0)
        .with_context(|| format!("failed to truncate {operation} lock owner record"))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek {operation} lock owner record"))?;
    file.write_all(owner_bytes)
        .with_context(|| format!("failed to record {operation} lock owner"))?;
    file.sync_all().with_context(|| {
        format!(
            "failed to persist {operation} lock owner record {}",
            path.display()
        )
    })
}

fn repository_lock_contention<T>(file: &mut fs::File, path: &Path, operation: &str) -> Result<T> {
    let current = read_lock_record(file, path)
        .and_then(|bytes| {
            serde_json::from_slice::<RepoLockOwner>(&bytes)
                .context("active repository lock owner JSON is malformed")
        })
        .and_then(|owner| {
            validate_lock_owner(&owner, operation)?;
            Ok(owner)
        });
    match current {
        Ok(owner) => bail!(
            "{operation} cannot acquire repository mutation lock: kernel lock is held for {} by pid {} (nonce {}, created {})",
            owner.operation,
            owner.pid,
            owner.nonce,
            owner.created_unix_seconds
        ),
        Err(error) => bail!(
            "{operation} cannot acquire repository mutation lock {}: an active kernel lock has an invalid owner record ({error:#})",
            path.display()
        ),
    }
}

fn validate_lock_owner(owner: &RepoLockOwner, operation: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch while validating repository lock")?
        .as_secs();
    if owner.version != LOCK_RECORD_VERSION
        || owner.pid == 0
        || owner.nonce.is_empty()
        || owner.nonce.len() > 128
        || !owner
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || owner.created_unix_seconds == 0
        || owner.created_unix_seconds > now.saturating_add(300)
        || owner.operation.is_empty()
        || owner.operation.len() > 64
        || !owner
            .operation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !valid_process_start_identity(owner.process_start.as_ref())
    {
        bail!(
            "{operation} repository mutation lock owner record is invalid and will not be reclaimed automatically"
        );
    }
    Ok(())
}

fn valid_process_start_identity(identity: Option<&ProcessStartIdentity>) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(identity, Some(ProcessStartIdentity::LinuxProcStartTicks(value)) if *value > 0)
    }
    #[cfg(target_os = "windows")]
    {
        matches!(identity, Some(ProcessStartIdentity::WindowsCreationFiletime(value)) if *value > 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        identity.is_none()
    }
}

fn read_lock_record(file: &mut fs::File, path: &Path) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if metadata.len() == 0 || metadata.len() > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record has an invalid size");
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek repository lock {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOCK_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read repository lock {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record changed size while being read");
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read process identity {}", path.display()))
        }
    };
    let closing_paren = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .context("Linux process stat did not contain a command terminator")?;
    let fields = bytes[closing_paren + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let start_ticks = fields
        .get(19)
        .context("Linux process stat did not contain starttime")?;
    let start_ticks = std::str::from_utf8(start_ticks)
        .context("Linux process starttime was not ASCII")?
        .parse::<u64>()
        .context("Linux process starttime was invalid")?;
    if start_ticks == 0 {
        bail!("Linux process starttime was zero");
    }
    Ok(Some(ProcessStartIdentity::LinuxProcStartTicks(start_ticks)))
}

#[cfg(target_os = "windows")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    windows_process_start_identity(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn process_start_identity(_pid: u32) -> Result<Option<ProcessStartIdentity>> {
    Ok(None)
}

fn lock_owner_process_start_identity() -> Result<Option<ProcessStartIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        process_start_identity(std::process::id())?
            .with_context(|| {
                "current process start identity disappeared while acquiring repository lock"
            })
            .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
fn windows_process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    // SAFETY: The Windows API calls use a PID-sized integer, checked null
    // handles, initialized FILETIME outputs, and close every acquired handle.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER) {
                Ok(None)
            } else {
                Err(error).context("failed to open process for creation-time identity")
            };
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let times_error = (result == 0).then(std::io::Error::last_os_error);
        let close_result = CloseHandle(handle);
        if let Some(error) = times_error {
            return Err(error).context("failed to read process creation-time identity");
        }
        if close_result == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to close process identity handle");
        }
        let value = (u64::from(creation.high) << 32) | u64::from(creation.low);
        if value == 0 {
            bail!("Windows process creation time was zero");
        }
        Ok(Some(ProcessStartIdentity::WindowsCreationFiletime(value)))
    }
}

impl Drop for RepoCommonLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl PrimaryRepositoryState {
    fn capture(repo_root: &Path) -> Result<Self> {
        let first = Self::capture_once(repo_root)?;
        let second = Self::capture_once(repo_root)?;
        if first != second {
            bail!(
                "primary repository state changed while it was being captured; retry merge apply after concurrent repository activity stops"
            );
        }
        Ok(second)
    }

    fn capture_once(repo_root: &Path) -> Result<Self> {
        let repo = Repository::open(repo_root).with_context(|| {
            format!("failed to open primary repository {}", repo_root.display())
        })?;
        let head = head_oid(&repo).context("failed to read primary HEAD for merge transaction")?;
        let index_digest = hash_optional_file(&repo.path().join("index"))?;
        let worktree_digest = snapshot_worktree_candidate(&repo, repo_root, head)?.oid;
        Ok(Self {
            head,
            index_digest,
            worktree_digest,
        })
    }
}

fn run_git_with_input(repo_root: &Path, args: &[&str], input: &[u8]) -> Result<GitCommandOutput> {
    let repo = Repository::open(repo_root)
        .with_context(|| format!("failed to open Git worktree {}", repo_root.display()))?;
    let context = TemporaryIndex::create(repo.commondir())?;
    initialize_isolated_index(&context, repo_root, head_oid(&repo)?)?;
    run_isolated_git_process(
        &context,
        repo_root,
        args,
        StdinMode::Bytes(input.to_vec()),
        "git patch command",
    )
}

fn run_isolated_git_process(
    context: &TemporaryIndex,
    worktree_path: &Path,
    operation: &[&str],
    stdin: StdinMode,
    label: &str,
) -> Result<GitCommandOutput> {
    run_isolated_git_process_os(
        context,
        worktree_path,
        context.command_args(worktree_path, operation),
        stdin,
        label,
    )
}

fn run_isolated_git_process_os(
    context: &TemporaryIndex,
    worktree_path: &Path,
    command_args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
) -> Result<GitCommandOutput> {
    let profile = StrictOfflineWorkspaceProfile::read_write(worktree_path)
        .with_writable_artifact_root(&context.directory)
        .with_visible_read_only_root(&context.alternate_object_directory);
    run_required_direct(
        label,
        resolve_trusted_executable("git")?,
        command_args,
        worktree_path,
        capture_git_environment(worktree_path)?,
        stdin,
        LOCAL_GIT_PROCESS_TIMEOUT,
        GIT_CAPTURE_LIMIT_BYTES,
        GIT_STDIN_LIMIT_BYTES,
        profile,
    )
}

fn initialize_isolated_index(
    context: &TemporaryIndex,
    worktree_path: &Path,
    head: Option<Oid>,
) -> Result<()> {
    let head_text = head.map(|oid| oid.to_string());
    let args = match head_text.as_deref() {
        Some(oid) => vec!["read-tree", oid],
        None => vec!["read-tree", "--empty"],
    };
    let output = run_isolated_git_process(
        context,
        worktree_path,
        &args,
        StdinMode::Null,
        "initialize isolated Git index",
    )?;
    require_git_success(output, "initialize isolated Git index")
}

fn capture_git_environment(repo_root: &Path) -> Result<BTreeMap<String, String>> {
    let allowed = [
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ];
    let mut environment = explicit_environment(&allowed);
    let runtime_root = trusted_runtime_root(repo_root)?;
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert(
        "GIT_CONFIG_GLOBAL".to_string(),
        path_environment_value(&disabled_git_path(&runtime_root, "global-config"))?,
    );
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    let runtime = path_environment_value(&runtime_root)?;
    environment.insert("TMPDIR".to_string(), runtime.clone());
    environment.insert("TMP".to_string(), runtime.clone());
    environment.insert("TEMP".to_string(), runtime);
    Ok(environment)
}

fn validation_command_environment(environment_root: &Path) -> Result<BTreeMap<String, String>> {
    create_private_directory(environment_root)?;
    let home = environment_root.join("home");
    let temporary = environment_root.join("tmp");
    let xdg_config = environment_root.join("xdg-config");
    let xdg_cache = environment_root.join("xdg-cache");
    let xdg_state = environment_root.join("xdg-state");
    for directory in [&home, &temporary, &xdg_config, &xdg_cache, &xdg_state] {
        create_private_directory(directory)?;
    }
    let global_git_config = environment_root.join("gitconfig");
    write_private_file(&global_git_config, b"")?;
    let mut environment = explicit_environment(&[
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ]);
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("HOME".to_string(), path_environment_value(&home)?);
    environment.insert(
        "XDG_CONFIG_HOME".to_string(),
        path_environment_value(&xdg_config)?,
    );
    environment.insert(
        "XDG_CACHE_HOME".to_string(),
        path_environment_value(&xdg_cache)?,
    );
    environment.insert(
        "XDG_STATE_HOME".to_string(),
        path_environment_value(&xdg_state)?,
    );
    let temporary = path_environment_value(&temporary)?;
    environment.insert("TMPDIR".to_string(), temporary.clone());
    environment.insert("TMP".to_string(), temporary.clone());
    environment.insert("TEMP".to_string(), temporary);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert(
        "GIT_CONFIG_GLOBAL".to_string(),
        path_environment_value(&global_git_config)?,
    );
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    Ok(environment)
}

fn validation_diagnostics_redactor(environment_root: &Path) -> Redactor {
    let mut redactor = Redactor::new().with_private_value(
        "validation-runtime",
        environment_root.to_string_lossy().into_owned(),
    );
    for (key, value) in env::vars() {
        if validation_private_environment_key(&key) && value.len() >= 4 {
            redactor = redactor.with_private_value("validation-private-env", value);
        }
    }
    redactor
}

fn validation_private_environment_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    key == "BASH_ENV"
        || key == "ENV"
        || key == "SSH_AUTH_SOCK"
        || key == "ALL_PROXY"
        || key == "NO_PROXY"
        || key.ends_with("_PROXY")
        || matches!(
            key.as_str(),
            "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
                | "CURL_CA_BUNDLE"
                | "REQUESTS_CA_BUNDLE"
                | "NODE_EXTRA_CA_CERTS"
                | "GIT_SSL_CAINFO"
                | "GIT_SSL_CAPATH"
        )
        || key.contains("SECRET")
        || key.contains("TOKEN")
        || key.contains("PASSWORD")
        || key.contains("PRIVATE_KEY")
        || key.contains("API_KEY")
        || key.contains("ACCESS_KEY")
        || key.contains("CREDENTIAL")
        || key.contains("COOKIE")
        || key.contains("SESSION")
        || key == "AUTH"
        || key.starts_with("AUTH_")
        || key.ends_with("_AUTH")
        || key.contains("_AUTH_")
        || (key.ends_with("_KEY") && !key.ends_with("_PUBLIC_KEY"))
        || [
            "AWS_",
            "AZURE_",
            "GOOGLE_",
            "OPENAI_",
            "ANTHROPIC_",
            "GH_",
            "GITHUB_",
            "GITLAB_",
            "HF_",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

pub(crate) fn minimal_network_environment() -> Result<BTreeMap<String, String>> {
    let allowed = [
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ];
    let mut environment = explicit_environment(&allowed);
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    Ok(environment)
}

fn explicit_environment(keys: &[&str]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| env::var(key).ok().map(|value| ((*key).to_string(), value)))
        .collect()
}

fn trusted_path_text() -> Result<String> {
    trusted_executable_search_path()?
        .into_string()
        .map_err(|_| anyhow::anyhow!("trusted executable PATH was not valid UTF-8"))
}

fn path_environment_value(path: &Path) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("environment path was not UTF-8: {}", path.display()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_required_direct(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: StrictOfflineWorkspaceProfile,
) -> Result<RequiredCommandOutput> {
    run_required_direct_with_profile(
        label,
        program,
        args,
        current_dir,
        environment,
        stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
        SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_required_network_direct(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: TrustedFixedNetworkProfile,
) -> Result<RequiredCommandOutput> {
    validate_fixed_network_command(
        label,
        &program,
        &args,
        current_dir,
        &environment,
        &stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
    )?;
    run_required_direct_with_profile(
        label,
        program,
        args,
        current_dir,
        environment,
        stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
        SideEffectConfinementProfile::TrustedFixedNetwork(profile),
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_required_direct_with_profile(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: SideEffectConfinementProfile,
    expected_profile: SideEffectConfinementProfileKind,
) -> Result<RequiredCommandOutput> {
    if let StdinMode::Bytes(bytes) = &stdin {
        if bytes.len() > stdin_limit_bytes {
            bail!("{label} stdin exceeded the {stdin_limit_bytes}-byte safety limit");
        }
    }
    let output = run_process(
        ProcessSpec::direct(label, program, args, current_dir, capture_limit_bytes)
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_side_effect_confinement(profile)
            .with_stdin(stdin)
            .with_timeout(Some(timeout)),
    )
    .with_context(|| format!("failed to run {label}"))?;
    require_verified_process_output(label, &output, expected_profile)?;
    Ok(RequiredCommandOutput {
        success: output.status.is_some_and(|status| status.success()),
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
    })
}

fn require_verified_process_output(
    label: &str,
    output: &ProcessOutput,
    expected_profile: SideEffectConfinementProfileKind,
) -> Result<()> {
    require_verified_containment(label, output.process_tree)?;
    if output.side_effects != SideEffectConfinementEvidence::Verified(expected_profile) {
        bail!(
            "{label} returned without exact verified {expected_profile:?} side-effect confinement: {:?}",
            output.side_effects,
        );
    }
    if output.timed_out {
        bail!("{label} exceeded its total operation deadline");
    }
    if let Some(error) = &output.process_error {
        bail!("{label} process cleanup failed: {error}");
    }
    if let Some(error) = &output.stdin_error {
        bail!("{label} stdin failed: {error}");
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!("{label} exceeded its bounded output capture limit");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_fixed_network_command(
    label: &str,
    program: &Path,
    args: &[OsString],
    current_dir: &Path,
    environment: &BTreeMap<String, String>,
    stdin: &StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
) -> Result<()> {
    if label.is_empty()
        || label.len() > 1024
        || label.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        bail!("trusted network command label is empty or oversized");
    }
    let program_text = program
        .to_str()
        .context("trusted network executable path was not strict UTF-8")?;
    if program_text.len() > 4096
        || program_text
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("trusted network executable path is malformed or oversized");
    }
    let executable_name = program
        .file_name()
        .and_then(OsStr::to_str)
        .context("trusted network executable name was not UTF-8")?;
    if !program.is_absolute() || !matches!(executable_name, "git" | "gh") {
        bail!("trusted network command requires an absolute fixed git or gh executable");
    }
    let expected = resolve_trusted_executable(executable_name)?;
    if expected != program {
        bail!("trusted network executable did not match its fixed resolved identity");
    }
    if timeout.is_zero() || timeout > Duration::from_secs(10 * 60) {
        bail!("trusted network command deadline is zero or exceeds ten minutes");
    }
    if capture_limit_bytes == 0
        || capture_limit_bytes > 64 * 1024 * 1024
        || stdin_limit_bytes > 64 * 1024 * 1024
    {
        bail!("trusted network stream bounds are zero or oversized");
    }
    if args.len() > 2048 {
        bail!("trusted network argument vector is oversized");
    }
    let mut total_argument_bytes = 0usize;
    for argument in args {
        let argument = argument
            .to_str()
            .context("trusted network command argument was not strict UTF-8")?;
        if argument.len() > 64 * 1024
            || argument
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
        {
            bail!("trusted network command argument is malformed or oversized");
        }
        total_argument_bytes = total_argument_bytes
            .checked_add(argument.len())
            .context("trusted network argument size overflow")?;
    }
    if total_argument_bytes > 2 * 1024 * 1024 {
        bail!("trusted network argument vector exceeds its aggregate bound");
    }
    if let StdinMode::Bytes(bytes) = stdin {
        if bytes.len() > stdin_limit_bytes {
            bail!("trusted network stdin exceeds its declared bound");
        }
    }
    if matches!(stdin, StdinMode::Inherit) {
        bail!("trusted network commands may not inherit stdin");
    }
    if !current_dir.is_absolute() {
        bail!("trusted network working directory must be absolute");
    }
    validate_fixed_network_environment(environment, current_dir)
}

fn validate_fixed_network_environment(
    environment: &BTreeMap<String, String>,
    current_dir: &Path,
) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ATTR_NOSYSTEM",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "GH_CONFIG_DIR",
        "GH_PROMPT_DISABLED",
    ];
    if environment.len() > 32 {
        bail!("trusted network environment exceeds its entry bound");
    }
    for (key, value) in environment {
        if !ALLOWED.contains(&key.as_str())
            || key.len() > 128
            || value.len() > 1024 * 1024
            || key
                .as_bytes()
                .iter()
                .chain(value.as_bytes())
                .any(|byte| byte.is_ascii_control())
        {
            bail!("trusted network environment contains an unapproved or oversized entry");
        }
    }
    let trusted_path = trusted_path_text()?;
    if environment.get("PATH").map(String::as_str) != Some(trusted_path.as_str()) {
        bail!("trusted network PATH differs from the fixed system executable path");
    }
    for key in ["GIT_CONFIG_GLOBAL", "GH_CONFIG_DIR"] {
        if let Some(value) = environment.get(key) {
            let path = Path::new(value);
            if !path.is_absolute() || !path.starts_with(current_dir) {
                bail!("trusted network private config escaped its fixed runtime directory");
            }
        }
    }
    Ok(())
}

fn require_verified_containment(label: &str, evidence: ContainmentEvidence) -> Result<()> {
    if !evidence.is_verified_empty() {
        bail!("{label} returned without verified-empty process containment: {evidence:?}");
    }
    Ok(())
}

#[cfg(test)]
fn is_git_injection_environment_key(key: &str) -> bool {
    matches!(
        key,
        "GIT_DIR"
            | "GIT_WORK_TREE"
            | "GIT_INDEX_FILE"
            | "GIT_COMMON_DIR"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
            | "GIT_REDIRECT_STDERR"
            | "GIT_EXEC_PATH"
            | "GIT_NAMESPACE"
            | "GIT_REPLACE_REF_BASE"
            | "GIT_SHALLOW_FILE"
            | "GIT_GRAFT_FILE"
            | "GIT_QUARANTINE_PATH"
            | "GIT_CEILING_DIRECTORIES"
            | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
            | "GIT_TEMPLATE_DIR"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_ASKPASS"
            | "SSH_ASKPASS"
            | "SSH_ASKPASS_REQUIRE"
            | "GIT_PROXY_COMMAND"
            | "GIT_ALLOW_PROTOCOL"
            | "GIT_PROTOCOL_FROM_USER"
            | "GIT_CURL_VERBOSE"
            | "GIT_SSL_NO_VERIFY"
    ) || key.starts_with("GIT_CONFIG_")
        || key.starts_with("GIT_TRACE")
}

pub(crate) fn resolve_trusted_executable(name: &str) -> Result<PathBuf> {
    if !matches!(name, "git" | "gh") {
        bail!("unsupported trusted executable name '{name}'");
    }
    #[cfg(target_os = "windows")]
    {
        let _ = name;
        bail!(
            "trusted Windows executable and ACL resolution is not implemented; refusing external command execution"
        );
    }
    #[cfg(unix)]
    {
        let mut inspected = BTreeSet::new();
        for candidate in trusted_executable_entry_candidates(name) {
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if !inspected.insert(canonical.clone()) {
                continue;
            }
            if validate_trusted_unix_executable(&canonical).is_ok() {
                return Ok(canonical);
            }
        }
        bail!(
            "no trusted root-owned, non-writable executable was found for '{name}' through a fixed system entry"
        );
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = name;
        bail!("trusted executable resolution is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_executable_entry_candidates(name: &str) -> [PathBuf; 3] {
    [
        Path::new("/run/current-system/sw/bin").join(name),
        Path::new("/usr/bin").join(name),
        Path::new("/bin").join(name),
    ]
}

#[cfg(unix)]
fn validate_trusted_unix_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect executable {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("trusted executable candidate is not a regular file");
    }
    let mode = metadata.permissions().mode();
    if metadata.uid() != 0 || mode & 0o022 != 0 || mode & 0o111 == 0 {
        bail!("trusted executable candidate has unsafe owner or mode");
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let directory_metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable ancestor {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && directory_metadata.uid() == 0
            && directory_metadata.permissions().mode() & 0o1000 != 0;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.uid() != 0
            || (!immutable_nix_store_root && directory_metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("trusted executable candidate has a writable or non-root ancestor");
        }
        ancestor = directory.parent();
    }
    let mut magic = [0_u8; 4];
    fs::File::open(path)
        .with_context(|| format!("failed to open executable {}", path.display()))?
        .read_exact(&mut magic)
        .with_context(|| format!("failed to inspect executable header {}", path.display()))?;
    if !is_native_executable_magic(magic) {
        if magic[..2] != *b"#!" {
            bail!("trusted executable candidate has an unsupported executable format");
        }
        validate_trusted_shebang(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_shebang(path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open executable script {}", path.display()))?
        .take(4096)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read executable script {}", path.display()))?;
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .context("trusted executable script omitted shebang")?;
    let interpreter = first_line
        .strip_prefix(b"#!")
        .context("trusted executable script omitted shebang marker")?;
    let interpreter = std::str::from_utf8(interpreter)
        .context("trusted executable script shebang was not UTF-8")?
        .trim()
        .split_ascii_whitespace()
        .next()
        .context("trusted executable script shebang omitted interpreter")?;
    let interpreter = Path::new(interpreter);
    if !interpreter.is_absolute() {
        bail!("trusted executable script shebang was not absolute");
    }
    let interpreter = fs::canonicalize(interpreter).with_context(|| {
        format!(
            "failed to resolve trusted script interpreter {}",
            interpreter.display()
        )
    })?;
    if interpreter == path {
        bail!("trusted executable script shebang referenced itself");
    }
    validate_trusted_unix_executable(&interpreter)
        .context("trusted executable script interpreter was unsafe")
}

fn is_native_executable_magic(magic: [u8; 4]) -> bool {
    magic == *b"\x7fELF"
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
        || magic[..2] == *b"MZ"
}

fn trusted_executable_search_path() -> Result<OsString> {
    #[cfg(unix)]
    {
        let directories = [
            PathBuf::from("/run/current-system/sw/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]
        .into_iter()
        .filter_map(|path| trusted_unix_search_directory(&path).ok())
        .collect::<Vec<_>>();
        if directories.is_empty() {
            bail!("no trusted system executable directories were available");
        }
        env::join_paths(directories).context("failed to build trusted executable PATH")
    }
    #[cfg(target_os = "windows")]
    {
        bail!("trusted Windows executable PATH is not implemented")
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        bail!("trusted executable PATH is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_unix_search_directory(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve executable directory {}", path.display()))?;
    let mut current = Some(canonical.as_path());
    while let Some(directory) = current {
        let metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable directory {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || (!immutable_nix_store_root && metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("executable search directory has unsafe owner or mode");
        }
        current = directory.parent();
    }
    Ok(canonical)
}

fn disabled_git_path(runtime_root: &Path, label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    runtime_root.join(format!(
        "maco-disabled-{label}-{}-{nanos}",
        std::process::id()
    ))
}

pub(crate) fn trusted_runtime_root(repo_root: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    let candidate = private_unix_runtime_root()?;
    #[cfg(target_os = "windows")]
    let candidate = windows_temp_path()?;
    #[cfg(not(any(unix, target_os = "windows")))]
    let candidate = env::temp_dir();

    let runtime_root = fs::canonicalize(&candidate).with_context(|| {
        format!(
            "failed to resolve trusted runtime directory {}",
            candidate.display()
        )
    })?;
    if !runtime_root.is_dir() {
        bail!(
            "trusted runtime path {} is not a directory",
            runtime_root.display()
        );
    }
    let repo_root = fs::canonicalize(repo_root)
        .with_context(|| format!("failed to resolve repository path {}", repo_root.display()))?;
    if runtime_root.starts_with(&repo_root) {
        bail!(
            "trusted runtime directory {} is inside repository {}; refusing capture-time writes",
            runtime_root.display(),
            repo_root.display()
        );
    }
    Ok(runtime_root)
}

#[cfg(unix)]
fn private_unix_runtime_root() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let uid = unsafe { libc::geteuid() };
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    let parent = match validate_private_unix_directory(&run_user, uid) {
        Ok(()) => run_user,
        Err(_) => {
            let temporary =
                fs::canonicalize("/tmp").context("failed to resolve /tmp runtime fallback")?;
            let metadata = fs::symlink_metadata(&temporary)
                .context("failed to inspect /tmp runtime fallback")?;
            let mode = metadata.permissions().mode();
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || mode & 0o1000 == 0
            {
                bail!("/tmp is not a root-owned sticky directory; refusing runtime fallback");
            }
            temporary
        }
    };
    let directory = parent.join(format!("maco-runtime-{uid}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to create private runtime {}", directory.display())
            })
        }
    }
    validate_private_unix_directory(&directory, uid)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_private_unix_directory(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!(
            "private runtime {} is not an owner-only real directory",
            path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_temp_path() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32;
    }

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: The buffer is writable for its declared length and the returned
    // length is checked before constructing the Windows path.
    let length = unsafe { GetTempPathW(buffer.len() as u32, buffer.as_mut_ptr()) };
    if length == 0 || length as usize >= buffer.len() {
        bail!("Windows GetTempPathW failed or returned an oversized path");
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn format_blockers(blockers: &[ApplyBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| blocker_label(*blocker))
        .collect::<Vec<_>>()
        .join(", ")
}

fn blocker_label(blocker: ApplyBlocker) -> &'static str {
    match blocker {
        ApplyBlocker::DirtyPrimary => "dirty_primary",
        ApplyBlocker::StaleBase => "stale_base",
        ApplyBlocker::ApplyCheckFailed => "apply_check_failed",
        ApplyBlocker::ExcludedReference => "excluded_reference",
        ApplyBlocker::UnclaimedEdits => "unclaimed_edits",
        ApplyBlocker::ValidationMissing => "validation_missing",
        ApplyBlocker::ValidationNotRun => "validation_not_run",
        ApplyBlocker::ValidationSkipped => "validation_skipped",
        ApplyBlocker::ValidationFailed => "validation_failed",
    }
}

fn git_stderr_text(output: &GitCommandOutput) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn merge_path_sets(left: &[PathBuf], right: &[PathBuf]) -> Vec<PathBuf> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_git_apply_error_paths(stderr: &str) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in stderr.lines().map(str::trim) {
        if let Some(path) = parse_patch_failed_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_error_suffix_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_quoted_error_path(line, "error: invalid path ") {
            paths.insert(path);
        }
    }
    paths.into_iter().collect()
}

fn parse_patch_failed_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: patch failed: ")?;
    let (path, line_number) = rest.rsplit_once(':')?;
    if line_number.chars().all(|c| c.is_ascii_digit()) && !path.is_empty() {
        Some(PathBuf::from(path))
    } else {
        None
    }
}

fn parse_error_suffix_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: ")?;
    const SUFFIXES: [&str; 8] = [
        ": patch does not apply",
        ": already exists in working directory",
        ": already exists in index",
        ": does not exist in index",
        ": No such file or directory",
        ": does not match index",
        ": cannot checkout",
        ": needs merge",
    ];
    SUFFIXES
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn parse_quoted_error_path(line: &str, prefix: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix(prefix)?;
    let path = rest.strip_prefix('\'')?.strip_suffix('\'')?;
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn validation_binding_from_json(value: &Value) -> Result<Option<CandidateValidationBinding>> {
    let Some(binding) = value.get("validation_binding") else {
        return Ok(None);
    };
    let binding: CandidateValidationBinding = serde_json::from_value(binding.clone())
        .context("validation_binding must match the candidate validation binding schema")?;
    binding.canonicalized().map(Some)
}

fn validation_report_from_json(value: &Value) -> Result<ValidationReport> {
    let object = value
        .as_object()
        .context("validation report must be an object")?;
    let name = ["name", "command", "id"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .unwrap_or("validation")
        .to_string();
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map(parse_validation_status)
        .transpose()?
        .unwrap_or(ValidationStatus::NotRun);
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| object.get("error").and_then(Value::as_str))
        .or_else(|| {
            object
                .get("stderr")
                .and_then(|stderr| stderr.get("text"))
                .and_then(Value::as_str)
        })
        .filter(|message| !message.is_empty())
        .map(str::to_string);
    let paths = validation_paths_from_json(value)?;

    Ok(ValidationReport {
        name,
        status,
        message,
        paths,
    })
}

fn parse_validation_status(value: &str) -> Result<ValidationStatus> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "not_run" | "not-run" | "pending" => Ok(ValidationStatus::NotRun),
        "passed" | "pass" | "succeeded" | "success" => Ok(ValidationStatus::Passed),
        "failed" | "fail" | "failure" => Ok(ValidationStatus::Failed),
        "skipped" | "skip" => Ok(ValidationStatus::Skipped),
        other => bail!("unknown validation status '{other}'"),
    }
}

fn validation_paths_from_json(value: &Value) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    if let Some(path) = value.get("path").and_then(Value::as_str) {
        paths.insert(PathBuf::from(path));
    }
    if let Some(items) = value.get("paths").and_then(Value::as_array) {
        for item in items {
            let path = item
                .as_str()
                .context("validation report paths must be strings")?;
            paths.insert(PathBuf::from(path));
        }
    }

    Ok(paths.into_iter().collect())
}

fn sort_validation_reports(reports: &mut [ValidationReport]) {
    reports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.paths.cmp(&right.paths))
            .then_with(|| left.message.cmp(&right.message))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::megafile::{FileSizeSample, MegafileRecordKind, MegafileThresholdCalibration};
    use crate::worktree::WorktreeCreateOptions;
    use git2::Signature;
    use std::process::{Command, Stdio};
    use std::sync::{mpsc, Mutex};

    static VALIDATION_ENVIRONMENT_TEST_LOCK: Mutex<()> = Mutex::new(());

    const ARBITRATION_PATCH_A: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+side-a\n";
    const ARBITRATION_PATCH_B: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..3333333 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+side-b\n";
    const ARBITRATION_PATCH_BOTH: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..4444444 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,3 @@\n base\n+side-a\n+side-b\n";
    const ARBITRATION_BASE: &str = "1111111111111111111111111111111111111111";

    #[derive(Clone)]
    struct FakeArbitrationEnvironment {
        prepared: PreparedMergeArbitration,
        candidate_diff: Vec<u8>,
        validation_status: ValidationStatus,
    }

    impl ArbitrationEnvironment for FakeArbitrationEnvironment {
        fn prepare(&self, _options: &MergeArbitrationOptions) -> Result<PreparedMergeArbitration> {
            Ok(self.prepared.clone())
        }

        fn materialize_candidate(
            &self,
            prepared: &PreparedMergeArbitration,
            _proposal: &ArbitrationProposal,
        ) -> Result<MergeApplyPreview> {
            Ok(fake_arbitration_preview(
                prepared,
                self.candidate_diff.clone(),
            ))
        }

        fn validate_candidate(
            &self,
            _preview: &MergeApplyPreview,
            _commands: &[CandidateValidationCommand],
        ) -> Result<Vec<ValidationReport>> {
            Ok(vec![ValidationReport {
                name: "fake candidate validation".to_string(),
                status: self.validation_status,
                message: None,
                paths: vec![PathBuf::from("shared.txt")],
            }])
        }

        fn current_primary_state_sha256(
            &self,
            prepared: &PreparedMergeArbitration,
        ) -> Result<String> {
            Ok(prepared.primary_state_sha256.clone())
        }
    }

    struct TrustedStaticArbitrationRunner {
        proposal: ArbitrationProposal,
    }

    impl ArbitrationRunner for TrustedStaticArbitrationRunner {
        fn run(&self, _request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult> {
            Ok(ArbitrationRunnerResult {
                proposal: self.proposal.clone(),
                execution: ArbitrationRunnerExecution {
                    kind: "trusted_fake_test".to_string(),
                    trusted_local_boundary: true,
                    command: Vec::new(),
                    exit_code: Some(0),
                    timed_out: false,
                },
            })
        }
    }

    fn fake_arbitration_prepared(
        repo: &Path,
        sides: [ArbitrationSide; 2],
        source_diffs: [Vec<u8>; 2],
    ) -> PreparedMergeArbitration {
        let side_evidence = std::array::from_fn(|index| ArbitrationSideEvidence {
            participant: sides[index].clone(),
            head_oid: if index == 0 {
                "2222222222222222222222222222222222222222".to_string()
            } else {
                "3333333333333333333333333333333333333333".to_string()
            },
            tree_oid: if index == 0 {
                "4444444444444444444444444444444444444444".to_string()
            } else {
                "5555555555555555555555555555555555555555".to_string()
            },
            base_oid: ARBITRATION_BASE.to_string(),
            diff_sha256: sha256_hex(&source_diffs[index]),
            diff_bytes: source_diffs[index].len(),
            diff: String::from_utf8_lossy(&source_diffs[index]).into_owned(),
            changed_paths: vec![PathBuf::from("shared.txt")],
            candidate_binding: None,
        });
        let input = ArbitrationInput {
            version: ARBITRATION_INPUT_VERSION,
            arbiter_id: "neutral-arbiter".to_string(),
            reviewed_base_oid: ARBITRATION_BASE.to_string(),
            neutral_worktree: ArbitrationNeutralWorktree {
                agent_id: "neutral-arbiter".to_string(),
                path: repo.join("neutral-worktree"),
                branch: "maco/neutral-arbiter".to_string(),
                exact_base_oid: ARBITRATION_BASE.to_string(),
                inherited_claim: false,
            },
            sides: side_evidence,
            relevant_path_claims: Vec::new(),
            relevant_semantic_intents: Vec::new(),
            semantic_classification: SemanticConflictClassification::no_conflict(),
        };
        let mut input_json = serde_json::to_vec_pretty(&input).expect("serialize fake input");
        input_json.push(b'\n');
        PreparedMergeArbitration {
            input,
            input_sha256: sha256_hex(&input_json),
            input_json,
            primary_repo_root: repo.to_path_buf(),
            primary_state_sha256: sha256_hex(b"stable primary"),
            source_diffs,
        }
    }

    fn fake_arbitration_preview(
        prepared: &PreparedMergeArbitration,
        raw_diff: Vec<u8>,
    ) -> MergeApplyPreview {
        let metadata = WorktreeMergeMetadata {
            agent_id: prepared.input.arbiter_id.clone(),
            worktree_path: prepared.input.neutral_worktree.path.clone(),
            branch: prepared.input.neutral_worktree.branch.clone(),
            primary_repo_root: prepared.primary_repo_root.clone(),
            primary_head: Some(ARBITRATION_BASE.to_string()),
            agent_head: Some(ARBITRATION_BASE.to_string()),
            merge_base: Some(ARBITRATION_BASE.to_string()),
            base_matches_primary: Some(true),
        };
        let binding =
            candidate_validation_binding(&metadata, &raw_diff).expect("fake candidate binding");
        let candidate = MergeCandidate {
            metadata,
            claimed_paths: vec![PathBuf::from("shared.txt")],
            changed_paths: vec![PathBuf::from("shared.txt")],
            changes: vec![ChangedPath {
                path: PathBuf::from("shared.txt"),
                kind: ChangeKind::Modified,
            }],
            unclaimed_changed_paths: Vec::new(),
            diff: DiffOutput {
                summary: summarize_text(
                    &String::from_utf8_lossy(&raw_diff),
                    DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                ),
                full: Some(String::from_utf8_lossy(&raw_diff).into_owned()),
            },
            validations: Vec::new(),
            validation_binding: binding,
            validation_evidence: ValidationEvidenceBundle::default(),
            raw_diff,
            snapshot_tree: Oid::from_str(ARBITRATION_BASE).expect("fake tree"),
        };
        MergeApplyPreview {
            candidate,
            safety: MergeApplySafety {
                primary_state_unchanged: passed_safety_check(),
                dirty_primary: passed_safety_check(),
                stale_base: passed_safety_check(),
                apply_check: passed_safety_check(),
                unclaimed_edits: passed_safety_check(),
                validation: passed_safety_check(),
                validation_evidence: ValidationEvidenceCheck {
                    status: SafetyCheckStatus::Passed,
                    binding_status: ValidationBindingStatus::NotRequired,
                    message: None,
                    paths: Vec::new(),
                },
                megafile: passed_safety_check(),
                megafile_warnings: Vec::new(),
                megafile_decomposition_target: None,
                megafile_decomposition_evidence: None,
                megafile_blocking: false,
                validation_required: false,
                candidate_validation_commands: Vec::new(),
                force_options: MergeForceOptions::default(),
                apply_mode: ApplyMode::Direct,
                semantic_conflicts: SemanticConflictClassification::no_conflict(),
                readiness: ApplyReadiness {
                    status: ApplyReadinessStatus::Safe,
                    blockers: Vec::new(),
                    forced: Vec::new(),
                    details: Vec::new(),
                },
            },
        }
    }

    fn fake_arbitration_options(repo: &Path, run_id: &str) -> MergeArbitrationOptions {
        MergeArbitrationOptions {
            repo: repo.to_path_buf(),
            run_id: RunId::new(run_id).expect("fake run id"),
            arbiter_agent_id: "neutral-arbiter".to_string(),
            sides: [
                ArbitrationSideSpec::Agent {
                    agent_id: "agent-a".to_string(),
                    claimed_paths: vec![PathBuf::from("shared.txt")],
                },
                ArbitrationSideSpec::Agent {
                    agent_id: "agent-b".to_string(),
                    claimed_paths: vec![PathBuf::from("shared.txt")],
                },
            ],
            validation_commands: vec![CandidateValidationCommand {
                command: "fake validation".to_string(),
            }],
            approve: true,
            codex_bin: PathBuf::from("unused"),
            timeout: Duration::from_secs(1),
            worktree_root: None,
        }
    }

    #[test]
    fn arbitration_strict_parser_and_static_runner_are_bounded_and_non_authoritative() {
        let digest = "1".repeat(64);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "input_sha256": digest,
            "disposition": "escalated",
            "rationale": "human review required",
            "candidate_patch": null,
        }))
        .expect("proposal JSON");
        let runner = StaticArbitrationRunner::from_bytes(bytes).expect("static runner");
        let result = runner
            .run(&ArbitrationRunnerRequest {
                input_sha256: "1".repeat(64),
                prompt_path: PathBuf::from("prompt"),
                output_schema_path: PathBuf::from("schema"),
                output_last_message_path: PathBuf::from("output"),
                json_log_path: PathBuf::from("log"),
                neutral_worktree_path: PathBuf::from("neutral"),
                hidden_primary_root: PathBuf::from("primary"),
                run_id: "run".to_string(),
                arbiter_id: "neutral-arbiter".to_string(),
            })
            .expect("static result");
        assert!(!result.execution.trusted_local_boundary);

        let missing = br#"{"version":1,"input_sha256":"1111111111111111111111111111111111111111111111111111111111111111","disposition":"escalated","rationale":"review"}"#;
        assert!(parse_arbitration_proposal(missing)
            .expect_err("missing candidate field")
            .to_string()
            .contains("candidate_patch"));
        assert!(
            parse_arbitration_proposal(&vec![b'x'; MAX_ARBITRATION_PROPOSAL_BYTES + 1])
                .expect_err("oversized proposal")
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn arbitration_prompt_cap_fits_existing_external_runner_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut prepared = fake_arbitration_prepared(
            temp.path(),
            [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Primary,
            ],
            [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
        );
        prepared.input_json = vec![b'x'; MAX_ARBITRATION_INPUT_BYTES];
        assert!(arbitration_prompt(&prepared).len() <= MAX_ARBITRATION_PROMPT_BYTES);
    }

    #[test]
    fn arbitration_preservation_counts_duplicate_occurrences() {
        let duplicate = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,3 @@\n base\n+repeat\n+repeat\n";
        let one_duplicate = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+repeat\n";
        let sides = [
            ArbitrationSideEvidence {
                participant: ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                head_oid: "2".repeat(40),
                tree_oid: "3".repeat(40),
                base_oid: ARBITRATION_BASE.to_string(),
                diff_sha256: sha256_hex(duplicate),
                diff_bytes: duplicate.len(),
                diff: String::from_utf8_lossy(duplicate).into_owned(),
                changed_paths: vec![PathBuf::from("shared.txt")],
                candidate_binding: None,
            },
            ArbitrationSideEvidence {
                participant: ArbitrationSide::Agent {
                    id: "agent-b".to_string(),
                },
                head_oid: "4".repeat(40),
                tree_oid: "5".repeat(40),
                base_oid: ARBITRATION_BASE.to_string(),
                diff_sha256: sha256_hex(ARBITRATION_PATCH_B),
                diff_bytes: ARBITRATION_PATCH_B.len(),
                diff: String::from_utf8_lossy(ARBITRATION_PATCH_B).into_owned(),
                changed_paths: vec![PathBuf::from("shared.txt")],
                candidate_binding: None,
            },
        ];
        let proofs = prove_both_sides_preserved(
            &sides,
            &[duplicate.to_vec(), ARBITRATION_PATCH_B.to_vec()],
            one_duplicate,
        )
        .expect("preservation proof");
        assert!(!proofs[0].preserved);
        assert_eq!(proofs[0].required_additions, 2);
        assert_eq!(proofs[0].preserved_additions, 1);
    }

    #[test]
    fn fake_arbitration_exercises_accepted_rejected_and_escalated_journals_without_primary_apply() {
        let cases = [
            (
                "fake-arbitration-accepted",
                ARBITRATION_PATCH_BOTH.to_vec(),
                ValidationStatus::Passed,
                true,
                ArbitrationOutcome::Accepted,
            ),
            (
                "fake-arbitration-discarded",
                ARBITRATION_PATCH_A.to_vec(),
                ValidationStatus::Passed,
                true,
                ArbitrationOutcome::Rejected,
            ),
            (
                "fake-arbitration-validation",
                ARBITRATION_PATCH_BOTH.to_vec(),
                ValidationStatus::Failed,
                true,
                ArbitrationOutcome::Rejected,
            ),
            (
                "fake-arbitration-unapproved",
                ARBITRATION_PATCH_BOTH.to_vec(),
                ValidationStatus::Passed,
                false,
                ArbitrationOutcome::Escalated,
            ),
        ];
        for (run_id, candidate_diff, validation_status, approve, expected) in cases {
            let temp = tempfile::tempdir().expect("tempdir");
            WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
            let prepared = fake_arbitration_prepared(
                temp.path(),
                [
                    ArbitrationSide::Agent {
                        id: "agent-a".to_string(),
                    },
                    ArbitrationSide::Agent {
                        id: "agent-b".to_string(),
                    },
                ],
                [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
            );
            let environment = FakeArbitrationEnvironment {
                prepared: prepared.clone(),
                candidate_diff,
                validation_status,
            };
            let runner = TrustedStaticArbitrationRunner {
                proposal: ArbitrationProposal {
                    version: ARBITRATION_PROPOSAL_VERSION,
                    input_sha256: prepared.input_sha256.clone(),
                    disposition: ArbitrationProposalDisposition::Proposed,
                    rationale: "bounded fake rationale".to_string(),
                    candidate_patch: Some(
                        "fake patch bytes are materialized by the fake environment".to_string(),
                    ),
                },
            };
            let mut options = fake_arbitration_options(temp.path(), run_id);
            options.approve = approve;
            let report =
                arbitrate_merge_with_environment(options, &runner, &environment).expect("report");
            assert_eq!(report.outcome, expected);
            assert!(!report.primary_mutated);
            assert!(report.later_ordinary_merge_apply_required);
            assert_eq!(primary_repo_path_for_verification(&prepared), temp.path());
        }
    }

    #[test]
    fn static_fake_cannot_claim_accepted_arbitration_authority() {
        let temp = tempfile::tempdir().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
        let prepared = fake_arbitration_prepared(
            temp.path(),
            [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Primary,
            ],
            [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
        );
        let environment = FakeArbitrationEnvironment {
            prepared: prepared.clone(),
            candidate_diff: ARBITRATION_PATCH_BOTH.to_vec(),
            validation_status: ValidationStatus::Passed,
        };
        let output = serde_json::to_vec(&ArbitrationProposal {
            version: ARBITRATION_PROPOSAL_VERSION,
            input_sha256: prepared.input_sha256,
            disposition: ArbitrationProposalDisposition::Proposed,
            rationale: "static fake proposal".to_string(),
            candidate_patch: Some("fake patch".to_string()),
        })
        .expect("static output");
        let runner = StaticArbitrationRunner::from_bytes(output).expect("static runner");
        let mut options = fake_arbitration_options(temp.path(), "static-fake-nonauthoritative");
        options.sides[1] = ArbitrationSideSpec::Primary;
        let report = arbitrate_merge_with_environment(options, &runner, &environment)
            .expect("static report");
        assert_eq!(report.outcome, ArbitrationOutcome::Escalated);
        assert!(!report.approved);
        assert!(!report.runner.trusted_local_boundary);
        assert!(matches!(report.sides[1], ArbitrationSide::Primary));
    }

    #[test]
    fn arbitration_tampered_input_digest_is_rejected_before_candidate_evaluation() {
        let temp = tempfile::tempdir().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
        let prepared = fake_arbitration_prepared(
            temp.path(),
            [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Agent {
                    id: "agent-b".to_string(),
                },
            ],
            [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
        );
        let environment = FakeArbitrationEnvironment {
            prepared,
            candidate_diff: ARBITRATION_PATCH_BOTH.to_vec(),
            validation_status: ValidationStatus::Passed,
        };
        let runner = TrustedStaticArbitrationRunner {
            proposal: ArbitrationProposal {
                version: ARBITRATION_PROPOSAL_VERSION,
                input_sha256: "f".repeat(64),
                disposition: ArbitrationProposalDisposition::Proposed,
                rationale: "tampered input binding".to_string(),
                candidate_patch: Some("fake patch".to_string()),
            },
        };
        let error = arbitrate_merge_with_environment(
            fake_arbitration_options(temp.path(), "tampered-input"),
            &runner,
            &environment,
        )
        .expect_err("tampered digest");
        assert!(error.to_string().contains("does not match"));
    }

    fn exact_test_validation_binding() -> CandidateValidationBinding {
        CandidateValidationBinding {
            version: VALIDATION_BINDING_VERSION,
            agent_id: "agent-a".to_string(),
            primary_head: Some("1111111111111111111111111111111111111111".to_string()),
            agent_head: Some("2222222222222222222222222222222222222222".to_string()),
            merge_base: Some("1111111111111111111111111111111111111111".to_string()),
            diff_oid: "3333333333333333333333333333333333333333".to_string(),
        }
    }

    fn passed_test_validation_report() -> ValidationReport {
        ValidationReport {
            name: " unit ".to_string(),
            status: ValidationStatus::Passed,
            message: None,
            paths: vec![
                PathBuf::from("src/../README.md"),
                PathBuf::from("README.md"),
            ],
        }
    }

    #[test]
    fn exact_bound_validation_factory_canonicalizes_passed_evidence() {
        let binding = exact_test_validation_binding();

        let bound = ValidationEvidenceBundle::bound_to(
            binding.clone(),
            vec![passed_test_validation_report()],
        )
        .expect("construct exact bound evidence");

        assert_eq!(bound.binding(), &binding);
        assert_eq!(bound.evidence().groups.len(), 1);
        let group = &bound.evidence().groups[0];
        assert_eq!(group.binding.as_ref(), Some(&binding));
        assert_eq!(group.reports.len(), 1);
        assert_eq!(group.reports[0].name, "unit");
        assert_eq!(group.reports[0].paths, vec![PathBuf::from("README.md")]);
    }

    #[test]
    fn exact_bound_validation_factory_rejects_malformed_or_nonpassing_input() {
        assert!(
            ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), Vec::new())
                .expect_err("empty evidence must be refused")
                .to_string()
                .contains("at least one passed")
        );

        let mut malformed = exact_test_validation_binding();
        malformed.version = VALIDATION_BINDING_VERSION + 1;
        assert!(ValidationEvidenceBundle::bound_to(
            malformed,
            vec![passed_test_validation_report()]
        )
        .expect_err("malformed binding must be refused")
        .to_string()
        .contains("unsupported validation binding version"));

        let mut malformed_oid = exact_test_validation_binding();
        malformed_oid.diff_oid = "ABC".to_string();
        let malformed_oid_error = ValidationEvidenceBundle::bound_to(
            malformed_oid,
            vec![passed_test_validation_report()],
        )
        .expect_err("malformed binding OID must be refused");
        assert!(
            format!("{malformed_oid_error:#}").contains("canonical 40-character lowercase"),
            "unexpected error: {malformed_oid_error:#}"
        );

        let mut skipped = passed_test_validation_report();
        skipped.status = ValidationStatus::Skipped;
        assert!(
            ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![skipped])
                .expect_err("nonpassing report must be refused")
                .to_string()
                .contains("only passed validation reports")
        );

        let mut absolute = passed_test_validation_report();
        absolute.paths = vec![PathBuf::from("/private/result")];
        let absolute_error =
            ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![absolute])
                .expect_err("absolute evidence path must be refused");
        assert!(
            format!("{absolute_error:#}").contains("repository-relative"),
            "unexpected error: {absolute_error:#}"
        );
    }

    #[test]
    fn exact_bound_validation_upgrade_rejects_legacy_and_multiple_groups() {
        let report = passed_test_validation_report();
        assert!(ValidationEvidenceBundle::legacy(vec![report.clone()])
            .try_into_exact_bound()
            .expect_err("legacy evidence must not become bound")
            .to_string()
            .contains("legacy unbound"));

        let first = ValidationEvidenceBundle::bound_to(
            exact_test_validation_binding(),
            vec![report.clone()],
        )
        .expect("first bound evidence");
        let mut combined = first.evidence().clone();
        combined.extend(
            ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![report])
                .expect("second bound evidence")
                .evidence()
                .clone(),
        );
        assert!(combined
            .try_into_exact_bound()
            .expect_err("multi-group evidence must be refused")
            .to_string()
            .contains("exactly one bound group"));
    }

    fn create_managed_merge_fixture(
        root: &Path,
    ) -> (PathBuf, WorktreeManager, WorktreeRecord, WorktreeRecord) {
        let repo_path = root.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        let repo = Repository::open(&repo_path).expect("open repository");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repo);

        let manager = WorktreeManager::new(&repo_path);
        let agent_a = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-a worktree");
        let agent_b = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create agent-b worktree");
        (repo_path, manager, agent_a, agent_b)
    }

    fn create_semantic_merge_fixture(
        root: &Path,
        files: &[(&str, &str)],
    ) -> (PathBuf, WorktreeRecord) {
        let repo_path = root.join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        for (path, contents) in files {
            let path = repo_path.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create semantic fixture parent");
            }
            fs::write(path, contents).expect("write semantic fixture file");
        }
        let repo = Repository::open(&repo_path).expect("open repository");
        commit_all_for_semantic_test(&repo, "initial semantic fixture")
            .expect("commit semantic fixture");
        drop(repo);

        let manager = WorktreeManager::new(&repo_path);
        let agent = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create semantic agent worktree");
        (repo_path, agent)
    }

    fn commit_all_for_semantic_test(repo: &Repository, message: &str) -> Result<Oid> {
        let mut index = repo.index().context("open semantic fixture index")?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .context("stage semantic fixture")?;
        index.write().context("write semantic fixture index")?;
        let tree_id = index.write_tree().context("write semantic fixture tree")?;
        let tree = repo
            .find_tree(tree_id)
            .context("find semantic fixture tree")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .context("commit semantic fixture")
    }

    fn semantic_preview_options(repo_path: &Path, claim: &str) -> MergePreviewOptions {
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: repo_path.to_path_buf(),
                agent_id: "agent-a".to_string(),
                claimed_paths: vec![PathBuf::from(claim)],
                include_full_diff: false,
                diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            forces: MergeForceOptions::default(),
            require_validation: false,
        }
    }

    fn megafile_test_policy(
        block: bool,
        decomposition_target: Option<&str>,
    ) -> MegafileMergePolicy {
        MegafileMergePolicy {
            block,
            decomposition_target: decomposition_target.map(PathBuf::from),
            decomposition_run_id: None,
            thresholds: MegafileThresholds {
                calibration: MegafileThresholdCalibration::Configured,
                file_bytes: 1,
                collision_count: 1,
                ..MegafileThresholds::provisional_bootstrap()
            },
        }
    }

    fn seed_megafile(repo_path: &Path, policy: &MegafileMergePolicy) {
        MegafileStore::open_with_thresholds(repo_path, policy.thresholds.clone())
            .expect("open megafile store")
            .record_file_samples([FileSizeSample {
                path: PathBuf::from("README.md"),
                bytes: 7,
                lines: 1,
            }])
            .expect("seed megafile");
    }

    fn megafile_preview_options(
        repo_path: &Path,
        claims: Vec<PathBuf>,
        validations: Vec<ValidationReport>,
        require_validation: bool,
    ) -> MergePreviewOptions {
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: repo_path.to_path_buf(),
                agent_id: "agent-a".to_string(),
                claimed_paths: claims,
                include_full_diff: true,
                diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations,
            },
            forces: MergeForceOptions::default(),
            require_validation,
        }
    }

    fn newest_numeric_state_json(root: &Path) -> Option<PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut candidates = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).expect("read authenticated state directory") {
                let entry = entry.expect("state directory entry");
                let file_type = entry.file_type().expect("state entry type");
                let path = entry.path();
                if file_type.is_dir() {
                    pending.push(path);
                } else if file_type.is_file()
                    && path.extension().and_then(OsStr::to_str) == Some("json")
                    && path
                        .file_stem()
                        .and_then(OsStr::to_str)
                        .is_some_and(|stem| {
                            !stem.is_empty() && stem.bytes().all(|byte| byte.is_ascii_digit())
                        })
                {
                    candidates.push(path);
                }
            }
        }
        candidates.sort();
        candidates.pop()
    }

    #[test]
    fn megafile_policy_is_warn_only_by_default_and_reuses_typed_blocker_detail() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) =
            create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
        fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
        let policy = megafile_test_policy(false, None);
        seed_megafile(&repo_path, &policy);
        let validation = ValidationReport {
            name: "megafile-unit".to_string(),
            status: ValidationStatus::Passed,
            message: None,
            paths: vec![PathBuf::from("README.md")],
        };

        let warning = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &repo_path,
                vec![PathBuf::from("README.md")],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::legacy(vec![validation.clone()]),
            policy.clone(),
        )
        .expect("warn-only preview");
        assert_eq!(warning.safety.readiness.status, ApplyReadinessStatus::Safe);
        assert!(!warning.safety.megafile_blocking);
        assert_eq!(warning.safety.megafile_warnings.len(), 1);
        assert_eq!(
            warning.safety.megafile_warnings[0].path,
            PathBuf::from("README.md")
        );

        let blocked = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &repo_path,
                vec![PathBuf::from("README.md")],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::legacy(vec![validation]),
            MegafileMergePolicy {
                block: true,
                ..policy
            },
        )
        .expect("blocking preview");
        assert_eq!(
            blocked.safety.readiness.status,
            ApplyReadinessStatus::Blocked
        );
        let detail = blocked
            .safety
            .readiness
            .details
            .iter()
            .find(|detail| detail.kind == ApplyBlocker::ExcludedReference)
            .expect("megafile blocker detail");
        assert_eq!(detail.paths, vec![PathBuf::from("README.md")]);
        assert!(detail
            .message
            .as_deref()
            .is_some_and(|message| message.contains("threshold-crossing megafiles")));
        assert_eq!(detail.validation_reports[0].name, "megafile-unit");
        assert!(detail.validation_commands.is_empty());
        assert!(detail
            .next_safe_operation
            .as_deref()
            .is_some_and(|operation| operation.contains("megafile_decomposition assignment")));
    }

    #[test]
    fn decomposition_bypass_requires_finalized_evidence_and_diff_backed_structure() {
        let bare_temp = tempfile::tempdir().expect("bare tempdir");
        let (bare_repo, bare_agent) =
            create_semantic_merge_fixture(bare_temp.path(), &[("README.md", "# Test\n")]);
        fs::write(bare_agent.path.join("README.md"), "x\n").expect("shrink bare target");
        fs::create_dir_all(bare_agent.path.join("src")).expect("create bare replacement parent");
        fs::write(bare_agent.path.join("src/readme_part.md"), "part\n")
            .expect("write bare replacement");
        let bare_policy = megafile_test_policy(true, Some("README.md"));
        seed_megafile(&bare_repo, &bare_policy);
        let bare_error = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &bare_repo,
                vec![
                    PathBuf::from("README.md"),
                    PathBuf::from("src/readme_part.md"),
                ],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::default(),
            bare_policy,
        )
        .expect_err("bare decomposition target must not self-authorize");
        assert!(format!("{bare_error:#}").contains("requires a finalized supervise run id"));

        let grown_temp = tempfile::tempdir().expect("grown tempdir");
        let (grown_repo, grown_agent) =
            create_semantic_merge_fixture(grown_temp.path(), &[("README.md", "# Test\n")]);
        fs::write(
            grown_agent.path.join("README.md"),
            "# Candidate target grew\n",
        )
        .expect("grow target");
        fs::write(grown_agent.path.join("unrelated.txt"), "unrelated\n")
            .expect("write unrelated claimed file");
        let grown_run = RunId::new("grown-target-evidence").expect("grown run id");
        crate::supervise::write_test_finalized_megafile_decomposition_evidence(
            &grown_repo,
            grown_run.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("unrelated.txt")],
        )
        .expect("write grown evidence");
        let mut grown_policy = megafile_test_policy(true, Some("README.md"));
        grown_policy.decomposition_run_id = Some(grown_run);
        seed_megafile(&grown_repo, &grown_policy);
        let grown_error = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &grown_repo,
                vec![PathBuf::from("README.md"), PathBuf::from("unrelated.txt")],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::default(),
            grown_policy,
        )
        .expect_err("grown target plus unrelated file must not qualify");
        assert!(format!("{grown_error:#}").contains("did not shrink"));

        let existing_temp = tempfile::tempdir().expect("existing replacement tempdir");
        let (existing_repo, existing_agent) = create_semantic_merge_fixture(
            existing_temp.path(),
            &[
                ("README.md", "# Test target contents\n"),
                ("existing.md", "old\n"),
            ],
        );
        fs::write(existing_agent.path.join("README.md"), "x\n").expect("shrink target");
        fs::write(existing_agent.path.join("existing.md"), "modified\n")
            .expect("modify existing pseudo replacement");
        let existing_run = RunId::new("existing-replacement-evidence").expect("existing run id");
        crate::supervise::write_test_finalized_megafile_decomposition_evidence(
            &existing_repo,
            existing_run.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("existing.md")],
        )
        .expect("write existing replacement evidence");
        let mut existing_policy = megafile_test_policy(true, Some("README.md"));
        existing_policy.decomposition_run_id = Some(existing_run);
        seed_megafile(&existing_repo, &existing_policy);
        let existing_error = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &existing_repo,
                vec![PathBuf::from("README.md"), PathBuf::from("existing.md")],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::default(),
            existing_policy,
        )
        .expect_err("modified existing file must not qualify as a replacement");
        assert!(format!("{existing_error:#}").contains("is not newly added"));

        let empty_temp = tempfile::tempdir().expect("empty replacement tempdir");
        let (empty_repo, empty_agent) = create_semantic_merge_fixture(
            empty_temp.path(),
            &[("README.md", "# Test target contents\n")],
        );
        fs::write(empty_agent.path.join("README.md"), "x\n").expect("shrink empty-case target");
        fs::write(empty_agent.path.join("empty.md"), "").expect("write empty replacement");
        let empty_run = RunId::new("empty-replacement-evidence").expect("empty run id");
        crate::supervise::write_test_finalized_megafile_decomposition_evidence(
            &empty_repo,
            empty_run.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("empty.md")],
        )
        .expect("write empty replacement evidence");
        let mut empty_policy = megafile_test_policy(true, Some("README.md"));
        empty_policy.decomposition_run_id = Some(empty_run);
        seed_megafile(&empty_repo, &empty_policy);
        let empty_error = preview_merge_apply_with_megafile_policy(
            megafile_preview_options(
                &empty_repo,
                vec![PathBuf::from("README.md"), PathBuf::from("empty.md")],
                Vec::new(),
                false,
            ),
            ValidationEvidenceBundle::default(),
            empty_policy,
        )
        .expect_err("empty replacement must not qualify");
        assert!(format!("{empty_error:#}").contains("is empty"));
    }

    #[test]
    fn decomposition_completion_is_persisted_only_after_successful_merge() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) =
            create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
        fs::write(agent.path.join("README.md"), "x\n").expect("shrink target");
        fs::create_dir_all(agent.path.join("src")).expect("create replacement parent");
        fs::write(agent.path.join("src/readme_part.md"), "extracted\n").expect("write replacement");
        let run_id = RunId::new("accepted-decomposition").expect("run id");
        crate::supervise::write_test_finalized_megafile_decomposition_evidence(
            &repo_path,
            run_id.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("src/readme_part.md")],
        )
        .expect("write finalized decomposition evidence");
        let mut policy = megafile_test_policy(true, Some("README.md"));
        policy.decomposition_run_id = Some(run_id);
        seed_megafile(&repo_path, &policy);
        let claims = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];

        let blocked = merge_apply_report_with_megafile_policy(
            MergeApplyOptions {
                preview: megafile_preview_options(&repo_path, claims.clone(), Vec::new(), true),
                candidate_validation_commands: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            policy.clone(),
        )
        .expect("validation-blocked decomposition");
        assert_eq!(blocked.status, MergeApplyReportStatus::Blocked);
        assert!(blocked.accepted_decomposition.is_none());
        assert!(
            !MegafileStore::open_with_thresholds(&repo_path, policy.thresholds.clone())
                .expect("reopen store")
                .report()
                .expect("report before merge")
                .records
                .iter()
                .any(|record| matches!(
                    record.kind,
                    MegafileRecordKind::AcceptedDecomposition { .. }
                ))
        );

        let applied = merge_apply_report_with_megafile_policy(
            MergeApplyOptions {
                preview: megafile_preview_options(&repo_path, claims, Vec::new(), false),
                candidate_validation_commands: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            policy.clone(),
        )
        .expect("apply typed decomposition");
        assert_eq!(applied.status, MergeApplyReportStatus::Applied);
        assert_eq!(
            applied
                .accepted_decomposition
                .as_ref()
                .map(|assessment| assessment.accepted_decompositions),
            Some(1)
        );
        let records = MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
            .expect("reopen store after merge")
            .report()
            .expect("report after merge")
            .records;
        let accepted = records
            .iter()
            .filter_map(|record| match &record.kind {
                MegafileRecordKind::AcceptedDecomposition { replacement_paths } => {
                    Some(replacement_paths)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(accepted, vec![&vec![PathBuf::from("src/readme_part.md")]]);
    }

    #[test]
    fn decomposition_rejects_same_path_content_substitution_after_finalized_review() {
        for changed_file in ["target", "replacement"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let (repo_path, agent) =
                create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
            fs::write(agent.path.join("README.md"), "x\n").expect("shrink target");
            fs::create_dir_all(agent.path.join("src")).expect("create replacement parent");
            fs::write(agent.path.join("src/readme_part.md"), "reviewed\n")
                .expect("write reviewed replacement");
            let run_id =
                RunId::new(format!("content-substitution-{changed_file}")).expect("run id");
            crate::supervise::write_test_finalized_megafile_decomposition_evidence(
                &repo_path,
                run_id.clone(),
                "agent-a",
                "worker-a",
                PathBuf::from("README.md"),
                vec![PathBuf::from("src/readme_part.md")],
            )
            .expect("write content-bound finalized evidence");

            match changed_file {
                "target" => {
                    fs::write(agent.path.join("README.md"), "y\n")
                        .expect("substitute target bytes");
                }
                "replacement" => {
                    fs::write(agent.path.join("src/readme_part.md"), "substituted\n")
                        .expect("substitute replacement bytes");
                }
                _ => unreachable!(),
            }

            let mut policy = megafile_test_policy(true, Some("README.md"));
            policy.decomposition_run_id = Some(run_id);
            seed_megafile(&repo_path, &policy);
            let claims = vec![
                PathBuf::from("README.md"),
                PathBuf::from("src/readme_part.md"),
            ];
            let error = merge_apply_report_with_megafile_policy(
                MergeApplyOptions {
                    preview: megafile_preview_options(&repo_path, claims, Vec::new(), false),
                    candidate_validation_commands: Vec::new(),
                },
                ValidationEvidenceBundle::default(),
                policy.clone(),
            )
            .expect_err("post-review same-path content substitution must be rejected");
            assert!(
                format!("{error:#}").contains(
                    "current decomposition candidate content binding does not match the exact supervisor-inspected candidate"
                ),
                "unexpected {changed_file} substitution error: {error:#}"
            );
            assert!(
                !MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
                    .expect("reopen store after rejected substitution")
                    .report()
                    .expect("report after rejected substitution")
                    .records
                    .iter()
                    .any(|record| matches!(
                        record.kind,
                        MegafileRecordKind::AcceptedDecomposition { .. }
                    )),
                "{changed_file} substitution recorded decomposition completion"
            );
        }
    }

    #[test]
    fn collision_decision_is_persisted_without_weakening_merge_blockers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) =
            create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
        fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
        fs::write(repo_path.join("README.md"), "# Primary\n").expect("edit primary");
        let policy = megafile_test_policy(false, None);

        let report = merge_apply_report_with_megafile_policy(
            MergeApplyOptions {
                preview: megafile_preview_options(
                    &repo_path,
                    vec![PathBuf::from("README.md")],
                    Vec::new(),
                    false,
                ),
                candidate_validation_commands: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            policy.clone(),
        )
        .expect("blocked collision report");
        assert_eq!(report.status, MergeApplyReportStatus::Blocked);
        assert_eq!(
            report.recorded_collision_paths,
            vec![PathBuf::from("README.md")]
        );
        assert!(report
            .preview
            .safety
            .readiness
            .blockers
            .contains(&ApplyBlocker::DirtyPrimary));
        let assessment = MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
            .expect("open collision store")
            .assess_path("README.md")
            .expect("assess collision path")
            .expect("collision assessment");
        assert_eq!(assessment.collisions_in_window, 1);
    }

    #[test]
    fn authenticated_megafile_failure_refuses_merge_before_primary_mutation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) =
            create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
        fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
        let policy = megafile_test_policy(false, None);
        seed_megafile(&repo_path, &policy);
        let snapshot = newest_numeric_state_json(
            &repo_path.join(".git/maco/state/authenticated-megafile-history-v1"),
        )
        .expect("authenticated megafile snapshot");
        fs::write(snapshot, b"{\"tampered\":true}\n").expect("tamper authenticated snapshot");

        let error = merge_apply_report_with_megafile_policy(
            MergeApplyOptions {
                preview: megafile_preview_options(
                    &repo_path,
                    vec![PathBuf::from("README.md")],
                    Vec::new(),
                    false,
                ),
                candidate_validation_commands: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            policy,
        )
        .expect_err("tampered telemetry must refuse merge");
        assert!(format!("{error:#}").contains("authenticated megafile telemetry"));
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md")).expect("read primary"),
            "# Test\n"
        );
    }

    #[test]
    fn semantic_conflicts_report_same_function_and_dependent_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) = create_semantic_merge_fixture(
            temp.path(),
            &[
                ("src/lib.rs", "pub mod consumer;\npub mod shared;\n"),
                ("src/shared.rs", "pub fn compute() -> i32 {\n    1\n}\n"),
                (
                    "src/consumer.rs",
                    "use crate::shared::compute;\n\npub fn consume() -> i32 { compute() }\n",
                ),
            ],
        );
        fs::write(
            agent.path.join("src/shared.rs"),
            "pub fn compute() -> i32 {\n    2\n}\n",
        )
        .expect("edit candidate function");
        fs::write(
            repo_path.join("src/shared.rs"),
            "pub fn compute() -> i32 {\n    3\n}\n",
        )
        .expect("edit primary function");
        let primary = Repository::open(&repo_path).expect("open primary");
        commit_all_for_semantic_test(&primary, "change primary function")
            .expect("commit primary function");

        let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/shared.rs"))
            .expect("preview semantic conflict");
        let semantic = &preview.safety.semantic_conflicts;
        assert!(semantic.advisory);
        assert_eq!(
            semantic.status,
            SemanticConflictClassificationStatus::Classified
        );
        assert!(!semantic.degraded);
        assert_eq!(semantic.risk, SemanticConflictRisk::Medium);
        assert_eq!(
            semantic.conflict_paths,
            vec![PathBuf::from("src/shared.rs")]
        );
        let overlap = semantic.overlaps.first().expect("semantic overlap");
        assert_eq!(overlap.kind, SemanticConflictOverlapKind::SymbolLevel);
        assert!(overlap
            .common_symbols
            .iter()
            .any(|symbol| symbol.name == "compute"));
        assert!(overlap
            .impacted_files
            .contains(&PathBuf::from("src/consumer.rs")));
        assert_eq!(
            preview.safety.readiness.status,
            ApplyReadinessStatus::Blocked
        );
        assert!(preview
            .safety
            .readiness
            .blockers
            .contains(&ApplyBlocker::ApplyCheckFailed));
        let preview_json = serde_json::to_value(&preview).expect("serialize semantic preview");
        assert_eq!(
            preview_json["safety"]["semantic_conflicts"]["overlaps"][0]["kind"],
            "symbol_level"
        );

        let report = merge_apply_report(MergeApplyOptions {
            preview: semantic_preview_options(&repo_path, "src/shared.rs"),
            candidate_validation_commands: Vec::new(),
        })
        .expect("build blocked apply report");
        assert_eq!(report.status, MergeApplyReportStatus::Blocked);
        assert_eq!(
            report.preview.safety.semantic_conflicts.overlaps[0].kind,
            SemanticConflictOverlapKind::SymbolLevel
        );
        let report_json = serde_json::to_value(&report).expect("serialize semantic apply report");
        assert_eq!(
            report_json["preview"]["safety"]["semantic_conflicts"]["advisory"],
            true
        );
    }

    #[test]
    fn semantic_conflicts_classify_import_only_as_low_risk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) = create_semantic_merge_fixture(
            temp.path(),
            &[
                (
                    "src/lib.rs",
                    "use crate::alpha::item;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
                ),
                ("src/alpha.rs", "pub fn item() {}\npub fn renamed() {}\n"),
                ("src/beta.rs", "pub fn item() {}\n"),
            ],
        );
        fs::write(
            agent.path.join("src/lib.rs"),
            "use crate::beta::item;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
        )
        .expect("edit candidate import");
        fs::write(
            repo_path.join("src/lib.rs"),
            "use crate::alpha::renamed;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
        )
        .expect("edit primary import");
        let primary = Repository::open(&repo_path).expect("open primary");
        commit_all_for_semantic_test(&primary, "change primary import")
            .expect("commit primary import");

        let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/lib.rs"))
            .expect("preview import conflict");
        let semantic = &preview.safety.semantic_conflicts;
        assert_eq!(
            semantic.status,
            SemanticConflictClassificationStatus::Classified
        );
        assert!(!semantic.degraded);
        assert_eq!(semantic.risk, SemanticConflictRisk::Low);
        let overlap = semantic.overlaps.first().expect("import overlap");
        assert_eq!(overlap.kind, SemanticConflictOverlapKind::ImportOnly);
        assert_eq!(overlap.risk, SemanticConflictRisk::Low);
        assert!(overlap.primary.import_only);
        assert!(overlap.candidate.import_only);
        assert!(!overlap.primary.touched_imports.is_empty());
        assert!(!overlap.candidate.touched_imports.is_empty());
    }

    #[test]
    fn semantic_conflicts_report_signature_and_impl_overlap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) = create_semantic_merge_fixture(
            temp.path(),
            &[(
                "src/lib.rs",
                "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i32) -> i32 { value }\n}\n",
            )],
        );
        fs::write(
            agent.path.join("src/lib.rs"),
            "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i64) -> i32 { value as i32 }\n}\n",
        )
        .expect("edit candidate signature");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i32) -> i64 { value as i64 }\n}\n",
        )
        .expect("edit primary signature");
        let primary = Repository::open(&repo_path).expect("open primary");
        commit_all_for_semantic_test(&primary, "change primary signature")
            .expect("commit primary signature");

        let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/lib.rs"))
            .expect("preview signature conflict");
        let overlap = preview
            .safety
            .semantic_conflicts
            .overlaps
            .first()
            .expect("signature overlap");
        assert_eq!(overlap.kind, SemanticConflictOverlapKind::SignatureLevel);
        assert_eq!(overlap.risk, SemanticConflictRisk::High);
        assert!(overlap
            .common_symbols
            .iter()
            .any(|symbol| symbol.name == "run"));
        assert!(overlap
            .common_impls
            .iter()
            .any(|symbol| symbol.impl_target.as_deref() == Some("Worker")));
        assert!(overlap
            .common_modules
            .iter()
            .any(|module| module == "crate"));
    }

    #[test]
    fn semantic_conflicts_mark_unresolved_paths_as_degraded() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) = create_semantic_merge_fixture(
            temp.path(),
            &[
                ("README.md", "# Base\n"),
                ("src/lib.rs", "pub fn ok() {}\n"),
            ],
        );
        fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate readme");
        fs::write(repo_path.join("README.md"), "# Primary\n").expect("edit primary readme");
        let primary = Repository::open(&repo_path).expect("open primary");
        commit_all_for_semantic_test(&primary, "change primary readme")
            .expect("commit primary readme");

        let preview = preview_merge_apply(semantic_preview_options(&repo_path, "README.md"))
            .expect("preview unresolved conflict");
        let semantic = &preview.safety.semantic_conflicts;
        assert_eq!(
            semantic.status,
            SemanticConflictClassificationStatus::Degraded
        );
        assert!(semantic.degraded);
        assert_eq!(semantic.risk, SemanticConflictRisk::Unknown);
        assert_eq!(semantic.confidence, SemanticConflictConfidence::None);
        assert_eq!(
            semantic.overlaps[0].kind,
            SemanticConflictOverlapKind::Unresolved
        );
        assert!(!semantic.overlaps[0].notes.is_empty());
    }

    #[test]
    fn candidate_collection_holds_read_lease_until_snapshot_finishes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, agent_b) = create_managed_merge_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Agent change\n").expect("edit agent worktree");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let collector_repo = repo_path.clone();
        let collector = std::thread::spawn(move || {
            collect_agent_result_with_evidence_after_lease(
                MergeCollectOptions {
                    repo: collector_repo,
                    agent_id: "agent-a".to_string(),
                    claimed_paths: vec![PathBuf::from("README.md")],
                    include_full_diff: false,
                    diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                    validations: Vec::new(),
                },
                ValidationEvidenceBundle::default(),
                || {
                    ready_tx.send(()).expect("publish acquired read lease");
                    release_rx.recv().expect("release collector");
                },
            )
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("collector acquired read lease");
        let writer_error = manager
            .acquire_write_execution_lease("agent-a")
            .expect_err("collector read lease must exclude a writer");
        assert!(writer_error.to_string().contains("exclusive write lease"));
        let removal_error = manager
            .remove("agent-a", true, false)
            .expect_err("collector read lease must exclude removal");
        assert!(removal_error
            .to_string()
            .contains("active cooperative execution lease"));

        let unrelated = manager
            .acquire_write_execution_lease("agent-b")
            .expect("unrelated worktree writer remains available");
        assert_eq!(unrelated.path(), agent_b.path);
        drop(unrelated);

        release_tx.send(()).expect("release collector");
        let candidate = collector
            .join()
            .expect("join collector")
            .expect("collect candidate");
        assert_eq!(candidate.changed_paths, vec![PathBuf::from("README.md")]);
        let released = manager
            .acquire_write_execution_lease("agent-a")
            .expect("collector releases read lease after snapshot");
        drop(released);
        let removed = manager
            .remove("agent-a", true, false)
            .expect("collector releases removal authority after snapshot");
        assert!(!removed.path.exists());
    }

    #[test]
    fn required_process_output_rejects_unverified_side_effect_evidence() {
        let output = ProcessOutput {
            status: None,
            duration: Duration::ZERO,
            timed_out: false,
            process_tree: ContainmentEvidence::VerifiedEmpty(
                crate::process_runner::ContainmentBackend::DirectChild,
            ),
            side_effects: crate::process_runner::SideEffectConfinementEvidence::Unverified(
                crate::process_runner::SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            ),
            stdout: crate::process_runner::CapturedBytes::default(),
            stderr: crate::process_runner::CapturedBytes::default(),
            process_error: None,
            stdin_error: None,
        };

        let error = require_verified_process_output(
            "test command",
            &output,
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        )
        .unwrap_err();

        assert!(error.to_string().contains("without exact verified"));
    }

    #[test]
    fn required_network_output_rejects_even_verified_wrong_profile() {
        let output = ProcessOutput {
            status: None,
            duration: Duration::ZERO,
            timed_out: false,
            process_tree: ContainmentEvidence::VerifiedEmpty(
                crate::process_runner::ContainmentBackend::DirectChild,
            ),
            side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            ),
            stdout: crate::process_runner::CapturedBytes::default(),
            stderr: crate::process_runner::CapturedBytes::default(),
            process_error: None,
            stdin_error: None,
        };
        assert!(require_verified_process_output(
            "network test command",
            &output,
            SideEffectConfinementProfileKind::TrustedFixedNetwork,
        )
        .is_err());
    }

    #[test]
    fn trusted_network_environment_and_stdin_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let global_config = temp.path().join("global-config");
        write_private_file(&global_config, b"").expect("global config");
        let mut environment = minimal_network_environment().expect("minimal environment");
        environment.insert(
            "GIT_CONFIG_GLOBAL".to_string(),
            global_config.to_string_lossy().into_owned(),
        );
        validate_fixed_network_environment(&environment, temp.path())
            .expect("exact network environment");
        environment.insert(
            "HTTPS_PROXY".to_string(),
            "https://proxy.invalid".to_string(),
        );
        assert!(validate_fixed_network_environment(&environment, temp.path()).is_err());
        environment.remove("HTTPS_PROXY");

        let git = resolve_trusted_executable("git").expect("trusted git");
        assert!(validate_fixed_network_command(
            "network stdin test",
            &git,
            &[OsString::from("ls-remote")],
            temp.path(),
            &environment,
            &StdinMode::Inherit,
            Duration::from_secs(1),
            1024,
            0,
        )
        .is_err());
    }

    fn private_runtime_test_root(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().join("runtime");
        create_private_directory(&root).expect("create private runtime test root");
        root
    }

    fn rewrite_private_runtime_owner(path: &Path, owner: &PrivateRuntimeOwner) {
        let mut bytes = serde_json::to_vec(owner).expect("serialize private runtime owner");
        bytes.push(b'\n');
        let owner_path = owner.kind.owner_path(path);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&owner_path)
            .expect("open private runtime owner for rewrite");
        file.write_all(&bytes)
            .expect("rewrite private runtime owner");
        file.sync_all().expect("persist rewritten runtime owner");
    }

    fn private_runtime_owner_for_test(
        kind: PrivateRuntimeKind,
        nonce: &str,
    ) -> PrivateRuntimeOwner {
        PrivateRuntimeOwner {
            version: PRIVATE_RUNTIME_OWNER_VERSION,
            pid: std::process::id(),
            process_start: private_runtime_current_process_start_identity()
                .expect("current process identity"),
            boot_id: private_runtime_boot_id().expect("current boot identity"),
            created_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time")
                .as_secs(),
            kind,
            nonce: nonce.to_string(),
        }
    }

    fn create_incomplete_private_runtime(
        root: &Path,
        kind: PrivateRuntimeKind,
        nonce: &str,
        create_validation_git: bool,
        write_owner_temp: bool,
        publish_owner: bool,
    ) -> PathBuf {
        let owner = private_runtime_owner_for_test(kind, nonce);
        let path = root.join(format!("{}{}-{}", kind.prefix(), owner.pid, owner.nonce));
        reserve_owner_only_directory(&path).expect("reserve incomplete private runtime");
        let owner_path = kind.owner_path(&path);
        let parent = owner_path.parent().expect("owner parent");
        if create_validation_git && kind == PrivateRuntimeKind::CandidateValidation {
            create_private_directory(parent).expect("create incomplete validation gitdir");
        }
        if write_owner_temp || publish_owner {
            if kind == PrivateRuntimeKind::CandidateValidation && !parent.exists() {
                create_private_directory(parent).expect("create owner parent");
            }
            let mut bytes = serde_json::to_vec(&owner).expect("serialize owner");
            bytes.push(b'\n');
            let temporary = parent.join(format!(".{PRIVATE_RUNTIME_OWNER_FILE}.{nonce}.tmp"));
            write_private_file(&temporary, &bytes).expect("write owner temp");
            if publish_owner {
                fs::rename(&temporary, &owner_path).expect("publish owner");
            }
        }
        path
    }

    #[test]
    fn successful_status_cannot_bypass_nonverified_containment_seam() {
        let error = require_verified_containment(
            "synthetic successful command",
            ContainmentEvidence::TrustedBestEffort(
                crate::process_runner::ContainmentBackend::UnixProcessGroup,
            ),
        )
        .expect_err("non-verified containment must be rejected");
        assert!(error.to_string().contains("without verified-empty"));
    }

    #[test]
    fn candidate_validation_total_deadline_returns_failed_report() {
        let temp = tempfile::tempdir().expect("tempdir");
        let started = std::time::Instant::now();
        let report = run_candidate_validation_command_with_timeout(
            temp.path(),
            &temp.path().join("validation-environment"),
            &CandidateValidationCommand {
                command: "sleep 2".to_string(),
            },
            0,
            &[PathBuf::from("README.md")],
            Duration::from_millis(100),
        );
        assert_eq!(report.status, ValidationStatus::Failed);
        assert_eq!(report.paths, vec![PathBuf::from("README.md")]);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(report
            .message
            .as_deref()
            .is_some_and(|message| message.contains("deadline") || message.contains("timed out")));
    }

    #[test]
    fn candidate_validation_clears_shell_startup_and_private_network_environment() {
        let _environment_guard = VALIDATION_ENVIRONMENT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temp = tempfile::tempdir().expect("tempdir");
        let bash_startup = temp.path().join("bash-startup");
        let sh_startup = temp.path().join("sh-startup");
        let marker = temp.path().join("startup-ran");
        fs::write(
            &bash_startup,
            format!("printf injected > '{}'\n", marker.display()),
        )
        .expect("write bash startup");
        fs::write(
            &sh_startup,
            format!("printf injected > '{}'\n", marker.display()),
        )
        .expect("write sh startup");
        let old_bash_env = env::var_os("BASH_ENV");
        let old_env = env::var_os("ENV");
        let old_token = env::var_os("OPENAI_API_KEY");
        // SAFETY: these tests restore the process environment before returning and the values are
        // used only to verify the child allowlist. The test suite does not otherwise rely on them.
        unsafe {
            env::set_var("BASH_ENV", &bash_startup);
            env::set_var("ENV", &sh_startup);
            env::set_var("OPENAI_API_KEY", "validation-secret-value");
        }
        let command = if cfg!(unix) {
            "bash -c 'test -z \"$OPENAI_API_KEY\" && test -z \"$BASH_ENV\" && test -z \"$ENV\"'"
        } else {
            "exit 0"
        };
        let report = run_candidate_validation_command_with_timeout(
            temp.path(),
            &temp.path().join("validation-environment"),
            &CandidateValidationCommand {
                command: command.to_string(),
            },
            0,
            &[],
            Duration::from_secs(10),
        );
        // SAFETY: restore the exact previous process environment values.
        unsafe {
            restore_test_environment("BASH_ENV", old_bash_env);
            restore_test_environment("ENV", old_env);
            restore_test_environment("OPENAI_API_KEY", old_token);
        }
        assert_eq!(report.status, ValidationStatus::Passed, "{report:?}");
        assert!(!marker.exists(), "shell startup injection must not execute");
    }

    #[test]
    fn candidate_validation_redacts_registered_private_output() {
        let _environment_guard = VALIDATION_ENVIRONMENT_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temp = tempfile::tempdir().expect("tempdir");
        let old_secret = env::var_os("MACO_VALIDATION_TEST_SECRET");
        let old_openai_key = env::var_os("OPENAI_API_KEY");
        let old_aws_key = env::var_os("AWS_ACCESS_KEY_ID");
        // SAFETY: the environment value is scoped to this test and restored below.
        unsafe {
            env::set_var(
                "MACO_VALIDATION_TEST_SECRET",
                "candidate-validation-super-secret",
            );
            env::set_var("OPENAI_API_KEY", "openai-validation-private-key");
            env::set_var("AWS_ACCESS_KEY_ID", "aws-validation-access-key");
        }
        let report = run_candidate_validation_command_with_timeout(
            temp.path(),
            &temp.path().join("validation-environment"),
            &CandidateValidationCommand {
                command: "printf '%s %s %s\\n' candidate-validation-super-secret openai-validation-private-key aws-validation-access-key >&2; exit 1".to_string(),
            },
            0,
            &[PathBuf::from("README.md")],
            Duration::from_secs(10),
        );
        // SAFETY: restore the exact previous process environment value.
        unsafe {
            restore_test_environment("MACO_VALIDATION_TEST_SECRET", old_secret);
            restore_test_environment("OPENAI_API_KEY", old_openai_key);
            restore_test_environment("AWS_ACCESS_KEY_ID", old_aws_key);
        }
        let message = report.message.expect("failed validation message");
        assert_eq!(report.status, ValidationStatus::Failed);
        assert!(!message.contains("candidate-validation-super-secret"));
        assert!(!message.contains("openai-validation-private-key"));
        assert!(!message.contains("aws-validation-access-key"));
        assert!(message.contains("<redacted:validation-private-env>"));
    }

    #[test]
    fn repository_index_digest_rejects_oversized_file_before_reading() {
        let temp = tempfile::tempdir().expect("tempdir");
        let index = temp.path().join("index");
        let file = fs::File::create(&index).expect("create sparse index");
        file.set_len(REPOSITORY_INDEX_MAX_BYTES + 1)
            .expect("size sparse index");

        let error = hash_optional_file(&index).expect_err("oversized index must fail closed");

        assert!(error.to_string().contains("bounded real regular file"));
    }

    unsafe fn restore_test_environment(key: &str, value: Option<OsString>) {
        match value {
            Some(value) => {
                // SAFETY: caller guarantees serialized restoration of the test process environment.
                unsafe { env::set_var(key, value) }
            }
            None => {
                // SAFETY: caller guarantees serialized restoration of the test process environment.
                unsafe { env::remove_var(key) }
            }
        }
    }

    #[test]
    fn candidate_capture_quota_rejects_oversized_changed_file_before_git_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(temp.path()).expect("init repo");
        let oversized = temp.path().join("oversized.bin");
        let file = fs::File::create(&oversized).expect("create oversized file");
        file.set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
            .expect("size oversized file");

        let error = snapshot_worktree_candidate(&repo, temp.path(), None)
            .expect_err("oversized candidate must fail");

        assert!(error.to_string().contains("single-file limit"));
    }

    fn passed_validation_evidence_check() -> ValidationEvidenceCheck {
        ValidationEvidenceCheck {
            status: SafetyCheckStatus::Passed,
            binding_status: ValidationBindingStatus::Bound,
            message: None,
            paths: Vec::new(),
        }
    }

    #[test]
    fn classifies_unclaimed_paths_by_repo_relative_claim_coverage() {
        let changed = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src/nested/mod.rs"),
            PathBuf::from("tests/smoke.rs"),
        ];
        let claims = vec![PathBuf::from("README.md"), PathBuf::from("src")];

        assert_eq!(
            unclaimed_paths(&changed, &claims),
            vec![PathBuf::from("tests/smoke.rs")]
        );
    }

    #[test]
    fn normalizes_and_collapses_claim_paths() {
        let paths = normalize_claim_paths(vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src"),
            PathBuf::from("README.md"),
            PathBuf::from("src/../README.md"),
        ])
        .expect("normalize paths");

        assert_eq!(
            paths,
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );
    }

    #[test]
    fn candidate_capture_retries_until_two_complete_snapshots_match() {
        let mut captures = vec![Some(1_u8), Some(2), Some(3), Some(3)].into_iter();

        let captured = capture_two_matching(|| Ok(captures.next().flatten()))
            .expect("capture should stabilize");

        assert_eq!(captured, 3);
    }

    #[test]
    fn candidate_capture_fails_closed_after_bounded_instability() {
        let mut captures =
            vec![Some(1_u8), Some(2), Some(1), Some(2), Some(1), Some(2)].into_iter();

        let error = capture_two_matching(|| Ok(captures.next().flatten()))
            .expect_err("capture should remain unstable");

        assert!(error.to_string().contains("state changed"));
    }

    #[test]
    fn safety_classification_blocks_unforced_failures() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: vec![PathBuf::from("README.md")],
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &failed,
            stale_base: &passed,
            apply_check: &passed,
            unclaimed_edits: &failed,
            validation: &passed,
            validation_evidence: &evidence,
            megafile: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(checks, &MergeForceOptions::default());

        assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
        assert_eq!(
            readiness.blockers,
            vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::UnclaimedEdits]
        );
        assert!(readiness.forced.is_empty());
        assert_eq!(readiness.details.len(), 2);
        assert_eq!(readiness.details[0].kind, ApplyBlocker::DirtyPrimary);
        assert_eq!(
            readiness.details[0].disposition,
            ApplyBlockerDisposition::Blocked
        );
        assert_eq!(readiness.details[0].check_status, SafetyCheckStatus::Failed);
        assert_eq!(readiness.details[0].paths, vec![PathBuf::from("README.md")]);
    }

    #[test]
    fn safety_classification_marks_allowed_risks_as_forced() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: Vec::new(),
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &failed,
            stale_base: &failed,
            apply_check: &passed,
            unclaimed_edits: &passed,
            validation: &passed,
            validation_evidence: &evidence,
            megafile: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(
            checks,
            &MergeForceOptions {
                allow_dirty_primary: true,
                allow_stale_base: true,
                ..MergeForceOptions::default()
            },
        );

        assert_eq!(readiness.status, ApplyReadinessStatus::Forced);
        assert!(readiness.blockers.is_empty());
        assert_eq!(
            readiness.forced,
            vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::StaleBase]
        );
        assert_eq!(
            readiness.details[0].disposition,
            ApplyBlockerDisposition::Forced
        );
    }

    #[test]
    fn apply_check_failures_are_not_forceable_by_policy_flags() {
        let failed = SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: None,
            paths: Vec::new(),
        };
        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let evidence = passed_validation_evidence_check();
        let checks = SafetyChecks {
            primary_state_unchanged: &passed,
            dirty_primary: &passed,
            stale_base: &passed,
            apply_check: &failed,
            unclaimed_edits: &passed,
            validation: &passed,
            validation_evidence: &evidence,
            megafile: &passed,
            validations: &[],
            require_validation: false,
            validation_commands: &[],
            validation_related_paths: &[],
        };

        let readiness = classify_apply_safety(
            checks,
            &MergeForceOptions {
                allow_apply_conflicts: true,
                ..MergeForceOptions::default()
            },
        );

        assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
        assert_eq!(readiness.blockers, vec![ApplyBlocker::ApplyCheckFailed]);
    }

    #[test]
    fn repo_common_lock_persists_file_and_kernel_unlocks_on_drop() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let lock = RepoCommonLock::acquire(&repo_path, "merge-apply").expect("acquire lock");
        let path = repo_path
            .join(".git/maco/state")
            .join(REPOSITORY_MUTATION_LOCK_FILE);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open stable lock file");
        assert!(matches!(
            contender.try_lock().expect_err("kernel lock must contend"),
            fs::TryLockError::WouldBlock
        ));

        drop(lock);
        contender.try_lock().expect("kernel lock released on drop");
        contender.unlock().expect("unlock contender");

        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            for directory in [
                repo_path.join(".git/maco"),
                repo_path.join(".git/maco/state"),
            ] {
                assert_eq!(
                    fs::metadata(directory)
                        .expect("managed directory metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
        }
    }

    #[test]
    fn initialized_repository_fingerprint_ignores_ignored_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(temp.path()).expect("init repo");
        fs::write(temp.path().join(".gitignore"), "ignored/\n").expect("write ignore");
        fs::write(temp.path().join("tracked.txt"), "tracked\n").expect("write tracked");
        let mut index = repo.index().expect("open index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("add files");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit");

        let before = validation_repository_fingerprint(&repo, temp.path(), None, 0)
            .expect("baseline fingerprint");
        fs::create_dir(temp.path().join("ignored")).expect("create ignored output");
        fs::write(
            temp.path().join("ignored/build.bin"),
            vec![7_u8; 1024 * 1024],
        )
        .expect("write ignored output");
        let after = validation_repository_fingerprint(&repo, temp.path(), None, 0)
            .expect("updated fingerprint");

        assert_eq!(before, after);
    }

    #[test]
    fn initialized_submodule_marker_directory_is_not_recursively_hashed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join(".git");
        fs::create_dir(&marker).expect("create marker directory");
        let large = fs::File::create(marker.join("large-object")).expect("create large object");
        large
            .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
            .expect("size large object");

        let fingerprint = validation_submodule_marker_fingerprint(&marker)
            .expect("fingerprint marker identity only");

        assert_eq!(fingerprint.entries.len(), 1);
        assert_eq!(
            fingerprint.entries[0].kind,
            ValidationFilesystemEntryKind::Directory
        );
    }

    #[test]
    fn uninitialized_submodule_raw_fingerprint_fails_with_typed_size_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let large = fs::File::create(temp.path().join("large.bin")).expect("create large file");
        large
            .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
            .expect("size large file");

        let error = validation_filesystem_fingerprint(temp.path())
            .expect_err("oversized raw fallback must fail closed");

        assert!(matches!(
            error.downcast_ref::<ValidationFilesystemFingerprintError>(),
            Some(ValidationFilesystemFingerprintError::SingleFileTooLarge { .. })
        ));
    }

    #[test]
    fn candidate_validation_sandbox_is_removed_when_patch_apply_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir(&repo_path).expect("create repo dir");
        let repo = Repository::init(&repo_path).expect("init repo");
        fs::write(repo_path.join("README.md"), "# Smoke\n").expect("write readme");
        let mut index = repo.index().expect("open index");
        index.add_path(Path::new("README.md")).expect("add readme");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("create signature");
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial commit",
            &tree,
            &[],
        )
        .expect("commit");

        let passed = SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        };
        let preview = MergeApplyPreview {
            candidate: MergeCandidate {
                metadata: WorktreeMergeMetadata {
                    agent_id: "agent-a".to_string(),
                    worktree_path: repo_path.clone(),
                    branch: "maco/agent-a".to_string(),
                    primary_repo_root: repo_path.clone(),
                    primary_head: None,
                    agent_head: None,
                    merge_base: None,
                    base_matches_primary: Some(true),
                },
                claimed_paths: vec![PathBuf::from("README.md")],
                changed_paths: vec![PathBuf::from("README.md")],
                changes: vec![ChangedPath {
                    path: PathBuf::from("README.md"),
                    kind: ChangeKind::Modified,
                }],
                unclaimed_changed_paths: Vec::new(),
                diff: DiffOutput {
                    summary: OutputSummary {
                        text: "invalid patch".to_string(),
                        truncated: false,
                    },
                    full: Some("this is not a patch\n".to_string()),
                },
                validations: Vec::new(),
                validation_binding: CandidateValidationBinding {
                    version: VALIDATION_BINDING_VERSION,
                    agent_id: "agent-a".to_string(),
                    primary_head: None,
                    agent_head: None,
                    merge_base: None,
                    diff_oid: Oid::hash_object(ObjectType::Blob, b"this is not a patch\n")
                        .expect("hash invalid patch")
                        .to_string(),
                },
                validation_evidence: ValidationEvidenceBundle::default(),
                raw_diff: b"this is not a patch\n".to_vec(),
                snapshot_tree: tree_id,
            },
            safety: MergeApplySafety {
                primary_state_unchanged: passed.clone(),
                dirty_primary: passed.clone(),
                stale_base: passed.clone(),
                apply_check: passed.clone(),
                unclaimed_edits: passed.clone(),
                validation: passed,
                validation_evidence: passed_validation_evidence_check(),
                megafile: SafetyCheck {
                    status: SafetyCheckStatus::Passed,
                    message: None,
                    paths: Vec::new(),
                },
                megafile_warnings: Vec::new(),
                megafile_decomposition_target: None,
                megafile_decomposition_evidence: None,
                megafile_blocking: false,
                validation_required: false,
                candidate_validation_commands: Vec::new(),
                force_options: MergeForceOptions::default(),
                apply_mode: ApplyMode::Direct,
                semantic_conflicts: SemanticConflictClassification::no_conflict(),
                readiness: ApplyReadiness {
                    status: ApplyReadinessStatus::Safe,
                    blockers: Vec::new(),
                    forced: Vec::new(),
                    details: Vec::new(),
                },
            },
        };

        let result = CandidateValidationSandbox::create(&preview);

        assert!(result.is_err());
        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .expect("list worktrees");
        assert!(output.status.success());
        let worktrees = String::from_utf8_lossy(&output.stdout);
        assert!(
            !worktrees.contains("maco-candidate-validation-"),
            "{worktrees}"
        );
    }

    #[test]
    fn truncates_output_by_char_boundary() {
        let summary = summarize_text("aé日b", 3);

        assert_eq!(summary.text, "aé日");
        assert!(summary.truncated);

        let untruncated = summarize_text("abc", 3);
        assert_eq!(untruncated.text, "abc");
        assert!(!untruncated.truncated);
    }

    #[test]
    fn native_executable_magic_accepts_thin_and_fat_macho() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            assert!(is_native_executable_magic(magic));
        }
        assert!(!is_native_executable_magic(*b"#!/b"));
    }

    #[test]
    fn network_environment_classifies_command_execution_overrides_as_injection() {
        for key in [
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_PROXY_COMMAND",
            "GIT_CURL_VERBOSE",
        ] {
            assert!(is_git_injection_environment_key(key), "missed {key}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_executable_validation_rejects_user_owned_path_shadow() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let shadow = temp.path().join("git");
        fs::write(&shadow, b"\x7fELFfake").expect("write shadow");
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o755)).expect("chmod shadow");

        assert!(validate_trusted_unix_executable(&shadow).is_err());
        assert!(resolve_trusted_executable("git").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_executable_candidates_exclude_direct_nix_store_path_entries() {
        let candidates = trusted_executable_entry_candidates("git");
        assert_eq!(
            candidates,
            [
                PathBuf::from("/run/current-system/sw/bin/git"),
                PathBuf::from("/usr/bin/git"),
                PathBuf::from("/bin/git"),
            ]
        );
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.starts_with("/nix/store")));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_runtime_is_owner_only_and_ignores_ambient_temp_paths() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().expect("repo tempdir");
        let runtime = trusted_runtime_root(temp.path()).expect("trusted runtime");
        let metadata = fs::symlink_metadata(&runtime).expect("runtime metadata");
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(!runtime.starts_with(temp.path()));
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_all_kinds_publish_owner_retain_live_and_reuse_lock_inode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let mut lock_inode = None;
        for kind in [
            PrivateRuntimeKind::CandidateCapture,
            PrivateRuntimeKind::CandidateValidation,
            PrivateRuntimeKind::PublicationGit,
            PrivateRuntimeKind::GhConfig,
        ] {
            let runtime =
                PrivateRuntimeDirectory::create_in_root(&root, kind).expect("create runtime");
            let owner_path = kind.owner_path(runtime.path());
            let owner_metadata = fs::symlink_metadata(&owner_path).expect("owner metadata");
            assert_eq!(owner_metadata.permissions().mode() & 0o777, 0o600);
            let (owner, _) =
                read_private_runtime_owner(runtime.path(), kind).expect("read runtime owner");
            assert_eq!(owner.kind, kind);
            assert_eq!(owner.pid, std::process::id());
            if kind == PrivateRuntimeKind::CandidateValidation {
                assert_eq!(
                    owner_path.parent(),
                    Some(runtime.path().join(".git").as_path())
                );
            } else {
                assert_eq!(owner_path.parent(), Some(runtime.path()));
            }

            let report = scavenge_private_runtime_orphans(&root).expect("scan live runtime");
            assert_eq!(
                report,
                PrivateRuntimeScavengeReport {
                    removed: 0,
                    retained: 0,
                }
            );
            assert!(runtime.path().exists());
            let path = runtime.path().to_path_buf();
            drop(runtime);
            assert!(!path.exists());

            let lock = fs::symlink_metadata(root.join(PRIVATE_RUNTIME_LOCK_FILE))
                .expect("persistent runtime lock");
            assert_eq!(lock.nlink(), 1);
            match lock_inode {
                Some(inode) => assert_eq!(lock.ino(), inode),
                None => lock_inode = Some(lock.ino()),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_root_lock_serializes_concurrent_creators() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let held = PrivateRuntimeRootLock::acquire(&root).expect("hold runtime lock");
        let (sender, receiver) = std::sync::mpsc::channel();
        let child_root = root.clone();
        let worker = std::thread::spawn(move || {
            let result = PrivateRuntimeDirectory::create_in_root(
                &child_root,
                PrivateRuntimeKind::CandidateCapture,
            )
            .map(|runtime| {
                let path = runtime.path().to_path_buf();
                drop(runtime);
                path
            });
            sender.send(result).expect("send creator result");
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(150)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        let path = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("creator completed after unlock")
            .expect("creator result");
        worker.join().expect("join creator");
        assert!(!path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_runtime_scavenger_reclaims_reused_and_missing_pid_but_retains_live_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);

        let live =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
                .expect("create live runtime");
        let live_path = live.path().to_path_buf();
        let report = scavenge_private_runtime_orphans(&root).expect("scan live owner");
        assert_eq!(report.removed, 0);
        assert!(live_path.exists());

        let reused =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::PublicationGit)
                .expect("create reused PID fixture");
        let reused_path = reused.path().to_path_buf();
        let mut reused_owner = reused.owner.clone();
        let Some(ProcessStartIdentity::LinuxProcStartTicks(start)) =
            reused_owner.process_start.as_mut()
        else {
            panic!("Linux owner omitted start ticks");
        };
        *start = start.saturating_add(1);
        rewrite_private_runtime_owner(&reused_path, &reused_owner);
        let report = scavenge_private_runtime_orphans(&root).expect("reclaim reused PID owner");
        assert_eq!(report.removed, 1);
        assert!(!reused_path.exists());

        let missing = PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::GhConfig)
            .expect("create missing PID fixture");
        let missing_path = missing.path().to_path_buf();
        let report = scavenge_private_runtime_orphans_with(
            &root,
            private_runtime_boot_id().expect("boot id").as_deref(),
            |_| Ok(None),
        )
        .expect("reclaim missing PID owner");
        assert_eq!(report.removed, 2);
        assert!(!missing_path.exists());
        assert!(!live_path.exists());
        std::mem::forget((live, reused, missing));
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_scavenger_retains_corrupt_unknown_and_unverifiable_entries_per_directory() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let corrupt =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
                .expect("create corrupt fixture");
        let corrupt_path = corrupt.path().to_path_buf();
        fs::write(
            PrivateRuntimeKind::CandidateCapture.owner_path(&corrupt_path),
            b"{broken",
        )
        .expect("corrupt owner");
        std::mem::forget(corrupt);

        let unknown = root.join("maco-publication-git-not-a-valid-reservation");
        create_private_directory(&unknown).expect("create unknown managed entry");
        let mut non_utf8_name = PrivateRuntimeKind::CandidateValidation
            .prefix()
            .as_bytes()
            .to_vec();
        non_utf8_name.extend_from_slice(b"1-20000-0-");
        non_utf8_name.push(0xff);
        let non_utf8 = root.join(OsString::from_vec(non_utf8_name));
        create_private_directory(&non_utf8).expect("create non-UTF-8 managed entry");
        let unverifiable =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::GhConfig)
                .expect("create unverifiable fixture");
        let unverifiable_path = unverifiable.path().to_path_buf();
        std::mem::forget(unverifiable);

        let report = scavenge_private_runtime_orphans_with(
            &root,
            private_runtime_boot_id().expect("boot id").as_deref(),
            |_| bail!("synthetic identity lookup failure"),
        )
        .expect("per-directory failures must not abort bounded scan");
        assert_eq!(report.removed, 0);
        assert_eq!(report.retained, 4);
        assert!(corrupt_path.exists());
        assert!(unknown.exists());
        assert!(non_utf8.exists());
        assert!(unverifiable_path.exists());

        let fresh =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateValidation)
                .expect("retained entries must not globally block a fresh reservation");
        assert!(fresh.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_scavenger_recovers_each_owner_publication_crash_point() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let kinds = [
            PrivateRuntimeKind::CandidateCapture,
            PrivateRuntimeKind::CandidateValidation,
            PrivateRuntimeKind::PublicationGit,
            PrivateRuntimeKind::GhConfig,
        ];
        let mut paths = Vec::new();
        for (kind_index, kind) in kinds.into_iter().enumerate() {
            paths.push(create_incomplete_private_runtime(
                &root,
                kind,
                &format!("{}-0", 10_000 + kind_index),
                false,
                false,
                false,
            ));
            if kind == PrivateRuntimeKind::CandidateValidation {
                paths.push(create_incomplete_private_runtime(
                    &root, kind, "11000-0", true, false, false,
                ));
            }
            paths.push(create_incomplete_private_runtime(
                &root,
                kind,
                &format!("{}-1", 12_000 + kind_index),
                kind == PrivateRuntimeKind::CandidateValidation,
                true,
                false,
            ));
            paths.push(create_incomplete_private_runtime(
                &root,
                kind,
                &format!("{}-2", 13_000 + kind_index),
                kind == PrivateRuntimeKind::CandidateValidation,
                true,
                true,
            ));
        }
        let report = scavenge_private_runtime_orphans_with(
            &root,
            private_runtime_boot_id().expect("boot id").as_deref(),
            |_| Ok(None),
        )
        .expect("recover interrupted reservations");
        assert_eq!(report.removed, paths.len());
        assert_eq!(report.retained, 0);
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_runtime_parent_sigkill_residue_is_reclaimed_on_next_entry() {
        const CHILD_ROOT: &str = "MACO_TEST_PRIVATE_RUNTIME_CHILD_ROOT";
        const CHILD_READY: &str = "MACO_TEST_PRIVATE_RUNTIME_CHILD_READY";
        if let (Some(root), Some(ready)) = (env::var_os(CHILD_ROOT), env::var_os(CHILD_READY)) {
            let runtime = PrivateRuntimeDirectory::create_in_root(
                Path::new(&root),
                PrivateRuntimeKind::CandidateCapture,
            )
            .expect("child creates private runtime");
            fs::write(&ready, runtime.path().as_os_str().as_encoded_bytes())
                .expect("publish child runtime path");
            loop {
                std::thread::park_timeout(Duration::from_secs(60));
            }
        }

        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let ready = temp.path().join("ready");
        let executable = env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "merge::tests::private_runtime_parent_sigkill_residue_is_reclaimed_on_next_entry",
                "--nocapture",
            ])
            .env(CHILD_ROOT, &root)
            .env(CHILD_READY, &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn private runtime crash child");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "private runtime crash child did not publish its path"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let path = PathBuf::from(OsString::from_vec(
            fs::read(&ready).expect("read child runtime path"),
        ));
        assert!(path.exists());
        // SAFETY: child.id identifies the live subprocess created above.
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGKILL) }, 0);
        child.wait().expect("reap crash child");
        let report = scavenge_private_runtime_orphans(&root).expect("reclaim crashed owner");
        assert_eq!(report.removed, 1);
        assert_eq!(report.retained, 0);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_fd_cleanup_never_follows_symlink_or_hardlink_outside_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let outside = temp.path().join("outside");
        create_private_directory(&outside).expect("create outside directory");
        let marker = outside.join("marker");
        fs::write(&marker, "preserve\n").expect("write outside marker");
        let hardlink_target = outside.join("hardlink-target");
        fs::write(&hardlink_target, "preserve hardlink\n").expect("write hardlink target");

        let runtime =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
                .expect("create stale runtime");
        let runtime_path = runtime.path().to_path_buf();
        symlink(&outside, runtime_path.join("escape")).expect("create escape symlink");
        fs::hard_link(&hardlink_target, runtime_path.join("hardlink"))
            .expect("create outside hardlink");
        std::mem::forget(runtime);
        let report = scavenge_private_runtime_orphans_with(
            &root,
            private_runtime_boot_id().expect("boot id").as_deref(),
            |_| Ok(None),
        )
        .expect("reclaim runtime containing links");
        assert_eq!(report.removed, 1);
        assert_eq!(
            fs::read_to_string(&marker).expect("outside marker"),
            "preserve\n"
        );
        assert_eq!(
            fs::read_to_string(&hardlink_target).expect("outside hardlink target"),
            "preserve hardlink\n"
        );

        let top_level = root.join(format!(
            "{}{}-14000-0",
            PrivateRuntimeKind::GhConfig.prefix(),
            std::process::id()
        ));
        symlink(&outside, &top_level).expect("create top-level managed symlink");
        let report = scavenge_private_runtime_orphans(&root).expect("retain top-level symlink");
        assert_eq!(report.retained, 1);
        assert!(top_level.symlink_metadata().is_ok());
        assert!(marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_fd_cleanup_race_never_escapes_managed_directory() {
        use std::{
            os::unix::fs::symlink,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
        };

        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        let outside = temp.path().join("outside-race");
        create_private_directory(&outside).expect("create outside race directory");
        let marker = outside.join("marker");
        fs::write(&marker, "outside survives\n").expect("write outside race marker");

        let runtime =
            PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
                .expect("create race runtime");
        let runtime_path = runtime.path().to_path_buf();
        let race = runtime_path.join("race");
        let holding = runtime_path.join("holding");
        create_private_directory(&race).expect("create raced child");
        fs::write(race.join("inside"), "inside\n").expect("write raced child content");
        std::mem::forget(runtime);

        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_outside = outside.clone();
        let worker = std::thread::spawn(move || {
            while worker_running.load(Ordering::Acquire) {
                if fs::rename(&race, &holding).is_ok() {
                    if symlink(&worker_outside, &race).is_ok() {
                        std::thread::yield_now();
                        let _ = fs::remove_file(&race);
                    }
                    let _ = fs::rename(&holding, &race);
                } else {
                    std::thread::yield_now();
                }
            }
        });
        let report = scavenge_private_runtime_orphans_with(
            &root,
            private_runtime_boot_id().expect("boot id").as_deref(),
            |_| Ok(None),
        )
        .expect("race cleanup remains bounded");
        running.store(false, Ordering::Release);
        worker.join().expect("join race worker");
        assert_eq!(report.removed + report.retained, 1);
        assert_eq!(
            fs::read_to_string(&marker).expect("outside race marker"),
            "outside survives\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_scan_entry_and_tree_depth_bounds_fail_before_deletion() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        };

        let temp = tempfile::tempdir().expect("tempdir");
        let root = private_runtime_test_root(&temp);
        for index in 0..=PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES {
            let path = root.join(format!(
                "{}{}-{}-0",
                PrivateRuntimeKind::CandidateCapture.prefix(),
                std::process::id(),
                20_000 + index
            ));
            create_private_directory(&path).expect("create bounded scan fixture");
        }
        let error = scavenge_private_runtime_orphans(&root)
            .expect_err("managed directory count overflow must fail");
        assert!(error.to_string().contains("unbounded scavenging"));

        let tree_root = temp.path().join("tree");
        create_private_directory(&tree_root).expect("create bounded tree root");
        create_private_directory(&tree_root.join("child")).expect("create bounded child");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let tree = options.open(&tree_root).expect("open bounded tree");
        let device = tree.metadata().expect("tree metadata").dev() as libc::dev_t;
        let mut entries = 1;
        let error = validate_private_runtime_contents_unix(
            tree.as_raw_fd(),
            device,
            &mut entries,
            1,
            16,
            0,
        )
        .expect_err("entry overflow must fail before deletion");
        assert!(error.to_string().contains("bounded directory-entry limit"));
        assert!(tree_root.join("child").exists());

        let mut entries = 1;
        let error = validate_private_runtime_contents_unix(
            tree.as_raw_fd(),
            device,
            &mut entries,
            16,
            0,
            0,
        )
        .expect_err("depth overflow must fail before deletion");
        assert!(error.to_string().contains("depth limit"));
        assert!(tree_root.join("child").exists());
    }

    #[test]
    fn parses_git_apply_paths_from_standard_errors() {
        let stderr = "\
error: patch failed: README.md:1
error: README.md: patch does not apply
error: src/lib.rs: does not match index
";

        assert_eq!(
            parse_git_apply_error_paths(stderr),
            vec![PathBuf::from("README.md"), PathBuf::from("src/lib.rs")]
        );
    }

    #[test]
    fn validation_reports_accept_external_and_summary_shapes() {
        let value = serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "validation": [
                        {
                            "name": "unit",
                            "status": "failed",
                            "message": "tests failed",
                            "paths": ["src/lib.rs"]
                        }
                    ]
                },
                {
                    "id": "agent-b",
                    "validation": [
                        {"name": "fmt", "status": "succeeded"}
                    ]
                }
            ]
        });

        let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
            .expect("parse agent validation reports");

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].name, "unit");
        assert_eq!(reports[0].status, ValidationStatus::Failed);
        assert_eq!(reports[0].message.as_deref(), Some("tests failed"));
        assert_eq!(reports[0].paths, vec![PathBuf::from("src/lib.rs")]);
    }

    #[test]
    fn validation_reports_do_not_treat_agent_summary_as_validation() {
        let value = serde_json::json!({
            "agents": [
                {
                    "id": "agent-a",
                    "paths": ["README.md"],
                    "command": "cargo test",
                    "status": "succeeded"
                }
            ]
        });

        let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
            .expect("parse empty validation reports");

        assert!(reports.is_empty());
    }

    #[test]
    fn validation_check_uses_explicit_paths_for_failures() {
        let validation = validation_check(
            &[ValidationReport {
                name: "unit".to_string(),
                status: ValidationStatus::Failed,
                message: Some("failed".to_string()),
                paths: vec![PathBuf::from("src/lib.rs")],
            }],
            false,
        );

        assert_eq!(validation.status, SafetyCheckStatus::Failed);
        assert_eq!(validation.paths, vec![PathBuf::from("src/lib.rs")]);
    }
}
