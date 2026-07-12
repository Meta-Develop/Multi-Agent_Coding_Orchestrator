//! Lossless, bounded wire encoding for authenticated orchestration state.
//!
//! `std::path::PathBuf`'s JSON representation rejects non-UTF-8 Unix paths.
//! Checkpoint state instead serializes explicit native path units and converts
//! back only on the matching platform.

use crate::{
    orchestrator::{
        AgentCandidateBinding, AgentCheckpoint, AgentRunStatus, CheckpointAgentPlanSnapshot,
        CheckpointPlanSnapshot, CheckpointValidationCommandSnapshot, CheckpointWorktreeRecord,
        CompletedCommandStateBinding, OutputSummary, RepoValidationTargetBinding,
        RepoValidationTargetKind, RunCheckpoint, RunCheckpointStage, RunId,
        SemanticCoordinationMode, ValidationRunSummary, WorktreeReusePolicy,
    },
    semantic_coord::{
        ResolvedSemanticSymbol, SemanticConflict, SemanticConflictKind, SemanticConflictSeverity,
        SemanticIntent, SemanticIntentToken,
    },
    sync::{ClaimToken, PathClaim},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const MAX_PATH_UNITS: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "encoding", content = "units", rename_all = "snake_case")]
pub(crate) enum LosslessPath {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}

impl LosslessPath {
    pub(crate) fn from_path(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let units = path.as_os_str().as_bytes().to_vec();
            validate_path_units(units.len())?;
            Ok(Self::UnixBytes(units))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
            validate_path_units(units.len())?;
            Ok(Self::WindowsUtf16(units))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            bail!("lossless checkpoint paths are unsupported on this platform")
        }
    }

    pub(crate) fn to_path_buf(&self) -> Result<PathBuf> {
        match self {
            Self::UnixBytes(units) => {
                validate_path_units(units.len())?;
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStringExt;
                    Ok(PathBuf::from(std::ffi::OsString::from_vec(units.clone())))
                }
                #[cfg(not(unix))]
                bail!("Unix checkpoint path cannot be decoded on this platform")
            }
            Self::WindowsUtf16(units) => {
                validate_path_units(units.len())?;
                #[cfg(windows)]
                {
                    use std::os::windows::ffi::OsStringExt;
                    Ok(PathBuf::from(std::ffi::OsString::from_wide(units)))
                }
                #[cfg(not(windows))]
                bail!("Windows checkpoint path cannot be decoded on this platform")
            }
        }
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        match self {
            Self::UnixBytes(units) => units.len(),
            Self::WindowsUtf16(units) => units.len().saturating_mul(2),
        }
    }
}

fn validate_path_units(len: usize) -> Result<()> {
    if len == 0 || len > MAX_PATH_UNITS {
        bail!("checkpoint path exceeds its native-unit bound");
    }
    Ok(())
}

fn encode_paths(paths: &[PathBuf]) -> Result<Vec<LosslessPath>> {
    paths
        .iter()
        .map(|path| LosslessPath::from_path(path))
        .collect()
}

fn decode_paths(paths: &[LosslessPath]) -> Result<Vec<PathBuf>> {
    paths.iter().map(LosslessPath::to_path_buf).collect()
}

fn encode_optional_path(path: Option<&PathBuf>) -> Result<Option<LosslessPath>> {
    path.map(|path| LosslessPath::from_path(path)).transpose()
}

fn decode_optional_path(path: Option<&LosslessPath>) -> Result<Option<PathBuf>> {
    path.map(LosslessPath::to_path_buf).transpose()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunCheckpointWire {
    version: u32,
    run_id: RunId,
    stage: RunCheckpointStage,
    repo: LosslessPath,
    repo_head: Option<String>,
    plan_file: LosslessPath,
    plan_snapshot: Option<PlanSnapshotWire>,
    keep_claims: bool,
    worktree_reuse_policy: WorktreeReusePolicy,
    semantic_coordination: SemanticCoordinationMode,
    success: bool,
    agents: Vec<AgentCheckpointWire>,
    repo_validation: Vec<ValidationSummaryWire>,
    repo_validation_target: Option<RepoValidationTargetWire>,
    released_claims: Vec<PathClaimWire>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntentWire>,
    semantic_release_errors: Vec<String>,
    updated_unix_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanSnapshotWire {
    worktree_reuse_policy: WorktreeReusePolicy,
    repo_validation_commands: Vec<ValidationCommandWire>,
    agents: Vec<AgentPlanWire>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentPlanWire {
    id: String,
    paths: Vec<LosslessPath>,
    semantic_symbols: Vec<String>,
    semantic_modules: Vec<String>,
    env: BTreeMap<String, String>,
    timeout_seconds: Option<u64>,
    command: String,
    depends_on: Vec<String>,
    working_directory: Option<LosslessPath>,
    validation_commands: Vec<ValidationCommandWire>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidationCommandWire {
    name: Option<String>,
    command: String,
    env: BTreeMap<String, String>,
    timeout_seconds: Option<u64>,
    working_directory: Option<LosslessPath>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentCheckpointWire {
    id: String,
    status: AgentRunStatus,
    worktree: Option<WorktreeWire>,
    claim: Option<PathClaimWire>,
    semantic_intent: Option<SemanticIntentWire>,
    semantic_conflicts: Vec<SemanticConflictWire>,
    changed_paths: Vec<LosslessPath>,
    unclaimed_changed_paths: Vec<LosslessPath>,
    validation: Vec<ValidationSummaryWire>,
    candidate_binding: Option<CandidateBindingWire>,
    command_completed_binding: Option<CompletedBindingWire>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorktreeWire {
    name: String,
    path: LosslessPath,
    branch: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PathClaimWire {
    token: u64,
    agent_id: String,
    paths: Vec<LosslessPath>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticIntentWire {
    token: u64,
    agent_id: String,
    paths: Vec<LosslessPath>,
    symbols: Vec<ResolvedSemanticSymbolWire>,
    modules: Vec<String>,
    impacted_files: Vec<LosslessPath>,
    task_digest: Option<String>,
    task_excerpt: Option<String>,
    notes: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedSemanticSymbolWire {
    id: String,
    qualified_path: String,
    name: String,
    kind: String,
    file: LosslessPath,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticConflictWire {
    severity: SemanticConflictSeverity,
    kind: SemanticConflictKind,
    requested_token: u64,
    active_token: Option<u64>,
    active_agent_id: Option<String>,
    path: Option<LosslessPath>,
    module: Option<String>,
    symbol_id: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidationSummaryWire {
    name: Option<String>,
    command: String,
    working_directory: Option<LosslessPath>,
    timeout_seconds: Option<u64>,
    status: AgentRunStatus,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
    timed_out: bool,
    stdout: OutputSummary,
    stderr: OutputSummary,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateBindingWire {
    version: u32,
    base_oid: String,
    head_oid: String,
    state_oid: String,
    diff_oid: String,
    changed_paths: Vec<LosslessPath>,
    patch_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletedBindingWire {
    version: u32,
    base_oid: String,
    head_oid: String,
    state_oid: String,
    changed_paths: Vec<LosslessPath>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RepoValidationTargetWire {
    version: u32,
    kind: RepoValidationTargetKind,
    base_oid: String,
    combined_diff_oid: String,
    changed_paths: Vec<LosslessPath>,
    candidate_count: usize,
    patch_count: usize,
    aggregate_patch_bytes: u64,
}

pub(crate) fn encode_run_checkpoint(checkpoint: &RunCheckpoint) -> Result<Value> {
    serde_json::to_value(RunCheckpointWire::try_from(checkpoint)?)
        .context("failed to encode lossless checkpoint wire state")
}

pub(crate) fn decode_run_checkpoint(value: Value) -> Result<RunCheckpoint> {
    let wire: RunCheckpointWire =
        serde_json::from_value(value).context("failed to decode lossless checkpoint wire state")?;
    RunCheckpoint::try_from(wire)
}

pub(crate) fn encode_agent_checkpoint(agent: &AgentCheckpoint) -> Result<Value> {
    serde_json::to_value(AgentCheckpointWire::try_from(agent)?)
        .context("failed to encode lossless agent checkpoint state")
}

pub(crate) fn decode_agent_checkpoint(value: Value) -> Result<AgentCheckpoint> {
    let wire: AgentCheckpointWire = serde_json::from_value(value)
        .context("failed to decode lossless agent checkpoint state")?;
    AgentCheckpoint::try_from(wire)
}

impl TryFrom<&RunCheckpoint> for RunCheckpointWire {
    type Error = anyhow::Error;

    fn try_from(value: &RunCheckpoint) -> Result<Self> {
        Ok(Self {
            version: value.version,
            run_id: value.run_id.clone(),
            stage: value.stage,
            repo: LosslessPath::from_path(&value.repo)?,
            repo_head: value.repo_head.clone(),
            plan_file: LosslessPath::from_path(&value.plan_file)?,
            plan_snapshot: value
                .plan_snapshot
                .as_ref()
                .map(PlanSnapshotWire::try_from)
                .transpose()?,
            keep_claims: value.keep_claims,
            worktree_reuse_policy: value.worktree_reuse_policy,
            semantic_coordination: value.semantic_coordination,
            success: value.success,
            agents: value
                .agents
                .iter()
                .map(AgentCheckpointWire::try_from)
                .collect::<Result<_>>()?,
            repo_validation: value
                .repo_validation
                .iter()
                .map(ValidationSummaryWire::try_from)
                .collect::<Result<_>>()?,
            repo_validation_target: value
                .repo_validation_target
                .as_ref()
                .map(RepoValidationTargetWire::try_from)
                .transpose()?,
            released_claims: value
                .released_claims
                .iter()
                .map(PathClaimWire::try_from)
                .collect::<Result<_>>()?,
            release_errors: value.release_errors.clone(),
            released_semantic_intents: value
                .released_semantic_intents
                .iter()
                .map(SemanticIntentWire::try_from)
                .collect::<Result<_>>()?,
            semantic_release_errors: value.semantic_release_errors.clone(),
            updated_unix_ms: value.updated_unix_ms,
        })
    }
}

impl TryFrom<RunCheckpointWire> for RunCheckpoint {
    type Error = anyhow::Error;

    fn try_from(value: RunCheckpointWire) -> Result<Self> {
        Ok(Self {
            version: value.version,
            run_id: value.run_id,
            stage: value.stage,
            repo: value.repo.to_path_buf()?,
            repo_head: value.repo_head,
            plan_file: value.plan_file.to_path_buf()?,
            plan_snapshot: value
                .plan_snapshot
                .map(CheckpointPlanSnapshot::try_from)
                .transpose()?,
            keep_claims: value.keep_claims,
            worktree_reuse_policy: value.worktree_reuse_policy,
            semantic_coordination: value.semantic_coordination,
            success: value.success,
            agents: value
                .agents
                .into_iter()
                .map(AgentCheckpoint::try_from)
                .collect::<Result<_>>()?,
            repo_validation: value
                .repo_validation
                .into_iter()
                .map(ValidationRunSummary::try_from)
                .collect::<Result<_>>()?,
            repo_validation_target: value
                .repo_validation_target
                .map(RepoValidationTargetBinding::try_from)
                .transpose()?,
            released_claims: value
                .released_claims
                .into_iter()
                .map(PathClaim::try_from)
                .collect::<Result<_>>()?,
            release_errors: value.release_errors,
            released_semantic_intents: value
                .released_semantic_intents
                .into_iter()
                .map(SemanticIntent::try_from)
                .collect::<Result<_>>()?,
            semantic_release_errors: value.semantic_release_errors,
            updated_unix_ms: value.updated_unix_ms,
        })
    }
}

impl TryFrom<&CheckpointPlanSnapshot> for PlanSnapshotWire {
    type Error = anyhow::Error;
    fn try_from(value: &CheckpointPlanSnapshot) -> Result<Self> {
        Ok(Self {
            worktree_reuse_policy: value.worktree_reuse_policy,
            repo_validation_commands: value
                .repo_validation_commands
                .iter()
                .map(ValidationCommandWire::try_from)
                .collect::<Result<_>>()?,
            agents: value
                .agents
                .iter()
                .map(AgentPlanWire::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<PlanSnapshotWire> for CheckpointPlanSnapshot {
    type Error = anyhow::Error;
    fn try_from(value: PlanSnapshotWire) -> Result<Self> {
        Ok(Self {
            worktree_reuse_policy: value.worktree_reuse_policy,
            repo_validation_commands: value
                .repo_validation_commands
                .into_iter()
                .map(CheckpointValidationCommandSnapshot::try_from)
                .collect::<Result<_>>()?,
            agents: value
                .agents
                .into_iter()
                .map(CheckpointAgentPlanSnapshot::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<&CheckpointAgentPlanSnapshot> for AgentPlanWire {
    type Error = anyhow::Error;
    fn try_from(value: &CheckpointAgentPlanSnapshot) -> Result<Self> {
        Ok(Self {
            id: value.id.clone(),
            paths: encode_paths(&value.paths)?,
            semantic_symbols: value.semantic_symbols.clone(),
            semantic_modules: value.semantic_modules.clone(),
            env: value.env.clone(),
            timeout_seconds: value.timeout_seconds,
            command: value.command.clone(),
            depends_on: value.depends_on.clone(),
            working_directory: encode_optional_path(value.working_directory.as_ref())?,
            validation_commands: value
                .validation_commands
                .iter()
                .map(ValidationCommandWire::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<AgentPlanWire> for CheckpointAgentPlanSnapshot {
    type Error = anyhow::Error;
    fn try_from(value: AgentPlanWire) -> Result<Self> {
        Ok(Self {
            id: value.id,
            paths: decode_paths(&value.paths)?,
            semantic_symbols: value.semantic_symbols,
            semantic_modules: value.semantic_modules,
            env: value.env,
            timeout_seconds: value.timeout_seconds,
            command: value.command,
            depends_on: value.depends_on,
            working_directory: decode_optional_path(value.working_directory.as_ref())?,
            validation_commands: value
                .validation_commands
                .into_iter()
                .map(CheckpointValidationCommandSnapshot::try_from)
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<&CheckpointValidationCommandSnapshot> for ValidationCommandWire {
    type Error = anyhow::Error;
    fn try_from(value: &CheckpointValidationCommandSnapshot) -> Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            command: value.command.clone(),
            env: value.env.clone(),
            timeout_seconds: value.timeout_seconds,
            working_directory: encode_optional_path(value.working_directory.as_ref())?,
        })
    }
}

impl TryFrom<ValidationCommandWire> for CheckpointValidationCommandSnapshot {
    type Error = anyhow::Error;
    fn try_from(value: ValidationCommandWire) -> Result<Self> {
        Ok(Self {
            name: value.name,
            command: value.command,
            env: value.env,
            timeout_seconds: value.timeout_seconds,
            working_directory: decode_optional_path(value.working_directory.as_ref())?,
        })
    }
}

impl TryFrom<&AgentCheckpoint> for AgentCheckpointWire {
    type Error = anyhow::Error;
    fn try_from(value: &AgentCheckpoint) -> Result<Self> {
        Ok(Self {
            id: value.id.clone(),
            status: value.status,
            worktree: value
                .worktree
                .as_ref()
                .map(WorktreeWire::try_from)
                .transpose()?,
            claim: value
                .claim
                .as_ref()
                .map(PathClaimWire::try_from)
                .transpose()?,
            semantic_intent: value
                .semantic_intent
                .as_ref()
                .map(SemanticIntentWire::try_from)
                .transpose()?,
            semantic_conflicts: value
                .semantic_conflicts
                .iter()
                .map(SemanticConflictWire::try_from)
                .collect::<Result<_>>()?,
            changed_paths: encode_paths(&value.changed_paths)?,
            unclaimed_changed_paths: encode_paths(&value.unclaimed_changed_paths)?,
            validation: value
                .validation
                .iter()
                .map(ValidationSummaryWire::try_from)
                .collect::<Result<_>>()?,
            candidate_binding: value
                .candidate_binding
                .as_ref()
                .map(CandidateBindingWire::try_from)
                .transpose()?,
            command_completed_binding: value
                .command_completed_binding
                .as_ref()
                .map(CompletedBindingWire::try_from)
                .transpose()?,
            error: value.error.clone(),
        })
    }
}

impl TryFrom<AgentCheckpointWire> for AgentCheckpoint {
    type Error = anyhow::Error;
    fn try_from(value: AgentCheckpointWire) -> Result<Self> {
        Ok(Self {
            id: value.id,
            status: value.status,
            worktree: value
                .worktree
                .map(CheckpointWorktreeRecord::try_from)
                .transpose()?,
            claim: value.claim.map(PathClaim::try_from).transpose()?,
            semantic_intent: value
                .semantic_intent
                .map(SemanticIntent::try_from)
                .transpose()?,
            semantic_conflicts: value
                .semantic_conflicts
                .into_iter()
                .map(SemanticConflict::try_from)
                .collect::<Result<_>>()?,
            changed_paths: decode_paths(&value.changed_paths)?,
            unclaimed_changed_paths: decode_paths(&value.unclaimed_changed_paths)?,
            validation: value
                .validation
                .into_iter()
                .map(ValidationRunSummary::try_from)
                .collect::<Result<_>>()?,
            candidate_binding: value
                .candidate_binding
                .map(AgentCandidateBinding::try_from)
                .transpose()?,
            command_completed_binding: value
                .command_completed_binding
                .map(CompletedCommandStateBinding::try_from)
                .transpose()?,
            error: value.error,
        })
    }
}

impl TryFrom<&CheckpointWorktreeRecord> for WorktreeWire {
    type Error = anyhow::Error;
    fn try_from(value: &CheckpointWorktreeRecord) -> Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            path: LosslessPath::from_path(&value.path)?,
            branch: value.branch.clone(),
        })
    }
}
impl TryFrom<WorktreeWire> for CheckpointWorktreeRecord {
    type Error = anyhow::Error;
    fn try_from(value: WorktreeWire) -> Result<Self> {
        Ok(Self {
            name: value.name,
            path: value.path.to_path_buf()?,
            branch: value.branch,
        })
    }
}

impl TryFrom<&PathClaim> for PathClaimWire {
    type Error = anyhow::Error;
    fn try_from(value: &PathClaim) -> Result<Self> {
        Ok(Self {
            token: value.token.get(),
            agent_id: value.agent_id.clone(),
            paths: encode_paths(&value.paths)?,
        })
    }
}
impl TryFrom<PathClaimWire> for PathClaim {
    type Error = anyhow::Error;
    fn try_from(value: PathClaimWire) -> Result<Self> {
        Ok(Self {
            token: ClaimToken::from_u64(value.token),
            agent_id: value.agent_id,
            paths: decode_paths(&value.paths)?,
        })
    }
}

impl TryFrom<&SemanticIntent> for SemanticIntentWire {
    type Error = anyhow::Error;
    fn try_from(value: &SemanticIntent) -> Result<Self> {
        Ok(Self {
            token: value.token.get(),
            agent_id: value.agent_id.clone(),
            paths: encode_paths(&value.paths)?,
            symbols: value
                .symbols
                .iter()
                .map(ResolvedSemanticSymbolWire::try_from)
                .collect::<Result<_>>()?,
            modules: value.modules.clone(),
            impacted_files: encode_paths(&value.impacted_files)?,
            task_digest: value.task_digest.clone(),
            task_excerpt: value.task_excerpt.clone(),
            notes: value.notes.clone(),
            warnings: value.warnings.clone(),
        })
    }
}
impl TryFrom<SemanticIntentWire> for SemanticIntent {
    type Error = anyhow::Error;
    fn try_from(value: SemanticIntentWire) -> Result<Self> {
        Ok(Self {
            token: SemanticIntentToken::from_u64(value.token),
            agent_id: value.agent_id,
            paths: decode_paths(&value.paths)?,
            symbols: value
                .symbols
                .into_iter()
                .map(ResolvedSemanticSymbol::try_from)
                .collect::<Result<_>>()?,
            modules: value.modules,
            impacted_files: decode_paths(&value.impacted_files)?,
            task_digest: value.task_digest,
            task_excerpt: value.task_excerpt,
            notes: value.notes,
            warnings: value.warnings,
        })
    }
}

impl TryFrom<&ResolvedSemanticSymbol> for ResolvedSemanticSymbolWire {
    type Error = anyhow::Error;
    fn try_from(value: &ResolvedSemanticSymbol) -> Result<Self> {
        Ok(Self {
            id: value.id.clone(),
            qualified_path: value.qualified_path.clone(),
            name: value.name.clone(),
            kind: value.kind.clone(),
            file: LosslessPath::from_path(&value.file)?,
        })
    }
}
impl TryFrom<ResolvedSemanticSymbolWire> for ResolvedSemanticSymbol {
    type Error = anyhow::Error;
    fn try_from(value: ResolvedSemanticSymbolWire) -> Result<Self> {
        Ok(Self {
            id: value.id,
            qualified_path: value.qualified_path,
            name: value.name,
            kind: value.kind,
            file: value.file.to_path_buf()?,
        })
    }
}

impl TryFrom<&SemanticConflict> for SemanticConflictWire {
    type Error = anyhow::Error;
    fn try_from(value: &SemanticConflict) -> Result<Self> {
        Ok(Self {
            severity: value.severity,
            kind: value.kind,
            requested_token: value.requested_token.get(),
            active_token: value.active_token.map(SemanticIntentToken::get),
            active_agent_id: value.active_agent_id.clone(),
            path: value
                .path
                .as_ref()
                .map(|path| LosslessPath::from_path(path))
                .transpose()?,
            module: value.module.clone(),
            symbol_id: value.symbol_id.clone(),
            message: value.message.clone(),
        })
    }
}
impl TryFrom<SemanticConflictWire> for SemanticConflict {
    type Error = anyhow::Error;
    fn try_from(value: SemanticConflictWire) -> Result<Self> {
        Ok(Self {
            severity: value.severity,
            kind: value.kind,
            requested_token: SemanticIntentToken::from_u64(value.requested_token),
            active_token: value.active_token.map(SemanticIntentToken::from_u64),
            active_agent_id: value.active_agent_id,
            path: value
                .path
                .as_ref()
                .map(LosslessPath::to_path_buf)
                .transpose()?,
            module: value.module,
            symbol_id: value.symbol_id,
            message: value.message,
        })
    }
}

impl TryFrom<&ValidationRunSummary> for ValidationSummaryWire {
    type Error = anyhow::Error;
    fn try_from(value: &ValidationRunSummary) -> Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            command: value.command.clone(),
            working_directory: encode_optional_path(value.working_directory.as_ref())?,
            timeout_seconds: value.timeout_seconds,
            status: value.status,
            exit_code: value.exit_code,
            duration_ms: value.duration_ms,
            timed_out: value.timed_out,
            stdout: value.stdout.clone(),
            stderr: value.stderr.clone(),
            error: value.error.clone(),
        })
    }
}
impl TryFrom<ValidationSummaryWire> for ValidationRunSummary {
    type Error = anyhow::Error;
    fn try_from(value: ValidationSummaryWire) -> Result<Self> {
        Ok(Self {
            name: value.name,
            command: value.command,
            working_directory: decode_optional_path(value.working_directory.as_ref())?,
            timeout_seconds: value.timeout_seconds,
            status: value.status,
            exit_code: value.exit_code,
            duration_ms: value.duration_ms,
            timed_out: value.timed_out,
            stdout: value.stdout,
            stderr: value.stderr,
            error: value.error,
        })
    }
}

impl TryFrom<&AgentCandidateBinding> for CandidateBindingWire {
    type Error = anyhow::Error;
    fn try_from(value: &AgentCandidateBinding) -> Result<Self> {
        Ok(Self {
            version: value.version,
            base_oid: value.base_oid.clone(),
            head_oid: value.head_oid.clone(),
            state_oid: value.state_oid.clone(),
            diff_oid: value.diff_oid.clone(),
            changed_paths: encode_paths(&value.changed_paths)?,
            patch_bytes: value.patch_bytes,
        })
    }
}
impl TryFrom<CandidateBindingWire> for AgentCandidateBinding {
    type Error = anyhow::Error;
    fn try_from(value: CandidateBindingWire) -> Result<Self> {
        Ok(Self {
            version: value.version,
            base_oid: value.base_oid,
            head_oid: value.head_oid,
            state_oid: value.state_oid,
            diff_oid: value.diff_oid,
            changed_paths: decode_paths(&value.changed_paths)?,
            patch_bytes: value.patch_bytes,
        })
    }
}

impl TryFrom<&CompletedCommandStateBinding> for CompletedBindingWire {
    type Error = anyhow::Error;
    fn try_from(value: &CompletedCommandStateBinding) -> Result<Self> {
        Ok(Self {
            version: value.version,
            base_oid: value.base_oid.clone(),
            head_oid: value.head_oid.clone(),
            state_oid: value.state_oid.clone(),
            changed_paths: encode_paths(&value.changed_paths)?,
        })
    }
}
impl TryFrom<CompletedBindingWire> for CompletedCommandStateBinding {
    type Error = anyhow::Error;
    fn try_from(value: CompletedBindingWire) -> Result<Self> {
        Ok(Self {
            version: value.version,
            base_oid: value.base_oid,
            head_oid: value.head_oid,
            state_oid: value.state_oid,
            changed_paths: decode_paths(&value.changed_paths)?,
        })
    }
}

impl TryFrom<&RepoValidationTargetBinding> for RepoValidationTargetWire {
    type Error = anyhow::Error;
    fn try_from(value: &RepoValidationTargetBinding) -> Result<Self> {
        Ok(Self {
            version: value.version,
            kind: value.kind,
            base_oid: value.base_oid.clone(),
            combined_diff_oid: value.combined_diff_oid.clone(),
            changed_paths: encode_paths(&value.changed_paths)?,
            candidate_count: value.candidate_count,
            patch_count: value.patch_count,
            aggregate_patch_bytes: value.aggregate_patch_bytes,
        })
    }
}
impl TryFrom<RepoValidationTargetWire> for RepoValidationTargetBinding {
    type Error = anyhow::Error;
    fn try_from(value: RepoValidationTargetWire) -> Result<Self> {
        Ok(Self {
            version: value.version,
            kind: value.kind,
            base_oid: value.base_oid,
            combined_diff_oid: value.combined_diff_oid,
            changed_paths: decode_paths(&value.changed_paths)?,
            candidate_count: value.candidate_count,
            patch_count: value.patch_count,
            aggregate_patch_bytes: value.aggregate_patch_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_non_utf8_path_round_trips_losslessly() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let raw = b"repo-\xff".to_vec();
        let path = PathBuf::from(std::ffi::OsString::from_vec(raw.clone()));
        let wire = LosslessPath::from_path(&path).expect("encode");
        let encoded = serde_json::to_vec(&wire).expect("json");
        let decoded: LosslessPath = serde_json::from_slice(&encoded).expect("decode json");
        assert_eq!(
            decoded
                .to_path_buf()
                .expect("decode")
                .as_os_str()
                .as_bytes(),
            raw
        );
    }
}
