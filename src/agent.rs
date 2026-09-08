use crate::{
    llm::{
        provider::CommandPurpose, LlmProvider, LlmRequest, LlmResponse, PromptContext,
        ProposedCommand, ProposedPatch, Redactor, RepoExcerpt, RequestBudget, ValidationCommand,
    },
    merge::{
        self, MergeApplyPreview, MergeCandidate, MergeCollectOptions, MergeForceOptions,
        MergePreviewOptions, ValidationReport, ValidationStatus,
    },
    process_runner::{
        read_bounded_regular_file_nofollow, resolve_existing_path_without_symlinks, run_process,
        CapturedBytes, EnvironmentMode, ProcessSpec, Shell, SideEffectConfinementProfile,
        StdinMode, StrictOfflineWorkspaceProfile,
    },
    sync::{normalize_repo_relative_path, PathClaim},
    sync_store::SyncStore,
    worktree::{
        normalize_agent_id, ManagedWorktreeWriteLease, WorktreeCreateOptions, WorktreeManager,
        WorktreeRecord,
    },
};
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use git2::StatusOptions;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::ExitStatus,
    time::{Duration, Instant},
};

const DEFAULT_MODEL: &str = "deterministic-fake";
const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_CAPTURE_LIMIT_BYTES: usize = OUTPUT_CHAR_LIMIT * 4;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROMPT_EXCERPT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone)]
pub struct AgentRunOptions {
    pub repo: PathBuf,
    pub agent_id: String,
    pub task: String,
    pub request_id: Option<String>,
    pub model: Option<String>,
    pub claimed_paths: Vec<PathBuf>,
    pub validation_commands: Vec<AgentValidationCommand>,
    pub keep_claims: bool,
    pub worktree_reuse: AgentWorktreeReusePolicy,
    pub provider_command_policy: ProviderCommandPolicy,
    pub command_timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorktreeReusePolicy {
    #[default]
    Clean,
    Required,
    Fresh,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCommandPolicy {
    #[default]
    Disabled,
    AllowUnsafeShell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentValidationCommand {
    pub name: Option<String>,
    pub command: String,
    pub working_directory: Option<PathBuf>,
}

impl AgentValidationCommand {
    pub fn required(command: impl Into<String>) -> Self {
        Self {
            name: None,
            command: command.into(),
            working_directory: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_working_directory(mut self, working_directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(working_directory.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentRunReport {
    pub success: bool,
    pub repo: PathBuf,
    pub agent_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub model: String,
    pub worktree: WorktreeRecord,
    pub worktree_reused: bool,
    pub claim: Option<PathClaim>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
    pub response: LlmResponse,
    pub patch_results: Vec<PatchApplicationReport>,
    pub command_results: Vec<CommandExecutionReport>,
    pub validation_results: Vec<CommandExecutionReport>,
    pub provider_command_policy: ProviderCommandPolicy,
    pub command_timeout_seconds: u64,
    pub candidate: MergeCandidate,
    pub merge_preview: MergeApplyPreview,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchApplicationReport {
    pub path: PathBuf,
    pub success: bool,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandExecutionReport {
    pub command: String,
    pub purpose: Option<CommandPurpose>,
    pub working_directory: Option<PathBuf>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub timeout_seconds: u64,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug)]
struct SelectedWorktree {
    lease: ManagedWorktreeWriteLease,
    reused: bool,
}

impl SelectedWorktree {
    fn record(&self) -> &WorktreeRecord {
        self.lease.record()
    }

    fn path(&self) -> &Path {
        self.lease.path()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentProtectedStage {
    Revalidation,
    Validation,
    Collect,
    Preview,
}

#[cfg(test)]
type AgentProtectedStageHook = Box<dyn FnMut(AgentProtectedStage)>;

#[cfg(test)]
thread_local! {
    static AGENT_PROTECTED_STAGE_HOOK: std::cell::RefCell<Option<AgentProtectedStageHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_agent_protected_stage_hook(hook: impl FnMut(AgentProtectedStage) + 'static) {
    AGENT_PROTECTED_STAGE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn clear_agent_protected_stage_hook() {
    AGENT_PROTECTED_STAGE_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn run_agent_protected_stage_hook(stage: AgentProtectedStage) {
    AGENT_PROTECTED_STAGE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(stage);
        }
    });
}

#[cfg(test)]
thread_local! {
    static AGENT_CLAIM_TIMING: std::cell::RefCell<Option<crate::sync_store::ClaimTiming>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_agent_claim_timing_for_test(timing: crate::sync_store::ClaimTiming) {
    AGENT_CLAIM_TIMING.with(|slot| *slot.borrow_mut() = Some(timing));
}

#[cfg(test)]
fn take_agent_claim_timing_for_test() -> Option<crate::sync_store::ClaimTiming> {
    AGENT_CLAIM_TIMING.with(|slot| slot.borrow_mut().take())
}

#[derive(Debug, Clone)]
struct CommandSpec {
    command: String,
    purpose: Option<CommandPurpose>,
    working_directory: Option<PathBuf>,
    timeout: Duration,
}

pub fn default_request_id(agent_id: &str) -> String {
    format!("agent-run-{agent_id}")
}

pub fn default_model() -> &'static str {
    DEFAULT_MODEL
}

pub fn default_command_timeout() -> Duration {
    DEFAULT_COMMAND_TIMEOUT
}

pub fn run_agent_with_provider<P>(
    options: AgentRunOptions,
    provider: &mut P,
) -> Result<AgentRunReport>
where
    P: LlmProvider,
{
    run_agent_with_provider_runtime(options, provider, AgentExecutionRuntime::Verified)
}

#[cfg(test)]
fn run_agent_with_provider_simulation<P>(
    options: AgentRunOptions,
    provider: &mut P,
) -> Result<AgentRunReport>
where
    P: LlmProvider,
{
    run_agent_with_provider_runtime(
        options,
        provider,
        AgentExecutionRuntime::NonpublishableSimulation,
    )
}

fn run_agent_with_provider_runtime<P>(
    options: AgentRunOptions,
    provider: &mut P,
    runtime: AgentExecutionRuntime,
) -> Result<AgentRunReport>
where
    P: LlmProvider,
{
    let repo = discover_repo_root(&options.repo)?;
    let agent_id = normalize_agent_id(&options.agent_id)?;
    let claimed_paths = normalize_claimed_paths(options.claimed_paths)?;
    let request_id = options
        .request_id
        .unwrap_or_else(|| default_request_id(&agent_id));
    let model = options.model.unwrap_or_else(|| DEFAULT_MODEL.to_string());
    let manager = WorktreeManager::new(&repo);
    let selected = select_worktree(&manager, &agent_id, options.worktree_reuse)?;
    let store = SyncStore::open(&repo)?;
    #[cfg(test)]
    let claim = match take_agent_claim_timing_for_test() {
        Some(timing) => store
            .claim_paths_with_timing(&agent_id, claimed_paths.iter(), timing)
            .map(|outcome| outcome.claim),
        None => store.claim_paths(&agent_id, claimed_paths.iter()),
    };
    #[cfg(not(test))]
    let claim = store.claim_paths(&agent_id, claimed_paths.iter());
    let claim = claim.with_context(|| format!("failed to claim paths for agent '{agent_id}'"))?;
    let claim_token = claim.token;

    let result = run_claimed_agent(ClaimedAgentRun {
        repo: repo.clone(),
        agent_id: agent_id.clone(),
        request_id,
        model,
        task: options.task,
        claimed_paths,
        validation_commands: options.validation_commands,
        selected,
        claim: claim.clone(),
        provider_command_policy: options.provider_command_policy,
        command_timeout: options.command_timeout,
        runtime,
        provider,
    });

    let (released_claims, release_errors) = if options.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        match store.release(claim_token) {
            Ok(released) => (vec![released], Vec::new()),
            Err(error) => (Vec::new(), vec![error.to_string()]),
        }
    };

    let mut report = result?;
    if !release_errors.is_empty() {
        report.success = false;
        report.error = Some(match report.error.take() {
            Some(existing) => format!(
                "{existing}; failed to release one or more claims: {}",
                release_errors.join("; ")
            ),
            None => format!(
                "failed to release one or more claims: {}",
                release_errors.join("; ")
            ),
        });
    }
    report.released_claims = released_claims;
    report.release_errors = release_errors;
    Ok(report)
}

struct ClaimedAgentRun<'a, P>
where
    P: LlmProvider,
{
    repo: PathBuf,
    agent_id: String,
    request_id: String,
    model: String,
    task: String,
    claimed_paths: Vec<PathBuf>,
    validation_commands: Vec<AgentValidationCommand>,
    selected: SelectedWorktree,
    claim: PathClaim,
    provider_command_policy: ProviderCommandPolicy,
    command_timeout: Duration,
    runtime: AgentExecutionRuntime,
    provider: &'a mut P,
}

fn run_claimed_agent<P>(run: ClaimedAgentRun<'_, P>) -> Result<AgentRunReport>
where
    P: LlmProvider,
{
    let capabilities = run.provider.capabilities();
    let worktree_path = run.selected.path().to_path_buf();
    let prompt = build_prompt(
        &worktree_path,
        &run.agent_id,
        &run.task,
        &run.claimed_paths,
        &run.validation_commands,
        capabilities,
    )?;
    let request = LlmRequest::new(run.request_id.clone(), run.model.clone(), prompt)
        .with_budget(RequestBudget::default());
    let response = run.provider.complete(request).map_err(|error| {
        crate::budget_ledger::record_bound_provider_error_preserving_source(error)
            .context(format!("provider '{}' failed", run.provider.provider_id()))
    })?;

    let mut patch_results = Vec::new();
    let mut command_results = Vec::new();
    let mut validation_results = Vec::new();
    let mut execution_error = None;

    let _revalidation = crate::collect_revalidation::revalidate_claimed_worker(
        &run.repo,
        &run.agent_id,
        run.claim.token,
        &run.claimed_paths,
        run.selected.record(),
    )
    .with_context(|| {
        format!(
            "pre-mutation revalidation failed for agent '{}'",
            run.agent_id
        )
    })?;
    _revalidation
        .start_guard_owned_heartbeat()
        .with_context(|| {
            format!(
                "failed to start guard-owned heartbeat for agent '{}'",
                run.agent_id
            )
        })?;
    #[cfg(test)]
    run_agent_protected_stage_hook(AgentProtectedStage::Revalidation);

    for patch in &response.proposal.patches {
        let result = apply_proposed_patch(
            &worktree_path,
            patch,
            &run.claimed_paths,
            run.command_timeout,
            run.runtime,
        );
        if !result.success && execution_error.is_none() {
            execution_error = result.error.clone();
        }
        patch_results.push(result);
        if execution_error.is_some() {
            break;
        }
    }

    if execution_error.is_none()
        && run.provider_command_policy == ProviderCommandPolicy::Disabled
        && !response.proposal.commands.is_empty()
    {
        for command in &response.proposal.commands {
            command_results.push(disabled_provider_command_report(
                command,
                run.command_timeout,
            ));
        }
        execution_error = Some(
            "provider-proposed shell commands are disabled; rerun with --allow-provider-commands to opt in"
                .to_string(),
        );
    }

    if execution_error.is_none() {
        for command in response
            .proposal
            .commands
            .iter()
            .filter(|command| command.purpose != CommandPurpose::Validate)
        {
            let result =
                run_proposed_command(&worktree_path, command, run.command_timeout, run.runtime);
            if !result.success && execution_error.is_none() {
                execution_error = result.error.clone();
            }
            command_results.push(result);
            if execution_error.is_some() {
                break;
            }
        }
    }

    let mut validations = Vec::new();
    if execution_error.is_none() {
        for command in response
            .proposal
            .commands
            .iter()
            .filter(|command| command.purpose == CommandPurpose::Validate)
        {
            let result =
                run_proposed_command(&worktree_path, command, run.command_timeout, run.runtime);
            validations.push(validation_report_for_command(&result));
            if !result.success && execution_error.is_none() {
                execution_error = result.error.clone();
            }
            validation_results.push(result);
            if execution_error.is_some() {
                break;
            }
        }
    }

    if execution_error.is_none() {
        for validation in &run.validation_commands {
            let result = run_validation_command(
                &worktree_path,
                validation,
                run.command_timeout,
                run.runtime,
            );
            validations.push(validation_report_for_command(&result));
            if !result.success && execution_error.is_none() {
                execution_error = result.error.clone();
            }
            validation_results.push(result);
            if execution_error.is_some() {
                break;
            }
        }
    }

    #[cfg(test)]
    run_agent_protected_stage_hook(AgentProtectedStage::Validation);
    let collect_validations = validations.clone();
    let candidate = merge::collect_agent_result_with_evidence_and_write_lease(
        MergeCollectOptions {
            repo: run.repo.clone(),
            agent_id: run.agent_id.clone(),
            claimed_paths: run.claimed_paths.clone(),
            include_full_diff: false,
            diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations: collect_validations.clone(),
        },
        merge::ValidationEvidenceBundle::legacy(collect_validations),
        &run.selected.lease,
    )?;
    #[cfg(test)]
    run_agent_protected_stage_hook(AgentProtectedStage::Collect);
    let preview_validations = validations;
    let merge_preview = merge::preview_merge_apply_with_evidence_and_write_lease(
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: run.repo.clone(),
                agent_id: run.agent_id.clone(),
                claimed_paths: run.claimed_paths.clone(),
                include_full_diff: true,
                diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: preview_validations.clone(),
            },
            forces: MergeForceOptions::default(),
            require_validation: false,
            review_intent: merge::MergeApplyReviewIntent::default(),
        },
        merge::ValidationEvidenceBundle::legacy(preview_validations),
        &run.selected.lease,
    )?;
    #[cfg(test)]
    run_agent_protected_stage_hook(AgentProtectedStage::Preview);

    let boundary_error = if candidate.unclaimed_changed_paths.is_empty() {
        None
    } else {
        Some(format!(
            "agent changed paths outside its claims: {}",
            display_paths(&candidate.unclaimed_changed_paths)
        ))
    };
    let validation_failed = validation_results.iter().any(|result| !result.success);
    let success = execution_error.is_none() && boundary_error.is_none() && !validation_failed;
    let error = execution_error.or(boundary_error);

    _revalidation
        .stop_guard_owned_heartbeat()
        .with_context(|| format!("guard-owned heartbeat failed for agent '{}'", run.agent_id))?;

    Ok(AgentRunReport {
        success,
        repo: run.repo,
        agent_id: run.agent_id,
        request_id: response.request_id.clone(),
        provider_id: response.provider_id.clone(),
        model: response.model.clone(),
        worktree: run.selected.record().clone(),
        worktree_reused: run.selected.reused,
        claim: Some(run.claim),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        response,
        patch_results,
        command_results,
        validation_results,
        provider_command_policy: run.provider_command_policy,
        command_timeout_seconds: run.command_timeout.as_secs(),
        candidate,
        merge_preview,
        error,
    })
}

fn build_prompt(
    repo: &Path,
    agent_id: &str,
    task: &str,
    claimed_paths: &[PathBuf],
    validation_commands: &[AgentValidationCommand],
    capabilities: crate::llm::ProviderCapabilities,
) -> Result<crate::llm::Prompt> {
    let mut context = PromptContext::new(task, agent_id);
    context.provider_capabilities = capabilities;

    for path in claimed_paths {
        context = context.with_claimed_path(path.clone(), "agent run claim");
        let full_path = match resolve_existing_path_without_symlinks(repo, path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to resolve claimed prompt path {}", path.display())
                });
            }
        };
        if full_path.is_file() {
            let content = read_bounded_regular_file_nofollow(&full_path, MAX_PROMPT_EXCERPT_BYTES)
                .with_context(|| format!("failed to read prompt path {}", path.display()))?;
            let content = String::from_utf8(content)
                .with_context(|| format!("prompt path is not UTF-8 text: {}", path.display()))?;
            context = context.with_repo_excerpt(RepoExcerpt::new(path.clone(), content));
        }
    }

    for validation in validation_commands {
        let mut prompt_command = ValidationCommand::required(validation.command.clone());
        if let Some(working_directory) = &validation.working_directory {
            prompt_command = prompt_command.with_working_directory(working_directory.clone());
        }
        context = context.with_validation_command(prompt_command);
    }

    Ok(context.assemble_prompt(&Redactor::new()))
}

fn select_worktree(
    manager: &WorktreeManager,
    agent_id: &str,
    policy: AgentWorktreeReusePolicy,
) -> Result<SelectedWorktree> {
    let existing = manager
        .list()?
        .into_iter()
        .find(|record| record.name == agent_id);

    if let Some(record) = existing {
        if policy == AgentWorktreeReusePolicy::Fresh {
            bail!(
                "worktree reuse policy 'fresh' requires no existing worktree for agent '{}' at {}",
                agent_id,
                record.path.display()
            );
        }
        ensure_clean_worktree(&record)?;
        let lease = manager
            .acquire_write_execution_lease(agent_id)
            .with_context(|| {
                format!("failed to acquire exclusive write lease for worktree '{agent_id}'")
            })?;
        if lease.record() != &record {
            bail!(
                "acquired write lease for agent '{agent_id}' no longer matches the selected worktree identity"
            );
        }
        ensure_clean_worktree(lease.record())?;
        return Ok(SelectedWorktree {
            lease,
            reused: true,
        });
    }

    if policy == AgentWorktreeReusePolicy::Required {
        bail!(
            "worktree reuse policy 'required' requires an existing clean worktree for agent '{agent_id}'"
        );
    }

    let create_options = WorktreeCreateOptions {
        agent_id: agent_id.to_string(),
        branch: None,
        base: None,
        worktree_root: None,
    };
    #[cfg(test)]
    let record = manager.create_for_test(create_options)?;
    #[cfg(not(test))]
    let record = {
        let cleanliness = manager.acquire_repository_cleanliness().context(
            "agent assignment creation requires a capability-bound repository \
             cleanliness input; commit, stash, or remove pending changes in the \
             primary repository, then rerun the agent",
        )?;
        manager.create_with_repository_cleanliness(create_options, &cleanliness)?
    };
    let lease = manager
        .acquire_write_execution_lease(agent_id)
        .with_context(|| {
            format!(
                "failed to acquire exclusive write lease for newly created worktree '{agent_id}'"
            )
        })?;
    if lease.record() != &record {
        bail!(
            "acquired write lease for newly created worktree '{agent_id}' no longer matches the created record"
        );
    }
    Ok(SelectedWorktree {
        lease,
        reused: false,
    })
}

fn ensure_clean_worktree(record: &WorktreeRecord) -> Result<()> {
    let repo = crate::git_repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect worktree status")?;
    if !statuses.is_empty() {
        bail!(
            "refusing to reuse dirty worktree '{}' at {}; remove it or clean it before rerunning",
            record.name,
            record.path.display()
        );
    }
    Ok(())
}

fn normalize_claimed_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    if paths.is_empty() {
        bail!("agent run requires at least one claimed path");
    }
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

fn apply_proposed_patch(
    worktree_path: &Path,
    patch: &ProposedPatch,
    claimed_paths: &[PathBuf],
    timeout: Duration,
    runtime: AgentExecutionRuntime,
) -> PatchApplicationReport {
    let normalized_path = match normalize_repo_relative_path(&patch.path) {
        Ok(path) => path,
        Err(error) => {
            return PatchApplicationReport {
                path: patch.path.clone(),
                success: false,
                stdout: OutputSummary::default(),
                stderr: OutputSummary::default(),
                error: Some(format!("invalid patch path: {error}")),
            }
        }
    };

    if !claimed_paths
        .iter()
        .any(|claim| path_is_covered_by_claim(&normalized_path, claim))
    {
        return PatchApplicationReport {
            path: normalized_path,
            success: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: Some("provider patch path is outside claimed paths".to_string()),
        };
    }

    if patch.unified_diff.trim().is_empty() {
        return PatchApplicationReport {
            path: normalized_path,
            success: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: Some("provider patch is empty".to_string()),
        };
    }

    if let Err(error) =
        validate_proposed_patch_diff_paths(&normalized_path, &patch.unified_diff, claimed_paths)
    {
        return PatchApplicationReport {
            path: normalized_path,
            success: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: Some(error.to_string()),
        };
    }

    match run_git_apply(worktree_path, &patch.unified_diff, timeout, runtime) {
        Ok(result) => PatchApplicationReport {
            path: normalized_path,
            success: result.status.is_some_and(|status| status.success()),
            stdout: result.stdout,
            stderr: result.stderr,
            error: if result.status.is_some_and(|status| status.success()) {
                None
            } else {
                Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("git apply exited with status {code}"),
                    None => "git apply terminated without an exit code".to_string(),
                })
            },
        },
        Err(error) => PatchApplicationReport {
            path: normalized_path,
            success: false,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: Some(format!("failed to apply provider patch: {error}")),
        },
    }
}

fn validate_proposed_patch_diff_paths(
    declared_path: &Path,
    unified_diff: &str,
    claimed_paths: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let diff_paths = parse_unified_diff_paths(unified_diff)?;
    if !diff_paths.iter().any(|path| path == declared_path) {
        bail!(
            "provider patch diff paths do not include declared path '{}'; actual paths: {}",
            declared_path.display(),
            display_paths(&diff_paths)
        );
    }

    for path in &diff_paths {
        if !claimed_paths
            .iter()
            .any(|claim| path_is_covered_by_claim(path, claim))
        {
            bail!(
                "provider patch diff path '{}' is outside claimed paths",
                path.display()
            );
        }
    }

    Ok(diff_paths)
}

fn parse_unified_diff_paths(unified_diff: &str) -> Result<Vec<PathBuf>> {
    let lines = unified_diff.lines().collect::<Vec<_>>();
    let mut paths = BTreeSet::new();
    let mut in_hunk = false;
    let mut index = 0;

    while index < lines.len() {
        let line = trim_cr(lines[index]);
        if let Some(rest) = line.strip_prefix("diff --git ") {
            in_hunk = false;
            for path in parse_diff_git_paths(rest)? {
                paths.insert(path);
            }
        } else if line.starts_with("@@") {
            in_hunk = true;
        } else if !in_hunk && line.starts_with("--- ") {
            if let Some(next) = lines.get(index + 1).map(|line| trim_cr(line)) {
                if next.starts_with("+++ ") {
                    if let Some(path) = parse_diff_file_header_path(line, "--- ")? {
                        paths.insert(path);
                    }
                    if let Some(path) = parse_diff_file_header_path(next, "+++ ")? {
                        paths.insert(path);
                    }
                    index += 1;
                }
            }
        }
        index += 1;
    }

    if paths.is_empty() {
        bail!("provider patch does not declare any diff paths");
    }

    Ok(paths.into_iter().collect())
}

fn parse_diff_git_paths(rest: &str) -> Result<Vec<PathBuf>> {
    let Some(split_index) = rest.find(" b/") else {
        return Ok(Vec::new());
    };
    let (left, right) = rest.split_at(split_index);
    let right = &right[1..];
    let mut paths = Vec::new();
    for raw_path in [left, right] {
        if let Some(path) = normalize_diff_path(raw_path)? {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn parse_diff_file_header_path(line: &str, prefix: &str) -> Result<Option<PathBuf>> {
    let Some(raw_path) = line.strip_prefix(prefix) else {
        return Ok(None);
    };
    normalize_diff_path(raw_path.split('\t').next().unwrap_or(raw_path))
}

fn normalize_diff_path(raw_path: &str) -> Result<Option<PathBuf>> {
    let raw_path = raw_path.trim();
    if raw_path == "/dev/null" || raw_path.is_empty() {
        return Ok(None);
    }
    let path = raw_path
        .strip_prefix("a/")
        .or_else(|| raw_path.strip_prefix("b/"))
        .unwrap_or(raw_path);
    normalize_repo_relative_path(path)
        .map(Some)
        .map_err(Into::into)
}

fn trim_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

fn disabled_provider_command_report(
    command: &ProposedCommand,
    timeout: Duration,
) -> CommandExecutionReport {
    CommandExecutionReport {
        command: command.command.clone(),
        purpose: Some(command.purpose),
        working_directory: command.working_directory.clone(),
        success: false,
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        timeout_seconds: timeout.as_secs(),
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: Some(
            "provider-proposed shell commands are disabled; rerun with --allow-provider-commands to opt in"
                .to_string(),
        ),
    }
}

fn run_proposed_command(
    worktree_path: &Path,
    command: &ProposedCommand,
    timeout: Duration,
    runtime: AgentExecutionRuntime,
) -> CommandExecutionReport {
    run_command(
        worktree_path,
        CommandSpec {
            command: command.command.clone(),
            purpose: Some(command.purpose),
            working_directory: command.working_directory.clone(),
            timeout,
        },
        runtime,
    )
}

fn run_validation_command(
    worktree_path: &Path,
    validation: &AgentValidationCommand,
    timeout: Duration,
    runtime: AgentExecutionRuntime,
) -> CommandExecutionReport {
    run_command(
        worktree_path,
        CommandSpec {
            command: validation.command.clone(),
            purpose: Some(CommandPurpose::Validate),
            working_directory: validation.working_directory.clone(),
            timeout,
        },
        runtime,
    )
}

fn run_command(
    worktree_path: &Path,
    spec: CommandSpec,
    runtime: AgentExecutionRuntime,
) -> CommandExecutionReport {
    let normalized_cwd = match normalize_optional_working_directory(spec.working_directory.as_ref())
    {
        Ok(path) => path,
        Err(error) => {
            return CommandExecutionReport {
                command: spec.command,
                purpose: spec.purpose,
                working_directory: spec.working_directory,
                success: false,
                exit_code: None,
                duration_ms: 0,
                timed_out: false,
                timeout_seconds: spec.timeout.as_secs(),
                stdout: OutputSummary::default(),
                stderr: OutputSummary::default(),
                error: Some(format!("invalid working directory: {error}")),
            }
        }
    };
    let full_cwd = normalized_cwd
        .as_ref()
        .map(|path| worktree_path.join(path))
        .unwrap_or_else(|| worktree_path.to_path_buf());
    let started = Instant::now();
    let process_spec = ProcessSpec::shell(
        "agent command",
        Shell::for_current_platform(),
        spec.command.clone(),
        full_cwd,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(sandbox_environment()))
    .with_timeout(Some(spec.timeout));
    let result = run_process(match runtime {
        AgentExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_write(worktree_path),
            )),
        #[cfg(test)]
        AgentExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    });

    match result {
        Ok(output) => {
            let success = match runtime {
                AgentExecutionRuntime::Verified => output.safety_sensitive_succeeded(),
                #[cfg(test)]
                AgentExecutionRuntime::NonpublishableSimulation => {
                    output.status.is_some_and(|status| status.success())
                        && !output.timed_out
                        && output.process_error.is_none()
                        && output.stdin_error.is_none()
                }
            };
            CommandExecutionReport {
                command: spec.command,
                purpose: spec.purpose,
                working_directory: normalized_cwd,
                success,
                exit_code: output.status.and_then(|status| status.code()),
                duration_ms: output.duration_ms(),
                timed_out: output.timed_out,
                timeout_seconds: spec.timeout.as_secs(),
                stdout: summarize_output(&output.stdout),
                stderr: summarize_output(&output.stderr),
                error: if success {
                    None
                } else if let Some(error) = output.process_error {
                    Some(error)
                } else if runtime == AgentExecutionRuntime::Verified
                    && !output.safety_evidence_verified()
                {
                    Some(format!(
                        "command safety evidence was not verified: process_tree={:?}; side_effects={:?}",
                        output.process_tree, output.side_effects
                    ))
                } else if output.timed_out {
                    Some(format!(
                        "command timed out after {} seconds",
                        spec.timeout.as_secs()
                    ))
                } else {
                    Some(match output.status.and_then(|status| status.code()) {
                        Some(code) => format!("command exited with status {code}"),
                        None => "command terminated without an exit code".to_string(),
                    })
                },
            }
        }
        Err(error) => CommandExecutionReport {
            command: spec.command,
            purpose: spec.purpose,
            working_directory: normalized_cwd,
            success: false,
            exit_code: None,
            duration_ms: duration_millis(started.elapsed()),
            timed_out: false,
            timeout_seconds: spec.timeout.as_secs(),
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: Some(format!("failed to run command: {error}")),
        },
    }
}

fn normalize_optional_working_directory(path: Option<&PathBuf>) -> Result<Option<PathBuf>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if path == Path::new(".") {
        return Ok(None);
    }
    normalize_repo_relative_path(path)
        .map(Some)
        .map_err(Into::into)
}

fn validation_report_for_command(result: &CommandExecutionReport) -> ValidationReport {
    ValidationReport {
        name: result.command.clone(),
        status: if result.success {
            ValidationStatus::Passed
        } else {
            ValidationStatus::Failed
        },
        message: result.error.clone(),
        paths: Vec::new(),
    }
}

fn run_git_apply(
    worktree_path: &Path,
    patch: &str,
    timeout: Duration,
    runtime: AgentExecutionRuntime,
) -> Result<ProcessOutput> {
    let process_spec = ProcessSpec::direct(
        "git apply",
        "git",
        ["apply", "--whitespace=nowarn", "--binary", "-"],
        worktree_path,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(sandbox_environment()))
    .with_stdin(StdinMode::Bytes(patch.as_bytes().to_vec()))
    .with_timeout(Some(timeout));
    let output = run_process(match runtime {
        AgentExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                git_apply_workspace_profile(worktree_path)?,
            )),
        #[cfg(test)]
        AgentExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })
    .with_context(|| format!("failed to run git apply in {}", worktree_path.display()))?;
    if output.timed_out {
        bail!("git apply timed out after {} seconds", timeout.as_secs());
    }
    let succeeded = match runtime {
        AgentExecutionRuntime::Verified => output.safety_sensitive_succeeded(),
        #[cfg(test)]
        AgentExecutionRuntime::NonpublishableSimulation => {
            output.status.is_some_and(|status| status.success())
                && !output.timed_out
                && output.process_error.is_none()
                && output.stdin_error.is_none()
        }
    };
    if !succeeded {
        if let Some(error) = output
            .stdin_error
            .as_deref()
            .or(output.process_error.as_deref())
        {
            bail!("{error}");
        }
        bail!(
            "git apply was not safely verified: exit={:?}; process_tree={:?}; side_effects={:?}",
            output.status.and_then(|status| status.code()),
            output.process_tree,
            output.side_effects
        );
    }
    Ok(ProcessOutput {
        status: output.status,
        stdout: summarize_output(&output.stdout),
        stderr: summarize_output(&output.stderr),
    })
}

fn git_apply_workspace_profile(worktree_path: &Path) -> Result<StrictOfflineWorkspaceProfile> {
    let repository = crate::git_repository::open(worktree_path).with_context(|| {
        format!(
            "failed to resolve Git administration roots for git apply in {}",
            worktree_path.display()
        )
    })?;
    let common_dir = std::fs::canonicalize(repository.commondir()).with_context(|| {
        format!(
            "failed to resolve Git common directory {}",
            repository.commondir().display()
        )
    })?;
    let git_dir = std::fs::canonicalize(repository.path()).with_context(|| {
        format!(
            "failed to resolve Git directory {}",
            repository.path().display()
        )
    })?;
    let mut profile = StrictOfflineWorkspaceProfile::read_write(worktree_path)
        .with_visible_read_only_root(&common_dir);
    if git_dir != common_dir {
        profile = profile.with_visible_read_only_root(git_dir);
    }
    hide_sensitive_state_if_present(profile, &common_dir)
}

fn hide_sensitive_state_if_present(
    profile: StrictOfflineWorkspaceProfile,
    common_dir: &Path,
) -> Result<StrictOfflineWorkspaceProfile> {
    let state_path = common_dir.join("maco").join("state");
    match std::fs::symlink_metadata(&state_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(profile),
        Err(error) => Err(error).context(format!(
            "failed to inspect repository sensitive state {}",
            state_path.display()
        )),
        Ok(_) => Ok(profile.with_hidden_root(
            crate::artifacts::state_auth::sensitive_state_root(common_dir).context(
                "repository sensitive state could not be bound for child-process masking",
            )?,
        )),
    }
}

#[cfg(test)]
use std::fs;

#[derive(Debug, Clone)]
struct ProcessOutput {
    status: Option<ExitStatus>,
    stdout: OutputSummary,
    stderr: OutputSummary,
}

fn summarize_output(output: &CapturedBytes) -> OutputSummary {
    let summary = output.summarize_chars(OUTPUT_CHAR_LIMIT);
    OutputSummary {
        text: summary.text,
        truncated: summary.truncated,
    }
}

fn sandbox_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ])
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn display_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{
        FakeOutcome, FakeProvider, LlmProvider, LlmRequest, LlmResponse, ProposedCommand,
        ProposedPatch, ProviderCapabilities, ProviderError, WorkProposal,
    };
    use crate::sync_store::ClaimTiming;
    use git2::{Oid, Signature};
    use std::{io::Read, sync::mpsc, thread};
    use tempfile::TempDir;

    #[test]
    fn provider_rate_limit_crosses_agent_boundary_and_latches_workspace_pool() -> Result<()> {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let detail = "agent tokens per minute";
        let rolling_guard = crate::budget_ledger::bind_rolling_budget(
            &repo_path,
            crate::budget_ledger::RollingBudgetQuota {
                max_tokens: Some(10_000),
                max_cost_usd: None,
                window_seconds: 60,
            },
            "agent-rate-limit-run",
        )?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_outcome(
            "agent-run-rate-limit-agent",
            FakeOutcome::Failure(ProviderError::RateLimited(detail.to_string())),
        );

        let error = run_agent_with_provider(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "rate-limit-agent".to_string(),
                task: "Exercise the typed provider boundary".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::Disabled,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        )
        .expect_err("rate-limited provider must fail the agent run");
        assert_eq!(
            error.downcast_ref::<ProviderError>(),
            Some(&ProviderError::RateLimited(detail.to_string()))
        );
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());
        drop(rolling_guard);

        let ledger = crate::budget_ledger::WorkspaceBudgetLedger::open_or_create(&repo_path)?;
        let latch = ledger
            .active_rate_limit(
                crate::budget_ledger::DEFAULT_RATE_LIMIT_POOL,
                crate::budget_ledger::unix_now()?,
            )
            .context("agent provider boundary must latch the default workspace pool")?;
        assert_eq!(latch.pool, crate::budget_ledger::DEFAULT_RATE_LIMIT_POOL);
        assert_eq!(latch.detail, detail);
        assert_eq!(provider.calls().len(), 1);

        Ok(())
    }

    #[test]
    fn fake_provider_agent_run_edits_only_agent_worktree_and_releases_claim() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-agent-a",
            WorkProposal::summary("update readme").with_command(ProposedCommand::new(
                "printf '# Test\\n\\nagent edit\\n' > README.md",
                CommandPurpose::Implement,
            )),
        );

        let report = run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                task: "Update README".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::AllowUnsafeShell,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        )?;

        assert!(report.success);
        assert_eq!(report.provider_id, "fake");
        assert_eq!(
            report.candidate.changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert!(report.candidate.unclaimed_changed_paths.is_empty());
        assert_eq!(provider.calls().len(), 1);
        assert_eq!(fs::read_to_string(repo_path.join("README.md"))?, "# Test\n");
        assert_eq!(
            fs::read_to_string(report.worktree.path.join("README.md"))?,
            "# Test\n\nagent edit\n"
        );
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());

        Ok(())
    }

    #[test]
    fn fake_provider_agent_run_reports_unclaimed_changes() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-agent-a",
            WorkProposal::summary("edit unclaimed file").with_command(ProposedCommand::new(
                "printf 'pub fn changed() -> bool { true }\\n' > src/lib.rs",
                CommandPurpose::Implement,
            )),
        );

        let report = run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                task: "Update README".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::AllowUnsafeShell,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        )?;

        assert!(!report.success);
        assert_eq!(
            report.candidate.unclaimed_changed_paths,
            vec![PathBuf::from("src/lib.rs")]
        );
        assert!(report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("outside its claims"));
        assert_eq!(
            fs::read_to_string(repo_path.join("src/lib.rs"))?,
            "pub fn ok() -> bool { true }\n"
        );
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());

        Ok(())
    }

    #[test]
    fn provider_commands_are_disabled_by_default_and_not_executed() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-agent-a",
            WorkProposal::summary("try command").with_command(ProposedCommand::new(
                "printf hacked > README.md",
                CommandPurpose::Implement,
            )),
        );

        let report = run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                task: "Update README".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::Disabled,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        )?;

        assert!(!report.success);
        assert_eq!(report.command_results.len(), 1);
        assert!(!report.command_results[0].success);
        assert!(report.command_results[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("disabled"));
        assert_eq!(
            fs::read_to_string(report.worktree.path.join("README.md"))?,
            "# Test\n"
        );
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());

        Ok(())
    }

    #[test]
    fn allowed_provider_command_timeout_with_keep_claims_leaves_claim_active() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-agent-a",
            WorkProposal::summary("slow command")
                .with_command(ProposedCommand::new("sleep 2", CommandPurpose::Implement)),
        );

        let report = run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                task: "Run slowly".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: true,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::AllowUnsafeShell,
                command_timeout: Duration::from_secs(1),
            },
            &mut provider,
        )?;

        assert!(!report.success);
        assert_eq!(report.command_results.len(), 1);
        assert!(report.command_results[0].timed_out);
        assert!(report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("timed out"));
        let active_claims = SyncStore::open(&repo_path)?.snapshot()?;
        assert_eq!(active_claims.len(), 1);
        assert_eq!(active_claims[0].agent_id, "agent-a");
        assert_eq!(active_claims[0].paths, vec![PathBuf::from("README.md")]);
        assert!(report.released_claims.is_empty());
        assert!(report.release_errors.is_empty());

        Ok(())
    }

    #[test]
    fn fake_provider_patch_with_mismatched_diff_path_is_rejected_before_apply() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-agent-a",
            WorkProposal::summary("mismatched patch").with_patch(ProposedPatch::new(
                "README.md",
                "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
-pub fn ok() -> bool { true }
+pub fn changed() -> bool { true }
",
            )),
        );

        let report = run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "agent-a".to_string(),
                task: "Update README".to_string(),
                request_id: None,
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::Disabled,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        )?;

        assert!(!report.success);
        assert_eq!(report.patch_results.len(), 1);
        assert!(!report.patch_results[0].success);
        assert!(report.patch_results[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("do not include declared path"));
        assert_eq!(
            fs::read_to_string(report.worktree.path.join("src/lib.rs"))?,
            "pub fn ok() -> bool { true }\n"
        );
        assert_eq!(
            fs::read_to_string(repo_path.join("src/lib.rs"))?,
            "pub fn ok() -> bool { true }\n"
        );
        assert!(report.candidate.changed_paths.is_empty());
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());

        Ok(())
    }

    #[test]
    fn writable_fake_provider_e2e_is_reachable_without_network() -> Result<()> {
        // FakeProvider applies a canned patch on the simulation path. Candidate
        // snapshot capture still uses isolated git, so self-skip when that
        // sandbox is unavailable. A named writable-capability refusal is also
        // skipped; production fail-closed is unchanged.
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-fake-e2e",
            WorkProposal::summary("writable fake-provider e2e").with_patch(ProposedPatch::new(
                "README.md",
                "\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,3 @@
 # Test
+
+fake-provider writable e2e
",
            )),
        );

        let report = match run_agent_with_provider_simulation(
            AgentRunOptions {
                repo: repo_path.clone(),
                agent_id: "fake-e2e".to_string(),
                task: "Apply a canned fake-provider patch in an isolated worktree.".to_string(),
                request_id: Some("agent-run-fake-e2e".to_string()),
                model: None,
                claimed_paths: vec![PathBuf::from("README.md")],
                validation_commands: Vec::new(),
                keep_claims: false,
                worktree_reuse: AgentWorktreeReusePolicy::Clean,
                provider_command_policy: ProviderCommandPolicy::Disabled,
                command_timeout: DEFAULT_COMMAND_TIMEOUT,
            },
            &mut provider,
        ) {
            Ok(report) => report,
            Err(error) => {
                let message = format!("{error:#}");
                if message.contains("failed closed before launch")
                    && (message.contains("blocking_pre_action_callback != All")
                        || message.contains("writable_workspace != supported"))
                {
                    return Ok(());
                }
                return Err(error);
            }
        };

        assert!(report.success, "unexpected failed report: {report:#?}");
        assert_eq!(report.provider_id, "fake");
        assert_eq!(report.model, DEFAULT_MODEL);
        assert_eq!(
            report.candidate.changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert!(report.candidate.unclaimed_changed_paths.is_empty());
        assert_eq!(provider.calls().len(), 1);
        assert_eq!(fs::read_to_string(repo_path.join("README.md"))?, "# Test\n");
        assert_eq!(
            fs::read_to_string(report.worktree.path.join("README.md"))?,
            "# Test\n\nfake-provider writable e2e\n"
        );
        assert_ne!(report.worktree.path, repo_path);
        assert!(SyncStore::open(&repo_path)?.snapshot()?.is_empty());

        Ok(())
    }

    #[test]
    fn git_apply_uses_the_agent_command_timeout() -> Result<()> {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let patch = "\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-# Test
+# Changed
";

        let applied = run_git_apply(
            &repo_path,
            patch,
            Duration::from_secs(5),
            AgentExecutionRuntime::NonpublishableSimulation,
        )
        .context("bounded git apply should succeed")?;
        assert!(applied.status.is_some_and(|status| status.success()));
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))?,
            "# Changed\n"
        );

        let started = Instant::now();
        let error = run_git_apply(
            &repo_path,
            patch,
            Duration::ZERO,
            AgentExecutionRuntime::NonpublishableSimulation,
        )
        .expect_err("zero apply budget must expire");
        assert!(started.elapsed() < Duration::from_secs(2));
        let message = format!("{error:#}");
        assert!(
            message.contains("timed out") || message.contains("timeout"),
            "git apply must report a timeout, got: {message}"
        );

        Ok(())
    }

    #[test]
    fn git_apply_workspace_profile_exposes_linked_primary_git_roots() -> Result<()> {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("worktrees")),
            })
            .context("create linked worktree")?;
        let repository =
            crate::git_repository::open(&worktree.path).context("open linked worktree")?;
        let common_dir =
            fs::canonicalize(repository.commondir()).context("canonicalize commondir")?;
        let git_dir = fs::canonicalize(repository.path()).context("canonicalize gitdir")?;
        let objects =
            fs::canonicalize(common_dir.join("objects")).context("canonicalize objects")?;
        let worktree_path = fs::canonicalize(&worktree.path).context("canonicalize worktree")?;
        assert_ne!(
            git_dir, common_dir,
            "linked worktree must use a separate gitdir"
        );
        assert!(
            !common_dir.starts_with(&worktree_path),
            "primary Git common dir must live outside the linked worktree"
        );

        let profile = git_apply_workspace_profile(&worktree.path)?;
        let visible = profile.visible_read_only_roots();
        assert!(
            visible
                .iter()
                .any(|root| *root == common_dir || common_dir.starts_with(root)),
            "git apply profile must expose the primary Git common dir, got {visible:?}"
        );
        assert!(
            visible.iter().any(|root| objects.starts_with(root)),
            "git apply profile must expose the shared object store, got {visible:?}"
        );
        assert!(
            visible.iter().any(|root| git_dir.starts_with(root)),
            "git apply profile must expose the linked gitdir, got {visible:?}"
        );
        if let Ok(sensitive) = crate::artifacts::state_auth::sensitive_state_root(&common_dir) {
            assert!(
                profile.hidden_roots().contains(&sensitive),
                "git apply profile must hide repository sensitive state"
            );
        }

        Ok(())
    }

    struct PanicOnCompleteProvider;

    impl LlmProvider for PanicOnCompleteProvider {
        fn provider_id(&self) -> &str {
            "panic-provider"
        }

        fn capabilities(&self) -> ProviderCapabilities {
            ProviderCapabilities::local_fake()
        }

        fn complete(
            &mut self,
            _request: LlmRequest,
        ) -> std::result::Result<LlmResponse, ProviderError> {
            panic!("injected provider panic for write-lease RAII");
        }
    }

    struct DetachHeadOnComplete {
        inner: FakeProvider,
        worktree_path: PathBuf,
    }

    impl LlmProvider for DetachHeadOnComplete {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn capabilities(&self) -> ProviderCapabilities {
            self.inner.capabilities()
        }

        fn complete(
            &mut self,
            request: LlmRequest,
        ) -> std::result::Result<LlmResponse, ProviderError> {
            let repo = crate::git_repository::open(&self.worktree_path)
                .expect("open selected worktree before mutation");
            let oid = repo
                .head()
                .expect("read HEAD")
                .peel_to_commit()
                .expect("peel HEAD")
                .id();
            repo.set_head_detached(oid)
                .expect("detach HEAD to drift identity before mutation");
            self.inner.complete(request)
        }
    }

    fn default_agent_options(repo: PathBuf, agent_id: &str) -> AgentRunOptions {
        AgentRunOptions {
            repo,
            agent_id: agent_id.to_string(),
            task: "Update README".to_string(),
            request_id: None,
            model: None,
            claimed_paths: vec![PathBuf::from("README.md")],
            validation_commands: Vec::new(),
            keep_claims: false,
            worktree_reuse: AgentWorktreeReusePolicy::Clean,
            provider_command_policy: ProviderCommandPolicy::Disabled,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
        }
    }

    fn exclusive_same_worktree_ops_refused(manager: &WorktreeManager, agent_id: &str) {
        let write_err = manager
            .acquire_write_execution_lease(agent_id)
            .expect_err("competing writer must be refused");
        let write_msg = format!("{write_err:#}");
        assert!(
            write_msg.contains("kernel state lock is already held")
                || write_msg.contains("exclusive"),
            "competing writer must fail on the kernel/exclusive lease, got {write_msg}"
        );

        let read_err = manager
            .acquire_read_execution_lease(agent_id)
            .expect_err("competing reader must be refused");
        let read_msg = format!("{read_err:#}");
        assert!(
            read_msg.contains("kernel state lock is already held")
                || read_msg.contains("exclusive"),
            "competing reader must fail on the kernel/exclusive lease, got {read_msg}"
        );

        let remove_err = manager
            .remove(agent_id, true, false)
            .expect_err("competing removal must be refused");
        let remove_msg = format!("{remove_err:#}");
        assert!(
            remove_msg.contains("active cooperative execution lease")
                || remove_msg.contains("kernel state lock is already held"),
            "competing removal/rebind must fail on the cooperative/kernel lease, got {remove_msg}"
        );
    }

    #[cfg(unix)]
    fn create_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let cstr = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) }, 0);
    }

    #[cfg(unix)]
    fn wait_for_fifo_byte(path: &Path, timeout: Duration) {
        let (tx, rx) = mpsc::channel();
        let opened = path.to_path_buf();
        let display = path.display().to_string();
        thread::spawn(move || match fs::File::open(&opened) {
            Ok(mut file) => {
                let mut buf = [0u8; 1];
                let _ = file.read(&mut buf);
                let _ = tx.send(Ok(()));
            }
            Err(error) => {
                let _ = tx.send(Err(error));
            }
        });
        rx.recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("timed out waiting for fifo {display}"))
            .unwrap_or_else(|error| panic!("failed to open fifo {display}: {error}"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_write_lease_blocks_same_worktree_through_validation_collect_and_preview(
    ) -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let unrelated = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .context("create unrelated worktree")?;

        let ready_fifo = temp.path().join("validation-ready.fifo");
        let release_fifo = temp.path().join("validation-release.fifo");
        create_fifo(&ready_fifo);
        create_fifo(&release_fifo);

        let (stage_ready_tx, stage_ready_rx) = mpsc::channel();
        let (stage_release_tx, stage_release_rx) = mpsc::channel();
        let run_repo = repo_path.clone();
        let validation_command = format!(
            "printf x > '{}'; cat '{}'",
            ready_fifo.display(),
            release_fifo.display()
        );
        let runner = thread::spawn(move || {
            set_agent_protected_stage_hook(move |stage| {
                stage_ready_tx.send(stage).expect("publish protected stage");
                stage_release_rx
                    .recv_timeout(Duration::from_secs(60))
                    .expect("release protected stage");
            });
            let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
            provider.push_response(
                "agent-run-agent-a",
                WorkProposal::summary("update readme").with_command(ProposedCommand::new(
                    "printf '# Test\\n\\nagent edit\\n' > README.md",
                    CommandPurpose::Implement,
                )),
            );
            let mut options = default_agent_options(run_repo, "agent-a");
            options.validation_commands =
                vec![AgentValidationCommand::required(validation_command)];
            options.provider_command_policy = ProviderCommandPolicy::AllowUnsafeShell;
            let result = run_agent_with_provider_simulation(options, &mut provider);
            clear_agent_protected_stage_hook();
            result
        });

        let after_revalidation = stage_ready_rx
            .recv_timeout(Duration::from_secs(60))
            .context("timed out waiting for after-revalidation")?;
        assert_eq!(after_revalidation, AgentProtectedStage::Revalidation);
        exclusive_same_worktree_ops_refused(&manager, "agent-a");
        let unrelated_before_mutation = manager
            .acquire_write_execution_lease("agent-b")
            .context("unrelated writer must remain available before mutation")?;
        assert_eq!(unrelated_before_mutation.path(), unrelated.path.as_path());
        drop(unrelated_before_mutation);
        stage_release_tx
            .send(())
            .context("release after-revalidation")?;

        wait_for_fifo_byte(&ready_fifo, Duration::from_secs(10));
        exclusive_same_worktree_ops_refused(&manager, "agent-a");
        let unrelated_during_validation = manager
            .acquire_write_execution_lease("agent-b")
            .context("unrelated writer must remain available during validation")?;
        assert_eq!(unrelated_during_validation.path(), unrelated.path.as_path());
        drop(unrelated_during_validation);
        fs::write(&release_fifo, b"go").context("release validation fifo")?;

        for expected in [
            AgentProtectedStage::Validation,
            AgentProtectedStage::Collect,
            AgentProtectedStage::Preview,
        ] {
            let stage = stage_ready_rx
                .recv_timeout(Duration::from_secs(60))
                .with_context(|| format!("timed out waiting for {expected:?}"))?;
            assert_eq!(stage, expected);
            exclusive_same_worktree_ops_refused(&manager, "agent-a");
            let unrelated_lease = manager
                .acquire_write_execution_lease("agent-b")
                .with_context(|| {
                    format!("unrelated writer must remain available at {expected:?}")
                })?;
            assert_eq!(unrelated_lease.path(), unrelated.path.as_path());
            drop(unrelated_lease);
            stage_release_tx
                .send(())
                .with_context(|| format!("release {expected:?}"))?;
        }

        let report = runner.join().expect("join agent run")?;
        assert!(report.success, "unexpected failed report: {report:?}");
        assert_eq!(
            report.candidate.changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert_eq!(
            report.merge_preview.candidate.changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert_eq!(
            fs::read_to_string(report.worktree.path.join("README.md"))?,
            "# Test\n\nagent edit\n"
        );

        let released = manager
            .acquire_write_execution_lease("agent-a")
            .context("success must RAII-release the write lease")?;
        drop(released);
        Ok(())
    }

    #[cfg(unix)]
    fn peek_agent_liveness(
        repo_path: &Path,
        agent_id: &str,
    ) -> Result<crate::sync_store::PeekedClaimLiveness> {
        crate::sync_store::peek_liveness_without_claims_lock(repo_path)?
            .into_iter()
            .find(|row| row.agent_id == agent_id)
            .with_context(|| format!("missing peeked liveness for {agent_id}"))
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_guard_owned_heartbeat_ticks_during_blocking_child() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let store = SyncStore::open(&repo_path)?;
        let foreign = store
            .claim_paths("foreign-agent", [PathBuf::from("src/lib.rs")])?
            .clone();
        let foreign_before = peek_agent_liveness(&repo_path, "foreign-agent")?;

        let ready_fifo = temp.path().join("heartbeat-ready.fifo");
        let release_fifo = temp.path().join("heartbeat-release.fifo");
        create_fifo(&ready_fifo);
        create_fifo(&release_fifo);

        let run_repo = repo_path.clone();
        let validation_command = format!(
            "printf x > '{}'; cat '{}'",
            ready_fifo.display(),
            release_fifo.display()
        );
        let runner = thread::spawn(move || {
            set_agent_claim_timing_for_test(ClaimTiming::new(1, 3).expect("timing"));
            let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
            provider.push_response(
                "agent-run-agent-a",
                WorkProposal::summary("update readme").with_command(ProposedCommand::new(
                    "printf '# Test\\n\\nagent edit\\n' > README.md",
                    CommandPurpose::Implement,
                )),
            );
            let mut options = default_agent_options(run_repo, "agent-a");
            options.keep_claims = true;
            options.validation_commands =
                vec![AgentValidationCommand::required(validation_command)];
            options.provider_command_policy = ProviderCommandPolicy::AllowUnsafeShell;
            run_agent_with_provider_simulation(options, &mut provider)
        });

        wait_for_fifo_byte(&ready_fifo, Duration::from_secs(30));
        let baseline = peek_agent_liveness(&repo_path, "agent-a")?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut observed = baseline.heartbeat_unix_seconds;
        while Instant::now() < deadline {
            if let Ok(row) = peek_agent_liveness(&repo_path, "agent-a") {
                observed = row.heartbeat_unix_seconds;
                if observed >= baseline.heartbeat_unix_seconds + 2 {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            observed > baseline.heartbeat_unix_seconds,
            "must observe disk heartbeat_unix_seconds advance while the child is blocked (baseline={}, observed={})",
            baseline.heartbeat_unix_seconds,
            observed
        );
        fs::write(&release_fifo, b"go").context("release validation fifo")?;

        let report = runner.join().expect("join agent run")?;
        assert!(report.success, "unexpected failed report: {report:?}");
        let claim = report.claim.as_ref().context("kept claim")?;
        assert_eq!(claim.agent_id, "agent-a");
        assert_eq!(claim.paths, vec![PathBuf::from("README.md")]);
        assert_eq!(claim.token, baseline.token);
        let after = peek_agent_liveness(&repo_path, "agent-a")?;
        assert_eq!(after.paths, vec![PathBuf::from("README.md")]);
        assert_eq!(after.run_owner_count, 0);
        assert!(after.takeover_eligible_since_unix_seconds.is_none());
        let foreign_after = peek_agent_liveness(&repo_path, "foreign-agent")?;
        assert_eq!(foreign_after.token, foreign.token);
        assert_eq!(
            foreign_after.heartbeat_unix_seconds,
            foreign_before.heartbeat_unix_seconds
        );
        assert_eq!(foreign_after.paths, foreign.paths);
        let sweep = store.sweep_stale()?;
        assert!(
            !sweep
                .newly_takeover_eligible
                .iter()
                .any(|claim_id| claim_id == &after.claim_id),
            "live ticking claim must not become takeover-eligible: {:?}",
            sweep.newly_takeover_eligible
        );
        store
            .takeover(claim.token, "other-agent", None)
            .expect_err("takeover of a live ticking claim must fail");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_guard_lifetime_blocks_competing_claim_ops_during_fifo_hold() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let store = SyncStore::open(&repo_path)?;
        let ready_fifo = temp.path().join("block-ready.fifo");
        let release_fifo = temp.path().join("block-release.fifo");
        create_fifo(&ready_fifo);
        create_fifo(&release_fifo);
        let run_repo = repo_path.clone();
        let validation_command = format!(
            "printf x > '{}'; cat '{}'",
            ready_fifo.display(),
            release_fifo.display()
        );
        let runner = thread::spawn(move || {
            set_agent_claim_timing_for_test(ClaimTiming::new(1, 3).expect("timing"));
            let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
            provider.push_response(
                "agent-run-agent-a",
                WorkProposal::summary("update readme").with_command(ProposedCommand::new(
                    "printf '# Test\\n\\nagent edit\\n' > README.md",
                    CommandPurpose::Implement,
                )),
            );
            let mut options = default_agent_options(run_repo, "agent-a");
            options.keep_claims = true;
            options.validation_commands =
                vec![AgentValidationCommand::required(validation_command)];
            options.provider_command_policy = ProviderCommandPolicy::AllowUnsafeShell;
            run_agent_with_provider_simulation(options, &mut provider)
        });

        wait_for_fifo_byte(&ready_fifo, Duration::from_secs(30));
        let live = peek_agent_liveness(&repo_path, "agent-a")?;
        let token = live.token;
        let release_store = store.clone();
        let takeover_store = store.clone();
        let heartbeat_store = store.clone();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (takeover_tx, takeover_rx) = mpsc::sync_channel(1);
        let (heartbeat_tx, heartbeat_rx) = mpsc::sync_channel(1);
        let release = thread::spawn(move || {
            let result = release_store.release(token).map(|claim| claim.token);
            let _ = release_tx.send(result);
        });
        let takeover = thread::spawn(move || {
            let result = takeover_store.takeover(token, "other-agent", None);
            let _ = takeover_tx.send(result.map(|outcome| outcome.claim.token));
        });
        let heartbeat = thread::spawn(move || {
            let result = heartbeat_store.heartbeat(token, "agent-a", None);
            let _ = heartbeat_tx.send(result.map(|report| report.claim.token));
        });
        assert!(
            release_rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "competing release must not complete while the guard holds claims.lock"
        );
        assert!(
            takeover_rx.try_recv().is_err(),
            "competing takeover must not complete while the guard holds claims.lock"
        );
        assert!(
            heartbeat_rx.try_recv().is_err(),
            "ordinary heartbeat must remain the timeout path while the guard holds claims.lock"
        );
        fs::write(&release_fifo, b"go").context("release validation fifo")?;
        let report = runner.join().expect("join agent run")?;
        assert!(report.success, "unexpected failed report: {report:?}");
        let _ = release_rx.recv_timeout(Duration::from_secs(6));
        let _ = takeover_rx.recv_timeout(Duration::from_millis(200));
        let _ = heartbeat_rx.recv_timeout(Duration::from_millis(200));
        let _ = release.join();
        let _ = takeover.join();
        let _ = heartbeat.join();
        let remaining = store.snapshot()?;
        if remaining.iter().any(|claim| claim.token == token) {
            let started = Instant::now();
            store.release(token)?;
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "release after drop+join must proceed"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_releases_write_lease_after_provider_error() -> Result<()> {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_failure("agent-run-error-agent", "injected provider failure");
        let error = run_agent_with_provider(
            default_agent_options(repo_path.clone(), "error-agent"),
            &mut provider,
        )
        .expect_err("injected provider failure must fail the agent run");
        assert!(
            error.to_string().contains("injected provider failure")
                || format!("{error:#}").contains("injected provider failure"),
            "unexpected provider error: {error:#}"
        );
        let released = manager
            .acquire_write_execution_lease("error-agent")
            .context("provider error must RAII-release the write lease")?;
        drop(released);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_releases_write_lease_after_provider_panic() -> Result<()> {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut provider = PanicOnCompleteProvider;
            run_agent_with_provider(
                default_agent_options(repo_path.clone(), "panic-agent"),
                &mut provider,
            )
        }));
        assert!(panicked.is_err(), "provider panic must unwind");
        let released = manager
            .acquire_write_execution_lease("panic-agent")
            .context("provider panic must RAII-release the write lease")?;
        drop(released);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_releases_write_lease_after_timeout_and_keep_claims() -> Result<()> {
        skip_without_containment!(ok);
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let block_fifo = temp.path().join("timeout-block.fifo");
        create_fifo(&block_fifo);
        let mut provider = FakeProvider::new("fake", DEFAULT_MODEL);
        provider.push_response(
            "agent-run-timeout-agent",
            WorkProposal::summary("block until timeout").with_command(ProposedCommand::new(
                format!("cat '{}'", block_fifo.display()),
                CommandPurpose::Implement,
            )),
        );
        let mut options = default_agent_options(repo_path.clone(), "timeout-agent");
        options.keep_claims = true;
        options.provider_command_policy = ProviderCommandPolicy::AllowUnsafeShell;
        options.command_timeout = Duration::from_secs(1);
        let report = run_agent_with_provider_simulation(options, &mut provider)?;
        assert!(!report.success);
        assert_eq!(report.command_results.len(), 1);
        assert!(report.command_results[0].timed_out);
        let active_claims = SyncStore::open(&repo_path)?.snapshot()?;
        assert_eq!(active_claims.len(), 1);
        assert_eq!(active_claims[0].agent_id, "timeout-agent");
        assert!(report.released_claims.is_empty());
        let released = manager
            .acquire_write_execution_lease("timeout-agent")
            .context("timeout/keep_claims must RAII-release the write lease")?;
        drop(released);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agent_run_identity_drift_before_mutation_refuses_before_artifact_publication() -> Result<()>
    {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "drift-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .context("pre-create worktree")?;
        let original = fs::read_to_string(worktree.path.join("README.md"))?;
        let mut inner = FakeProvider::new("fake", DEFAULT_MODEL);
        inner.push_response(
            "agent-run-drift-agent",
            WorkProposal::summary("mutate after drift").with_patch(ProposedPatch::new(
                "README.md",
                "\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,3 @@
 # Test
+
+should not be published
",
            )),
        );
        let mut provider = DetachHeadOnComplete {
            inner,
            worktree_path: worktree.path.clone(),
        };
        let mut options = default_agent_options(repo_path.clone(), "drift-agent");
        options.worktree_reuse = AgentWorktreeReusePolicy::Required;
        let error = run_agent_with_provider(options, &mut provider)
            .expect_err("identity drift must fail closed before mutation");
        let message = format!("{error:#}");
        assert!(
            message.contains("pre-mutation revalidation failed")
                || message.contains("detached")
                || message.contains("OID mismatch")
                || message.contains("branch"),
            "unexpected identity-drift error: {message}"
        );
        assert_eq!(
            fs::read_to_string(worktree.path.join("README.md"))?,
            original,
            "drift must refuse before publishing worktree artifacts"
        );
        assert_eq!(fs::read_to_string(repo_path.join("README.md"))?, "# Test\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn path_claim_and_revalidation_guard_without_write_lease_allow_competing_writer() -> Result<()>
    {
        let temp = TempDir::new().context("tempdir")?;
        let repo_path = create_committed_repo(temp.path())?;
        let manager = WorktreeManager::new(&repo_path);
        let worktree = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .context("create worktree")?;
        let store = SyncStore::open(&repo_path)?;
        let claim = store.claim_paths("agent-a", [PathBuf::from("README.md")])?;
        let guard = crate::collect_revalidation::revalidate_claimed_worker(
            &repo_path,
            "agent-a",
            claim.token,
            &claim.paths,
            &worktree,
        )
        .context("claims-only revalidation guard")?;
        let competing = manager.acquire_write_execution_lease("agent-a").context(
            "negative control: claim+guard without write lease must still allow a competing writer",
        )?;
        drop(competing);
        drop(guard);
        Ok(())
    }

    fn create_committed_repo(root: &Path) -> Result<PathBuf> {
        let repo_path = root.join("repo");
        WorktreeManager::init_repository(&repo_path, "main")?;
        fs::create_dir_all(repo_path.join("src")).context("create src")?;
        fs::write(repo_path.join("README.md"), "# Test\n").context("write readme")?;
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub fn ok() -> bool { true }\n",
        )
        .context("write lib")?;
        let repo = crate::git_repository::open(&repo_path).context("open repo")?;
        commit_all(&repo, "initial commit")?;
        Ok(repo_path)
    }

    fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
        let mut index = repo.index().context("open index")?;
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .context("add all")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        repo.commit(Some("HEAD"), &signature, &signature, message, &tree, &[])
            .context("commit")
    }
}
