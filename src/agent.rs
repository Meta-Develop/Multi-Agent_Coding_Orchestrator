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
    worktree::{normalize_agent_id, WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
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

#[derive(Debug, Clone)]
struct SelectedWorktree {
    record: WorktreeRecord,
    reused: bool,
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
    let claim = store
        .claim_paths(&agent_id, claimed_paths.iter())
        .with_context(|| format!("failed to claim paths for agent '{agent_id}'"))?;
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
    let prompt = build_prompt(
        &run.selected.record.path,
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
        &run.selected.record,
    )
    .with_context(|| {
        format!(
            "pre-mutation revalidation failed for agent '{}'",
            run.agent_id
        )
    })?;

    for patch in &response.proposal.patches {
        let result = apply_proposed_patch(
            &run.selected.record.path,
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
            let result = run_proposed_command(
                &run.selected.record.path,
                command,
                run.command_timeout,
                run.runtime,
            );
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
            let result = run_proposed_command(
                &run.selected.record.path,
                command,
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

    if execution_error.is_none() {
        for validation in &run.validation_commands {
            let result = run_validation_command(
                &run.selected.record.path,
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

    let candidate = merge::collect_agent_result(MergeCollectOptions {
        repo: run.repo.clone(),
        agent_id: run.agent_id.clone(),
        claimed_paths: run.claimed_paths.clone(),
        include_full_diff: false,
        diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        validations: validations.clone(),
    })?;
    let merge_preview = merge::preview_merge_apply(MergePreviewOptions {
        collect: MergeCollectOptions {
            repo: run.repo.clone(),
            agent_id: run.agent_id.clone(),
            claimed_paths: run.claimed_paths.clone(),
            include_full_diff: true,
            diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations,
        },
        forces: MergeForceOptions::default(),
        require_validation: false,
        review_intent: merge::MergeApplyReviewIntent::default(),
    })?;

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

    Ok(AgentRunReport {
        success,
        repo: run.repo,
        agent_id: run.agent_id,
        request_id: response.request_id.clone(),
        provider_id: response.provider_id.clone(),
        model: response.model.clone(),
        worktree: run.selected.record,
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
        return Ok(SelectedWorktree {
            record,
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
    Ok(SelectedWorktree {
        record,
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
        FakeOutcome, FakeProvider, ProposedCommand, ProposedPatch, ProviderError, WorkProposal,
    };
    use git2::{Oid, Signature};
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
