use crate::{
    sync::{normalize_repo_relative_path, ClaimToken, PathClaim},
    sync_store::SyncStore,
    worktree::{normalize_agent_id, WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestrationPlan {
    pub agents: Vec<AgentPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPlan {
    pub id: String,
    pub paths: Vec<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<Duration>,
    pub command: String,
    pub depends_on: Vec<String>,
    pub working_directory: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct OrchestrationRunOptions {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub keep_claims: bool,
    pub jobs: usize,
    pub patch_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrchestrationSummary {
    pub repo: PathBuf,
    pub plan_file: PathBuf,
    pub keep_claims: bool,
    pub success: bool,
    pub agents: Vec<AgentRunSummary>,
    pub released_claims: Vec<PathClaim>,
    pub release_errors: Vec<String>,
}

impl OrchestrationSummary {
    pub fn first_failed_agent(&self) -> Option<&str> {
        self.agents
            .iter()
            .find(|agent| agent.status == AgentRunStatus::Failed)
            .map(|agent| agent.id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentRunSummary {
    pub id: String,
    pub paths: Vec<PathBuf>,
    pub depends_on: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub command: String,
    pub timeout_seconds: Option<u64>,
    pub worktree: Option<WorktreeRecord>,
    pub worktree_reused: bool,
    pub claim: Option<PathClaim>,
    pub status: AgentRunStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub timed_out: bool,
    pub changed_paths: Vec<PathBuf>,
    pub unclaimed_changed_paths: Vec<PathBuf>,
    pub patch_path: Option<PathBuf>,
    pub stdout: OutputSummary,
    pub stderr: OutputSummary,
    pub error: Option<String>,
}

impl AgentRunSummary {
    fn pending(agent: &AgentPlan) -> Self {
        Self {
            id: agent.id.clone(),
            paths: agent.paths.clone(),
            depends_on: agent.depends_on.clone(),
            working_directory: agent.working_directory.clone(),
            command: agent.command.clone(),
            timeout_seconds: agent.timeout.map(|timeout| timeout.as_secs()),
            worktree: None,
            worktree_reused: false,
            claim: None,
            status: AgentRunStatus::Pending,
            exit_code: None,
            duration_ms: None,
            timed_out: false,
            changed_paths: Vec::new(),
            unclaimed_changed_paths: Vec::new(),
            patch_path: None,
            stdout: OutputSummary::default(),
            stderr: OutputSummary::default(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Pending,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlan {
    agents: Vec<RawAgentPlan>,
    #[serde(default)]
    default_timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentPlan {
    id: String,
    paths: Vec<PathBuf>,
    command: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default, alias = "cwd")]
    working_directory: Option<PathBuf>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

pub fn load_plan(path: impl AsRef<Path>) -> Result<OrchestrationPlan> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read orchestration plan {}", path.display()))?;
    let raw: RawPlan = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse orchestration plan {}", path.display()))?;

    validate_plan(raw)
}

pub fn run_plan_file(options: OrchestrationRunOptions) -> Result<OrchestrationSummary> {
    let plan = load_plan(&options.plan_file)?;
    run_plan(plan, options)
}

pub fn run_plan(
    plan: OrchestrationPlan,
    options: OrchestrationRunOptions,
) -> Result<OrchestrationSummary> {
    if options.jobs == 0 {
        bail!("orchestration jobs must be at least 1");
    }

    let repo = discover_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo);
    let store = SyncStore::open(&repo)?;
    let mut summaries = plan
        .agents
        .iter()
        .map(AgentRunSummary::pending)
        .collect::<Vec<_>>();
    let mut acquired_tokens = Vec::new();

    let worktrees = select_worktrees(&manager, &plan)?;
    for (summary, worktree) in summaries.iter_mut().zip(worktrees) {
        summary.worktree_reused = worktree.reused;
        summary.worktree = Some(worktree.record);
    }

    for (index, agent) in plan.agents.iter().enumerate() {
        let claim = match store.claim_paths(&agent.id, agent.paths.iter()) {
            Ok(claim) => claim,
            Err(error) => {
                summaries[index].status = AgentRunStatus::Failed;
                summaries[index].error = Some(format!("failed to claim paths: {error}"));
                for (skipped_index, skipped) in summaries.iter_mut().enumerate() {
                    if skipped_index != index && skipped.status == AgentRunStatus::Pending {
                        skipped.status = AgentRunStatus::Skipped;
                        skipped.error = Some(format!(
                            "skipped because paths could not be claimed for agent '{}'",
                            agent.id
                        ));
                    }
                }
                let (released_claims, release_errors) = if options.keep_claims {
                    (Vec::new(), Vec::new())
                } else {
                    release_claims(&store, acquired_tokens)
                };
                return Ok(OrchestrationSummary {
                    repo,
                    plan_file: options.plan_file,
                    keep_claims: options.keep_claims,
                    success: false,
                    agents: summaries,
                    released_claims,
                    release_errors,
                });
            }
        };
        acquired_tokens.push(claim.token);
        summaries[index].claim = Some(claim);
    }

    run_agent_schedule(
        &plan,
        &mut summaries,
        options.jobs,
        options.patch_dir.as_deref(),
    )?;

    let (released_claims, release_errors) = if options.keep_claims {
        (Vec::new(), Vec::new())
    } else {
        release_claims(&store, acquired_tokens)
    };
    let success = release_errors.is_empty()
        && summaries
            .iter()
            .all(|summary| summary.status == AgentRunStatus::Succeeded);

    Ok(OrchestrationSummary {
        repo,
        plan_file: options.plan_file,
        keep_claims: options.keep_claims,
        success,
        agents: summaries,
        released_claims,
        release_errors,
    })
}

fn validate_plan(raw: RawPlan) -> Result<OrchestrationPlan> {
    if raw.agents.is_empty() {
        bail!("orchestration plan must include at least one agent");
    }
    if matches!(raw.default_timeout_seconds, Some(0)) {
        bail!("default timeout must be greater than zero seconds");
    }

    let mut seen_agents = BTreeSet::new();
    let mut claimed_paths = Vec::<PlanPathOwner>::new();
    let mut agents = Vec::with_capacity(raw.agents.len());

    for raw_agent in raw.agents {
        let id = normalize_agent_id(&raw_agent.id)?;
        if !seen_agents.insert(id.clone()) {
            bail!("orchestration plan contains duplicate agent id '{id}'");
        }

        let command = raw_agent.command.trim().to_string();
        if command.is_empty() {
            bail!("agent '{id}' command cannot be empty");
        }

        let timeout_seconds = raw_agent
            .timeout_seconds
            .or(raw.default_timeout_seconds)
            .map(validate_timeout_seconds)
            .transpose()
            .with_context(|| format!("agent '{id}' has invalid timeout"))?;
        let timeout = timeout_seconds.map(Duration::from_secs);

        let working_directory = normalize_working_directory(raw_agent.working_directory)
            .with_context(|| format!("agent '{id}' has invalid working_directory"))?;
        validate_env(&id, &raw_agent.env)?;

        let paths = normalize_plan_paths(raw_agent.paths)
            .with_context(|| format!("agent '{id}' has invalid path claims"))?;
        for path in &paths {
            if let Some(owner) = claimed_paths
                .iter()
                .find(|owner| paths_overlap(path, &owner.path))
            {
                bail!(
                    "path '{}' for agent '{}' overlaps path '{}' for agent '{}'",
                    path.display(),
                    id,
                    owner.path.display(),
                    owner.agent_id
                );
            }
        }
        claimed_paths.extend(paths.iter().cloned().map(|path| PlanPathOwner {
            agent_id: id.clone(),
            path,
        }));

        let depends_on = raw_agent
            .depends_on
            .into_iter()
            .map(|dependency| normalize_agent_id(&dependency))
            .collect::<Result<BTreeSet<_>>>()?
            .into_iter()
            .collect::<Vec<_>>();

        agents.push(AgentPlan {
            id,
            paths,
            env: raw_agent.env,
            timeout,
            command,
            depends_on,
            working_directory,
        });
    }

    validate_dependencies(&agents, &seen_agents)?;

    Ok(OrchestrationPlan { agents })
}

fn validate_timeout_seconds(seconds: u64) -> Result<u64> {
    if seconds == 0 {
        bail!("timeout must be greater than zero seconds");
    }

    Ok(seconds)
}

fn validate_env(agent_id: &str, env: &BTreeMap<String, String>) -> Result<()> {
    for key in env.keys() {
        if key.trim().is_empty() {
            bail!("agent '{agent_id}' environment variable names cannot be empty");
        }
        if key.contains('=') {
            bail!("agent '{agent_id}' environment variable names cannot contain '='");
        }
    }

    Ok(())
}

fn normalize_working_directory(path: Option<PathBuf>) -> Result<Option<PathBuf>> {
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

fn validate_dependencies(agents: &[AgentPlan], seen_agents: &BTreeSet<String>) -> Result<()> {
    for agent in agents {
        for dependency in &agent.depends_on {
            if dependency == &agent.id {
                bail!("agent '{}' cannot depend on itself", agent.id);
            }
            if !seen_agents.contains(dependency) {
                bail!(
                    "agent '{}' depends on unknown agent '{}'",
                    agent.id,
                    dependency
                );
            }
        }
    }

    ensure_acyclic_dependencies(agents)
}

fn ensure_acyclic_dependencies(agents: &[AgentPlan]) -> Result<()> {
    let mut remaining = agents
        .iter()
        .map(|agent| agent.id.clone())
        .collect::<BTreeSet<_>>();
    let dependencies = agents
        .iter()
        .map(|agent| {
            (
                agent.id.clone(),
                agent.depends_on.iter().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .find(|agent_id| {
                dependencies
                    .get(*agent_id)
                    .map(|agent_dependencies| {
                        agent_dependencies
                            .iter()
                            .all(|dependency| !remaining.contains(dependency))
                    })
                    .unwrap_or(false)
            })
            .cloned();

        let Some(agent_id) = ready else {
            bail!("orchestration plan contains a dependency cycle");
        };
        remaining.remove(&agent_id);
    }

    Ok(())
}

fn normalize_plan_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;

    if paths.is_empty() {
        bail!("path claims cannot be empty");
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

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[derive(Debug, Clone)]
struct PlanPathOwner {
    agent_id: String,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct SelectedWorktree {
    record: WorktreeRecord,
    reused: bool,
}

fn select_worktrees(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
) -> Result<Vec<SelectedWorktree>> {
    let mut existing = manager
        .list()?
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::with_capacity(plan.agents.len());

    for agent in &plan.agents {
        if let Some(record) = existing.remove(&agent.id) {
            ensure_reusable_worktree(&record)?;
            selected.push(SelectedWorktree {
                record,
                reused: true,
            });
            continue;
        }

        let record = manager.create(WorktreeCreateOptions {
            agent_id: agent.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        })?;
        selected.push(SelectedWorktree {
            record,
            reused: false,
        });
    }

    Ok(selected)
}

fn ensure_reusable_worktree(record: &WorktreeRecord) -> Result<()> {
    let repo = Repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    let statuses = collect_status_paths(&repo)?;
    if !statuses.is_empty() {
        bail!(
            "refusing to reuse dirty worktree '{}' at {}; remove it or clean it before rerunning",
            record.name,
            record.path.display()
        );
    }

    Ok(())
}

fn run_agent_schedule(
    plan: &OrchestrationPlan,
    summaries: &mut [AgentRunSummary],
    jobs: usize,
    patch_dir: Option<&Path>,
) -> Result<()> {
    let jobs = jobs.max(1);
    let mut remaining = (0..plan.agents.len()).collect::<BTreeSet<_>>();
    let mut succeeded = BTreeSet::<String>::new();

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .copied()
            .filter(|index| {
                plan.agents[*index]
                    .depends_on
                    .iter()
                    .all(|dependency| succeeded.contains(dependency))
            })
            .take(jobs)
            .collect::<Vec<_>>();

        if ready.is_empty() {
            for index in remaining {
                summaries[index].status = AgentRunStatus::Skipped;
                summaries[index].error =
                    Some("skipped because dependencies could not be satisfied".to_string());
            }
            break;
        }

        let outcomes = run_ready_agents(plan, summaries, &ready)?;
        let mut failed_agent = None;

        for (index, run_result) in outcomes {
            apply_command_result(&mut summaries[index], run_result);
            inspect_agent_changes(&plan.agents[index], &mut summaries[index], patch_dir);
            remaining.remove(&index);

            if summaries[index].status == AgentRunStatus::Succeeded {
                succeeded.insert(summaries[index].id.clone());
            } else if failed_agent.is_none() {
                failed_agent = Some(summaries[index].id.clone());
            }
        }

        if let Some(failed_agent) = failed_agent {
            for index in remaining {
                summaries[index].status = AgentRunStatus::Skipped;
                summaries[index].error =
                    Some(format!("skipped because agent '{failed_agent}' failed"));
            }
            break;
        }
    }

    Ok(())
}

fn run_ready_agents(
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    ready: &[usize],
) -> Result<Vec<(usize, std::io::Result<CommandRunResult>)>> {
    if ready.len() == 1 {
        let index = ready[0];
        let spec = command_spec(&plan.agents[index], &summaries[index])?;
        return Ok(vec![(index, run_agent_command(spec))]);
    }

    let mut handles = Vec::with_capacity(ready.len());
    for index in ready {
        let spec = command_spec(&plan.agents[*index], &summaries[*index])?;
        let index = *index;
        handles.push((
            index,
            thread::spawn(move || (index, run_agent_command(spec))),
        ));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for (index, handle) in handles {
        let outcome = handle.join().unwrap_or_else(|_| {
            (
                index,
                Ok(CommandRunResult {
                    status: None,
                    duration_ms: 0,
                    timed_out: false,
                    stdout: OutputSummary::default(),
                    stderr: OutputSummary::default(),
                    process_error: Some("agent command runner panicked".to_string()),
                }),
            )
        });
        outcomes.push(outcome);
    }

    outcomes.sort_by_key(|(index, _)| *index);
    Ok(outcomes)
}

fn inspect_agent_changes(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    patch_dir: Option<&Path>,
) {
    let Some(worktree) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree");
        return;
    };
    let worktree_path = worktree.path.clone();

    let repo = match Repository::open(&worktree_path) {
        Ok(repo) => repo,
        Err(error) => {
            fail_summary(
                summary,
                format!(
                    "failed to inspect worktree changes at {}: {error}",
                    worktree_path.display()
                ),
            );
            return;
        }
    };

    let changed_paths = match collect_status_paths(&repo) {
        Ok(paths) => paths,
        Err(error) => {
            fail_summary(summary, format!("failed to collect changed paths: {error}"));
            return;
        }
    };
    let unclaimed_changed_paths = changed_paths
        .iter()
        .filter(|path| {
            !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect::<Vec<_>>();

    summary.changed_paths = changed_paths;
    summary.unclaimed_changed_paths = unclaimed_changed_paths;

    if !summary.unclaimed_changed_paths.is_empty() {
        let paths = summary
            .unclaimed_changed_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        fail_summary(
            summary,
            format!("agent changed paths outside its claims: {paths}"),
        );
    }

    if let Some(patch_dir) = patch_dir {
        match write_agent_patch(&worktree_path, &agent.id, patch_dir) {
            Ok(Some(path)) => summary.patch_path = Some(path),
            Ok(None) => {}
            Err(error) => fail_summary(summary, format!("failed to write patch: {error}")),
        }
    }
}

fn fail_summary(summary: &mut AgentRunSummary, message: impl Into<String>) {
    summary.status = AgentRunStatus::Failed;
    let message = message.into();
    summary.error = match summary.error.take() {
        Some(existing) => Some(format!("{existing}; {message}")),
        None => Some(message),
    };
}

fn collect_status_paths(repo: &Repository) -> Result<Vec<PathBuf>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect git status")?;
    let mut paths = statuses
        .iter()
        .filter_map(|entry| entry.path().map(PathBuf::from))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn write_agent_patch(
    worktree_path: &Path,
    agent_id: &str,
    patch_dir: &Path,
) -> Result<Option<PathBuf>> {
    fs::create_dir_all(patch_dir)
        .with_context(|| format!("failed to create patch directory {}", patch_dir.display()))?;
    mark_untracked_intent_to_add(worktree_path)?;

    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .arg("diff")
        .arg("--binary")
        .arg("HEAD")
        .output()
        .with_context(|| format!("failed to run git diff in {}", worktree_path.display()))?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.is_empty() {
        return Ok(None);
    }

    let patch_path = patch_dir.join(format!("{agent_id}.patch"));
    fs::write(&patch_path, output.stdout)
        .with_context(|| format!("failed to write patch {}", patch_path.display()))?;
    Ok(Some(patch_path))
}

fn mark_untracked_intent_to_add(worktree_path: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree_path)
        .arg("ls-files")
        .arg("--others")
        .arg("--exclude-standard")
        .arg("-z")
        .output()
        .with_context(|| {
            format!(
                "failed to list untracked files in {}",
                worktree_path.display()
            )
        })?;
    if !output.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(());
    }

    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(worktree_path)
        .arg("add")
        .arg("-N")
        .arg("--");
    for path in paths {
        command.arg(String::from_utf8_lossy(path).as_ref());
    }

    let output = command.output().with_context(|| {
        format!(
            "failed to mark untracked files in {}",
            worktree_path.display()
        )
    })?;
    if !output.status.success() {
        bail!(
            "git add -N failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn command_spec(agent: &AgentPlan, summary: &AgentRunSummary) -> Result<CommandRunSpec> {
    let worktree = summary
        .worktree
        .as_ref()
        .with_context(|| format!("agent '{}' has no selected worktree", summary.id))?;
    let working_directory = agent
        .working_directory
        .as_ref()
        .map(|path| worktree.path.join(path))
        .unwrap_or_else(|| worktree.path.clone());

    Ok(CommandRunSpec {
        command: agent.command.clone(),
        working_directory,
        env: agent.env.clone(),
        timeout: agent.timeout,
    })
}

#[derive(Debug, Clone)]
struct CommandRunSpec {
    command: String,
    working_directory: PathBuf,
    env: BTreeMap<String, String>,
    timeout: Option<Duration>,
}

fn run_agent_command(spec: CommandRunSpec) -> std::io::Result<CommandRunResult> {
    let started = Instant::now();
    let mut child = shell_command(&spec.command)
        .current_dir(&spec.working_directory)
        .envs(&spec.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let output = if let Some(timeout) = spec.timeout {
        loop {
            if child.try_wait()?.is_some() {
                let output = child.wait_with_output()?;
                break TimedOutput {
                    status: Some(output.status),
                    timed_out: false,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error: None,
                };
            }

            if started.elapsed() >= timeout {
                let kill_result = child.kill();
                let output = child.wait_with_output()?;
                break TimedOutput {
                    status: Some(output.status),
                    timed_out: true,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    process_error: kill_result
                        .err()
                        .map(|error| format!("command timed out but process kill failed: {error}")),
                };
            }

            thread::sleep(Duration::from_millis(25));
        }
    } else {
        let output = child.wait_with_output()?;
        TimedOutput {
            status: Some(output.status),
            timed_out: false,
            stdout: output.stdout,
            stderr: output.stderr,
            process_error: None,
        }
    };

    Ok(CommandRunResult {
        status: output.status,
        duration_ms: duration_millis(started.elapsed()),
        timed_out: output.timed_out,
        stdout: summarize_output(&output.stdout),
        stderr: summarize_output(&output.stderr),
        process_error: output.process_error,
    })
}

fn shell_command(command: &str) -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut shell = Command::new("cmd");
        shell.arg("/C").arg(command);
        shell
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut shell = Command::new("sh");
        shell.arg("-c").arg(command);
        shell
    }
}

#[derive(Debug, Clone)]
struct CommandRunResult {
    status: Option<ExitStatus>,
    duration_ms: u64,
    timed_out: bool,
    stdout: OutputSummary,
    stderr: OutputSummary,
    process_error: Option<String>,
}

#[derive(Debug)]
struct TimedOutput {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    process_error: Option<String>,
}

fn apply_command_result(summary: &mut AgentRunSummary, result: std::io::Result<CommandRunResult>) {
    match result {
        Ok(result) => {
            summary.exit_code = result.status.and_then(|status| status.code());
            summary.duration_ms = Some(result.duration_ms);
            summary.timed_out = result.timed_out;
            summary.stdout = result.stdout;
            summary.stderr = result.stderr;
            if let Some(error) = result.process_error {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(error);
            } else if result.timed_out {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match summary.timeout_seconds {
                    Some(seconds) => format!("command timed out after {seconds} seconds"),
                    None => "command timed out".to_string(),
                });
            } else if result.status.is_some_and(|status| status.success()) {
                summary.status = AgentRunStatus::Succeeded;
                summary.error = None;
            } else {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("command exited with status {code}"),
                    None => "command terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            summary.status = AgentRunStatus::Failed;
            summary.error = Some(format!("failed to run command: {error}"));
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

fn summarize_output(output: &[u8]) -> OutputSummary {
    let text = String::from_utf8_lossy(output);
    let mut chars = text.chars();
    let value = chars.by_ref().take(OUTPUT_CHAR_LIMIT).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn release_claims(store: &SyncStore, tokens: Vec<ClaimToken>) -> (Vec<PathClaim>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();

    for token in tokens {
        match store.release(token) {
            Ok(claim) => released.push(claim),
            Err(error) => errors.push(format!("failed to release claim {}: {error}", token.get())),
        }
    }

    (released, errors)
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("orchestration requires a non-bare repository")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_store::SyncStore;
    use crate::worktree::WorktreeManager;
    use git2::{Oid, Repository, Signature};
    use tempfile::TempDir;

    #[test]
    fn load_plan_normalizes_agent_ids_and_paths() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {
                  "id": " agent-a ",
                  "paths": ["src/../README.md", "src"],
                  "command": " echo ok "
                }
              ]
            }"#,
        )
        .expect("write plan");

        let plan = load_plan(&plan_path).expect("load plan");

        assert_eq!(plan.agents[0].id, "agent-a");
        assert_eq!(
            plan.agents[0].paths,
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );
        assert_eq!(plan.agents[0].command, "echo ok");
    }

    #[test]
    fn load_plan_accepts_dependencies_env_working_directory_and_timeout() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "default_timeout_seconds": 30,
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {
                  "id": "agent-b",
                  "paths": ["README.md"],
                  "depends_on": ["agent-a"],
                  "working_directory": "src",
                  "env": {"MACO_TEST": "ok"},
                  "timeout_seconds": 5,
                  "command": "echo b"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let plan = load_plan(&plan_path).expect("load plan");

        assert_eq!(plan.agents[0].timeout, Some(Duration::from_secs(30)));
        assert_eq!(plan.agents[1].depends_on, vec!["agent-a"]);
        assert_eq!(plan.agents[1].working_directory, Some(PathBuf::from("src")));
        assert_eq!(
            plan.agents[1].env.get("MACO_TEST").map(String::as_str),
            Some("ok")
        );
        assert_eq!(plan.agents[1].timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn load_plan_rejects_invalid_completion_criteria() {
        let cases = [
            (
                r#"{"agents":[]}"#,
                "orchestration plan must include at least one agent",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":[],"command":"echo a"}]}"#,
                "path claims cannot be empty",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"   "}]}"#,
                "command cannot be empty",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["/tmp"],"command":"echo a"}]}"#,
                "repository-relative",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["../src"],"command":"echo a"}]}"#,
                "escape repository",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"},{"id":"agent-a","paths":["README.md"],"command":"echo b"}]}"#,
                "duplicate agent id",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-missing"]}]}"#,
                "depends on unknown agent",
            ),
            (
                r#"{"agents":[{"id":"agent-a","paths":["src"],"command":"echo a","depends_on":["agent-a"]}]}"#,
                "cannot depend on itself",
            ),
            (
                r#"{"default_timeout_seconds":0,"agents":[{"id":"agent-a","paths":["src"],"command":"echo a"}]}"#,
                "default timeout",
            ),
        ];

        for (contents, expected) in cases {
            let temp = TempDir::new().expect("tempdir");
            let plan_path = temp.path().join("plan.json");
            fs::write(&plan_path, contents).expect("write plan");

            let error = load_plan(&plan_path).expect_err("plan should fail");
            let rendered = format!("{error:#}");

            assert!(
                rendered.contains(expected),
                "expected '{expected}' in '{rendered}'"
            );
        }
    }

    #[test]
    fn load_plan_rejects_dependency_cycles() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a", "depends_on": ["agent-b"]},
                {"id": "agent-b", "paths": ["README.md"], "command": "echo b", "depends_on": ["agent-a"]}
              ]
            }"#,
        )
        .expect("write plan");

        let error = load_plan(&plan_path).expect_err("cycle should fail");

        assert!(error.to_string().contains("dependency cycle"));
    }

    #[test]
    fn load_plan_rejects_overlapping_agent_paths() {
        let temp = TempDir::new().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(
            &plan_path,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["src"], "command": "echo a"},
                {"id": "agent-b", "paths": ["src/lib.rs"], "command": "echo b"}
              ]
            }"#,
        )
        .expect("write plan");

        let error = load_plan(&plan_path).expect_err("overlap should fail");

        assert!(error.to_string().contains("overlaps"));
    }

    #[test]
    fn run_plan_creates_worktree_runs_command_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["src"],
                  "command": "git rev-parse --is-inside-work-tree"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Succeeded);
        assert_eq!(summary.agents[0].stdout.text.trim(), "true");
        assert_eq!(summary.released_claims.len(), 1);
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
    }

    #[test]
    fn run_plan_reports_failed_command_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "false"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
    }

    #[test]
    fn run_plan_reports_claim_conflict_as_summary() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        SyncStore::open(&repo_path)
            .expect("open store")
            .claim_paths("other-agent", ["README.md"])
            .expect("preclaim");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert!(summary.agents[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to claim paths"));
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .owner_of("README.md")
                .expect("owner")
                .owner,
            Some("other-agent".to_string())
        );
    }

    #[test]
    fn run_plan_reports_unclaimed_changes_and_releases_claims() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::write(repo_path.join("Cargo.toml"), "[package]\n").expect("write cargo");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf 'changed\n' > Cargo.toml"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path.clone(),
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.first_failed_agent(), Some("agent-a"));
        assert_eq!(
            summary.agents[0].unclaimed_changed_paths,
            vec![PathBuf::from("Cargo.toml")]
        );
        assert_eq!(
            SyncStore::open(&repo_path)
                .expect("open store")
                .snapshot()
                .expect("snapshot"),
            Vec::<PathClaim>::new()
        );
    }

    #[test]
    fn run_plan_writes_patch_for_claimed_changes() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let patch_dir = temp.path().join("patches");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "command": "printf '# Changed\n' > README.md"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 1,
            patch_dir: Some(patch_dir.clone()),
        })
        .expect("run plan");

        assert!(summary.success);
        assert_eq!(
            summary.agents[0].changed_paths,
            vec![PathBuf::from("README.md")]
        );
        assert_eq!(
            summary.agents[0].patch_path,
            Some(patch_dir.join("agent-a.patch"))
        );
        let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).expect("read patch");
        assert!(patch.contains("# Changed"));
    }

    #[test]
    fn run_plan_times_out_and_skips_dependents() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");
        commit_all(&repo, "initial commit").expect("commit");
        let plan_file = temp.path().join("plan.json");
        fs::write(
            &plan_file,
            r#"{
              "agents": [
                {
                  "id": "agent-a",
                  "paths": ["README.md"],
                  "timeout_seconds": 1,
                  "command": "sleep 5"
                },
                {
                  "id": "agent-b",
                  "paths": ["src"],
                  "depends_on": ["agent-a"],
                  "command": "echo should-not-run"
                }
              ]
            }"#,
        )
        .expect("write plan");

        let summary = run_plan_file(OrchestrationRunOptions {
            repo: repo_path,
            plan_file,
            keep_claims: false,
            jobs: 2,
            patch_dir: None,
        })
        .expect("run plan");

        assert!(!summary.success);
        assert_eq!(summary.agents[0].status, AgentRunStatus::Failed);
        assert!(summary.agents[0].timed_out);
        assert_eq!(summary.agents[1].status, AgentRunStatus::Skipped);
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
