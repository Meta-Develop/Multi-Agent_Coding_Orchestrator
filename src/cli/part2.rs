fn run_evaluation_command(args: RunEvaluationArgs) -> Result<()> {
    let manifest_bytes =
        BoundedRegularReader::read_tree_no_follow(&args.manifest, MAX_EVALUATION_MANIFEST_BYTES)
            .with_context(|| {
                format!(
                    "failed to read evaluation manifest {}",
                    args.manifest.display()
                )
            })?;
    let manifest = serde_json::from_slice::<crate::evaluation::EvaluationManifest>(&manifest_bytes)
        .with_context(|| {
            format!(
                "failed to parse evaluation manifest {}",
                args.manifest.display()
            )
        })?;
    let plan_bytes =
        BoundedRegularReader::read_tree_no_follow(&args.plan_file, MAX_EVALUATION_PLAN_BYTES)
            .with_context(|| {
                format!(
                    "failed to read hand-authored evaluation plan {}",
                    args.plan_file.display()
                )
            })?;

    // This legacy Phase-A runner generates synthetic fixtures only: it does not inspect the
    // repository or execute a provider, supervisor, held-out command, or isolated workflow.
    // Keep the reserved repository binding explicit so a future isolated runner can replace this
    // single call without silently changing the command contract.
    let _repo = args.repo;
    let results = crate::evaluation::run_evaluation(
        &manifest,
        &plan_bytes,
        crate::evaluation::EvaluationRunRequest {
            execution: args.execution,
            allow_real_provider: args.allow_real_provider,
            fake_seed: args.fake_seed,
        },
    )?;
    print_query_report(&results, args.json)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredEvaluationResultsFamily {
    Evaluation,
    Experiment,
}

fn run_evaluation_rescore_command(
    manifest_path: PathBuf,
    results_path: PathBuf,
    family: StoredEvaluationResultsFamily,
    objective_profile: String,
    repo: PathBuf,
    json: bool,
) -> Result<()> {
    let manifest_bytes =
        BoundedRegularReader::read_tree_no_follow(&manifest_path, MAX_EVALUATION_MANIFEST_BYTES)
            .with_context(|| {
                format!(
                    "failed to read evaluation manifest {}",
                    manifest_path.display()
                )
            })?;
    let results_bytes =
        BoundedRegularReader::read_tree_no_follow(&results_path, MAX_EVALUATION_PLAN_BYTES)
            .with_context(|| {
                format!(
                    "failed to read stored evaluation results {}",
                    results_path.display()
                )
            })?;
    let applied_profile =
        crate::objective_profile::resolve_objective_profile(&repo, Some(&objective_profile))
            .with_context(|| {
                format!(
                    "failed to resolve objective profile '{}' from {}",
                    objective_profile,
                    repo.display()
                )
            })?;

    match family {
        StoredEvaluationResultsFamily::Evaluation => {
            let manifest =
                serde_json::from_slice::<crate::evaluation::EvaluationManifest>(&manifest_bytes)
                    .with_context(|| {
                        format!(
                            "failed to parse evaluation manifest {} as evaluation",
                            manifest_path.display()
                        )
                    })?;
            let stored_results =
                serde_json::from_slice::<crate::evaluation::EvaluationResults>(&results_bytes)
                    .with_context(|| {
                        format!(
                            "failed to parse stored evaluation results {} as evaluation",
                            results_path.display()
                        )
                    })?;
            let rescored = crate::evaluation::rescore::rescore_evaluation_results(
                &manifest,
                &stored_results,
                applied_profile,
            )?;
            print_query_report(&rescored, json)
        }
        StoredEvaluationResultsFamily::Experiment => {
            let manifest = crate::evaluation::parse_experiment_manifest(&manifest_bytes)
                .with_context(|| {
                    format!(
                        "failed to parse evaluation manifest {} as experiment",
                        manifest_path.display()
                    )
                })?;
            let stored_results =
                serde_json::from_slice::<crate::evaluation::ExperimentResults>(&results_bytes)
                    .with_context(|| {
                        format!(
                            "failed to parse stored evaluation results {} as experiment",
                            results_path.display()
                        )
                    })?;
            let rescored = crate::evaluation::rescore::rescore_experiment_results(
                &manifest,
                &stored_results,
                applied_profile,
            )?;
            print_query_report(&rescored, json)
        }
    }
}

const MAX_OPTIMIZER_JSON_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args)]
struct OptimizerCommand {
    #[command(subcommand)]
    command: OptimizerSubcommand,
}

impl OptimizerCommand {
    fn run(self) -> Result<()> {
        match self.command {
            OptimizerSubcommand::Library(command) => command.run(),
            OptimizerSubcommand::Preference(command) => command.run(),
            OptimizerSubcommand::Replay(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum OptimizerSubcommand {
    /// Inspect the fixed starter policy library.
    Library(OptimizerLibraryCommand),
    /// Select, inspect, and diff operator preference profiles.
    Preference(OptimizerPreferenceCommand),
    /// Inspect stored decision replay snapshots.
    Replay(OptimizerReplayCommand),
}

#[derive(Debug, Args)]
struct OptimizerLibraryCommand {
    #[command(subcommand)]
    command: OptimizerLibrarySubcommand,
}

impl OptimizerLibraryCommand {
    fn run(self) -> Result<()> {
        match self.command {
            OptimizerLibrarySubcommand::List(args) => {
                let library = crate::optimizer::policy::PolicyLibrary::starter()
                    .context("failed to construct starter policy library")?;
                let ids: Vec<&str> = library.entries.keys().map(String::as_str).collect();
                if args.json {
                    print_query_report(&library, true)
                } else {
                    println!("policy library v{}", library.version);
                    for id in ids {
                        println!("{id}");
                    }
                    Ok(())
                }
            }
            OptimizerLibrarySubcommand::Show(args) => {
                let library = crate::optimizer::policy::PolicyLibrary::starter()
                    .context("failed to construct starter policy library")?;
                let id =
                    crate::optimizer::ids::PolicyId::new(&args.id).context("invalid policy id")?;
                let graph = library.get(&id).with_context(|| {
                    format!("policy '{}' is not in the starter library", args.id)
                })?;
                print_query_report(graph, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum OptimizerLibrarySubcommand {
    /// List starter-library policy ids.
    List(OptimizerJsonArgs),
    /// Show one starter-library policy graph.
    Show(OptimizerShowArgs),
}

#[derive(Debug, Args)]
struct OptimizerJsonArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerShowArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceCommand {
    #[command(subcommand)]
    command: OptimizerPreferenceSubcommand,
}

impl OptimizerPreferenceCommand {
    fn run(self) -> Result<()> {
        match self.command {
            OptimizerPreferenceSubcommand::List(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                print_query_report(&store.list()?, args.json)
            }
            OptimizerPreferenceSubcommand::Show(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                print_query_report(&store.load(&args.id)?, args.json)
            }
            OptimizerPreferenceSubcommand::Set(args) => {
                let bytes =
                    BoundedRegularReader::read_tree_no_follow(&args.file, MAX_OPTIMIZER_JSON_BYTES)
                        .with_context(|| {
                            format!("failed to read preference file {}", args.file.display())
                        })?;
                let profile = crate::optimizer::objective::parse_preference_profile(&bytes)
                    .context("invalid preference profile")?;
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                let path = store.save(&profile)?;
                if args.r#default {
                    store.set_project_default(profile.id.as_str())?;
                }
                print_query_report(
                    &serde_json::json!({
                        "id": profile.id.as_str(),
                        "version": profile.version,
                        "path": path,
                    }),
                    args.json,
                )
            }
            OptimizerPreferenceSubcommand::Default(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                if let Some(id) = args.id {
                    store.set_project_default(&id)?;
                }
                print_query_report(&store.project_default()?, args.json)
            }
            OptimizerPreferenceSubcommand::Diff(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                let left = store.load(&args.a)?;
                let right = store.load(&args.b)?;
                print_query_report(
                    &crate::optimizer::objective::diff_profiles(&left, &right),
                    args.json,
                )
            }
            OptimizerPreferenceSubcommand::Preview(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                let left = store.load(&args.a)?;
                let right = store.load(&args.b)?;
                let bytes = BoundedRegularReader::read_tree_no_follow(
                    &args.decision,
                    MAX_OPTIMIZER_JSON_BYTES,
                )
                .with_context(|| {
                    format!("failed to read decision file {}", args.decision.display())
                })?;
                let candidates: Vec<crate::optimizer::objective::PreferenceCandidate> =
                    serde_json::from_slice(&bytes).context("parse preference candidates")?;
                let preview = crate::optimizer::objective::preview_profile_effect(
                    &candidates,
                    &left,
                    &right,
                    args.quality_threshold_bp,
                )?;
                if let Some(output) = args.html {
                    let html = crate::optimizer::objective::render_preference_surface_html(
                        &left,
                        &right,
                        Some(&preview),
                    )?;
                    std::fs::write(&output, html).with_context(|| {
                        format!("failed to write preference HTML {}", output.display())
                    })?;
                }
                print_query_report(&preview, args.json)
            }
            OptimizerPreferenceSubcommand::Select(args) => {
                let store = crate::optimizer::objective::PreferenceStore::open(&args.store);
                let profile = store
                    .load(&args.id)?
                    .resolved_for_task_class(args.task_class.as_deref());
                let bytes = BoundedRegularReader::read_tree_no_follow(
                    &args.decision,
                    MAX_OPTIMIZER_JSON_BYTES,
                )
                .with_context(|| {
                    format!("failed to read decision file {}", args.decision.display())
                })?;
                let candidates: Vec<crate::optimizer::objective::PreferenceCandidate> =
                    serde_json::from_slice(&bytes).context("parse preference candidates")?;
                let decision = crate::optimizer::objective::decide_with_profile(
                    &candidates,
                    &profile,
                    args.quality_threshold_bp,
                )?;
                print_query_report(&decision, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum OptimizerPreferenceSubcommand {
    /// List stored preference profiles.
    List(OptimizerStoreArgs),
    /// Show one preference profile.
    Show(OptimizerPreferenceShowArgs),
    /// Import a GUI- or CLI-authored preference profile.
    Set(OptimizerPreferenceSetArgs),
    /// Inspect or set the project-default profile.
    Default(OptimizerPreferenceDefaultArgs),
    /// Diff two stored profiles.
    Diff(OptimizerPreferenceDiffArgs),
    /// Preview selected policies under two profiles.
    Preview(OptimizerPreferencePreviewArgs),
    /// Select once and emit complete deterministic scoring evidence.
    #[command(alias = "decide")]
    Select(OptimizerPreferenceSelectArgs),
}

#[derive(Debug, Args)]
struct OptimizerStoreArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceShowArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    id: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceSetArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    r#default: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceDefaultArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceDiffArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    a: String,
    #[arg(long)]
    b: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferencePreviewArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    #[arg(long)]
    a: String,
    #[arg(long)]
    b: String,
    /// Recorded preference candidates (same JSON the GUI exports).
    #[arg(long)]
    decision: PathBuf,
    #[arg(long, default_value_t = 8000)]
    quality_threshold_bp: u16,
    #[arg(long)]
    html: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerPreferenceSelectArgs {
    #[arg(long, default_value = ".maco/optimizer/preferences")]
    store: PathBuf,
    /// Exact stored profile id. Selection never substitutes catalog order.
    #[arg(long)]
    id: String,
    /// Recorded candidates with evaluation evidence and admission state.
    #[arg(long)]
    decision: PathBuf,
    /// Resolve an optional task-class override before hashing and scoring.
    #[arg(long)]
    task_class: Option<String>,
    #[arg(long, default_value_t = 8000)]
    quality_threshold_bp: u16,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OptimizerReplayCommand {
    #[command(subcommand)]
    command: OptimizerReplaySubcommand,
}

impl OptimizerReplayCommand {
    fn run(self) -> Result<()> {
        match self.command {
            OptimizerReplaySubcommand::Show(args) => {
                let store = crate::optimizer::replay::FileReplayStore::open(&args.store);
                let id = crate::optimizer::ids::PolicyId::new(&args.policy)
                    .context("invalid policy id")?;
                let record = crate::optimizer::replay::ReplayStore::load(&store, &id)?
                    .with_context(|| format!("no replay record for {id}"))?;
                print_query_report(&record, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum OptimizerReplaySubcommand {
    /// Show a stored replay snapshot.
    Show(OptimizerReplayShowArgs),
}

#[derive(Debug, Args)]
struct OptimizerReplayShowArgs {
    #[arg(long, default_value = ".maco/optimizer/replay")]
    store: PathBuf,
    #[arg(long)]
    policy: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum WorktreeSubcommand {
    /// Create a linked worktree for an agent.
    Create(CreateWorktreeArgs),
    /// Manage the advisory agent-branch guard in the primary worktree.
    Guard(WorktreeGuardCommand),
    /// Collect an agent worktree diff and claim-boundary report.
    Diff(DiffWorktreeArgs),
    /// Remove clean, inactive managed worktrees and unregistered leftover directories.
    Gc(GcWorktreeArgs),
    /// Sweep managed worktrees across every repository group in a workspace.
    Sweep(SweepWorktreeArgs),
    /// Classify and optionally apply opt-in worktree and artifact lifecycle automation.
    Lifecycle(LifecycleWorktreeArgs),
    /// Remove a linked worktree for an agent.
    Remove(RemoveWorktreeArgs),
    /// List registered worktrees.
    List(ListWorktreesArgs),
    /// Inspect authenticated pending worktree operations without recovering them.
    Pending(ListWorktreesArgs),
}

#[derive(Debug, Args)]
struct WorktreeGuardCommand {
    #[command(subcommand)]
    command: WorktreeGuardSubcommand,
}

#[derive(Debug, Subcommand)]
enum WorktreeGuardSubcommand {
    /// Install the primary-worktree guard while preserving existing hooks.
    Install(WorktreeGuardArgs),
    /// Verify the exact guard payload and repository binding without changes.
    Verify(WorktreeGuardArgs),
    /// Remove an exactly verified guard and restore preserved hooks.
    Uninstall(WorktreeGuardArgs),
}

#[derive(Debug, Args)]
struct WorktreeGuardArgs {
    /// Primary repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id. Allowed characters: ASCII letters, digits, '.', '_' and '-'.
    agent_id: String,
    /// Branch to check out in the worktree. Defaults to maco/<agent-id>.
    #[arg(long)]
    branch: Option<String>,
    /// Base revision used when creating a new branch. Defaults to HEAD.
    #[arg(long)]
    base: Option<String>,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// After creation, remove eligible older clean worktrees older than this many seconds.
    #[arg(long)]
    gc_max_age_seconds: Option<u64>,
    /// After creation, keep at most this many newest eligible clean worktrees.
    #[arg(long)]
    gc_max_count: Option<usize>,
    /// After creation, retain at most this many apparent, not allocated, bytes in newest eligible lanes.
    #[arg(long)]
    gc_max_total_bytes: Option<u64>,
    /// Apply the bounded O2-launch default of retaining the newest 10 lanes after creation.
    #[arg(long)]
    o2_launch_retention_defaults: bool,
    /// Classify this newly created retry lane's exact predecessor for guarded supersession.
    #[arg(long)]
    supersede_retry_predecessor: bool,
    /// Apply eligible retry predecessor reaping after creation.
    #[arg(long, requires = "supersede_retry_predecessor")]
    apply_retry_supersession: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GcWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// List cleanup actions without removing anything.
    #[arg(long)]
    dry_run: bool,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Reclaim eligible target/ directories while retaining every lane and branch; conflicts with retention filters.
    #[arg(long)]
    targets_only: bool,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees.
    #[arg(long)]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes; sizing failure protects a lane.
    #[arg(long)]
    max_total_bytes: Option<u64>,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Exact reviewed config used to gate nonempty unregistered-directory cleanup.
    #[arg(long)]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root contains the managed worktree root.
    #[arg(long)]
    machine_global_worktree_root_id: Option<String>,
    /// Correction lifecycle identity used by typed machine-global gate denials.
    #[arg(long)]
    machine_global_correlation: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SweepWorktreeArgs {
    /// Workspace containing .maco/worktrees/<repo>/<lane> directories.
    #[arg(long)]
    workspace: PathBuf,
    /// Apply cleanup. Without this flag, the sweep is a dry-run.
    #[arg(long)]
    apply: bool,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Reclaim eligible target/ directories while retaining every lane and branch; conflicts with retention filters.
    #[arg(long)]
    targets_only: bool,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees per discovered root.
    #[arg(long)]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes per discovered root.
    #[arg(long)]
    max_total_bytes: Option<u64>,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LifecycleWorktreeArgs {
    /// Repository path. Lifecycle automation is disabled unless a feature flag is supplied.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Apply explicitly enabled lifecycle actions. Without this flag, the pass is a dry-run.
    #[arg(long)]
    apply: bool,
    /// Classify fully merged lanes for guarded automatic reaping.
    #[arg(long, requires = "trunk_ref")]
    auto_reap_merged: bool,
    /// Exact local trunk reference used for merged ancestry, for example refs/heads/main.
    #[arg(long, value_name = "REF", requires = "auto_reap_merged")]
    trunk_ref: Option<String>,
    /// Exact retry-lane successor whose unambiguous predecessor may be superseded.
    #[arg(long, value_name = "AGENT_ID")]
    retry_successor: Option<String>,
    /// Detect metadata/on-disk registration mismatches left by an unclean shutdown.
    #[arg(long)]
    startup_reconciliation: bool,
    /// Permit guarded destructive resolution of startup reconciliation findings.
    #[arg(long, requires_all = ["startup_reconciliation", "apply"])]
    destructive_reconciliation: bool,
    /// Schedule the bounded O2-launch run-artifact retention profile.
    #[arg(long)]
    o2_launch_retention: bool,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long, requires = "auto_reap_merged")]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees.
    #[arg(long, requires = "auto_reap_merged")]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes.
    #[arg(long, requires = "auto_reap_merged")]
    max_total_bytes: Option<u64>,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Keep the latest N O2-launch run directories instead of the bounded profile default.
    #[arg(long, value_name = "N", requires = "o2_launch_retention")]
    artifact_keep: Option<usize>,
    /// Reclaim O2-launch artifacts at least this old even when within --artifact-keep.
    #[arg(long, value_name = "SECONDS", requires = "o2_launch_retention")]
    artifact_max_age_seconds: Option<u64>,
    /// Retain at most this many apparent artifact bytes, newest first.
    #[arg(long, value_name = "BYTES", requires = "o2_launch_retention")]
    artifact_max_total_bytes: Option<u64>,
    /// Override the grace for idle unfinalized O2-launch artifacts.
    #[arg(long, value_name = "SECONDS", requires = "o2_launch_retention")]
    artifact_unfinalized_grace_seconds: Option<u64>,
    /// Allow grace-based expiry of present but unverifiable finalization evidence.
    #[arg(long, requires = "o2_launch_retention")]
    reclaim_unverifiable: bool,
    /// Confirm that non-cooperating external artifact writers are stopped.
    #[arg(long, requires = "o2_launch_retention")]
    acknowledge_external_writers_stopped: bool,
    /// Exact reviewed config used to gate nonempty unregistered-directory cleanup.
    #[arg(long)]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root contains the managed worktree root.
    #[arg(long)]
    machine_global_worktree_root_id: Option<String>,
    /// Correction lifecycle identity used by typed machine-global gate denials.
    #[arg(long)]
    machine_global_correlation: Option<String>,
    /// Emit the aggregate lifecycle report as one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DiffWorktreeArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Include the complete binary-safe git diff in JSON output.
    #[arg(long)]
    full_diff: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RemoveWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Remove even if the worktree has uncommitted changes or is locked.
    #[arg(long)]
    force: bool,
    /// Delete the worktree branch after removing the worktree.
    #[arg(long)]
    delete_branch: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ListWorktreesArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn resolve_claims(
    repo: &Path,
    agent_id: &str,
    explicit_claims: Vec<PathBuf>,
) -> Result<Vec<PathBuf>> {
    if !explicit_claims.is_empty() {
        return Ok(explicit_claims);
    }

    let store = SyncStore::open(repo)?;
    let claims = store
        .snapshot()?
        .into_iter()
        .filter(|claim| claim.agent_id == agent_id)
        .flat_map(|claim| claim.paths)
        .collect::<Vec<_>>();
    Ok(claims)
}

fn collect_options_from_claims(
    repo: &Path,
    agent_id: &str,
    claimed_paths: Vec<PathBuf>,
    include_full_diff: bool,
    validations: Vec<ValidationReport>,
) -> MergeCollectOptions {
    MergeCollectOptions {
        repo: repo.to_path_buf(),
        agent_id: agent_id.to_string(),
        claimed_paths,
        include_full_diff,
        diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        validations,
    }
}

#[allow(clippy::too_many_arguments)]
fn preview_merge_from_args(
    repo: PathBuf,
    agent_id: String,
    explicit_claims: Vec<PathBuf>,
    validation_report_paths: Vec<PathBuf>,
    forces: MergeForceOptions,
    require_validation: bool,
    review_intent: merge::MergeApplyReviewIntent,
    megafile_policy: MegafileMergePolicy,
    local_git: merge::MergeLocalGitOptions,
) -> Result<MergeApplyPreview> {
    let claims = resolve_claims(&repo, &agent_id, explicit_claims)?;
    let validation_evidence = load_validation_evidence(&validation_report_paths, &agent_id)?;
    merge::preview_merge_apply_with_megafile_policy_and_local_git_options(
        MergePreviewOptions {
            collect: collect_options_from_claims(&repo, &agent_id, claims, true, Vec::new()),
            forces,
            require_validation,
            review_intent,
        },
        validation_evidence,
        megafile_policy,
        local_git,
    )
}

#[derive(Debug, Args)]
struct MergeCommand {
    #[command(subcommand)]
    command: MergeSubcommand,
}

impl MergeCommand {
    fn run(self) -> Result<()> {
        match self.command {
            MergeSubcommand::Preview(args) => {
                let megafile_policy = args.megafile_policy()?;
                let local_git = args.local_git.options()?;
                let review_intent = args.review_intent()?;
                let preview = preview_merge_from_args(
                    args.repo,
                    args.agent_id,
                    args.claim,
                    args.validation_report,
                    args.forces.into_force_options(),
                    args.require_validation,
                    review_intent,
                    megafile_policy,
                    local_git,
                )?;
                print_merge_preview(&preview, args.json)
            }
            MergeSubcommand::Apply(args) => run_merge_apply_controller(
                args,
                print_merge_apply_report,
                print_merge_apply_review_refusal,
            ),
            MergeSubcommand::Arbitrate(args) => {
                let first_side =
                    arbitration_side_from_cli(args.first_side, args.first_claim, "first")?;
                let second_side =
                    arbitration_side_from_cli(args.second_side, args.second_claim, "second")?;
                let report = merge::arbitrate_merge(MergeArbitrationOptions {
                    repo: args.repo,
                    run_id: RunId::new(args.run_id)?,
                    arbiter_agent_id: args.arbiter_id,
                    sides: [first_side, second_side],
                    validation_commands: args
                        .validation_command
                        .into_iter()
                        .map(|command| CandidateValidationCommand { command })
                        .collect(),
                    approve: args.approve,
                    codex_bin: args.codex_bin,
                    timeout: Duration::from_secs(args.timeout_seconds),
                    worktree_root: args.worktree_root,
                    machine_global_config: args.machine_global_config,
                    machine_global_runtime_root_id: args.machine_global_runtime_root_id,
                })?;
                print_merge_arbitration_report(&report, args.json)
            }
        }
    }
}

fn run_merge_apply_controller(
    args: MergeApplyArgs,
    mut deliver_report: impl FnMut(&MergeApplyReport, bool) -> Result<()>,
    mut deliver_review_refusal: impl FnMut(&merge::MergeApplyReviewRefusalEnvelope, bool) -> Result<()>,
) -> Result<()> {
    let review_intent = args.review_intent()?;
    let lifecycle_repo = args.repo.clone();
    let lifecycle_agent_id = args.agent_id.clone();
    let auto_reap_merged = review_intent.auto_reap_merged;
    let apply_auto_reap = review_intent.apply_auto_reap;
    let lifecycle_trunk_ref = review_intent.trunk_ref.clone();
    let json = args.json;
    let megafile_policy = args.megafile_policy()?;
    let local_git = args.local_git.options()?;
    let reviewed_watermark = match load_reviewed_merge_preview(args.reviewed_watermark.as_deref()) {
        Ok(reviewed) => reviewed,
        Err(error) => {
            return deliver_merge_review_refusal(error, json, &mut deliver_review_refusal)
        }
    };
    let claims = resolve_claims(&args.repo, &args.agent_id, args.claim)?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &args.agent_id)?;
    let candidate_validation_commands = args
        .validation_command
        .into_iter()
        .map(|command| CandidateValidationCommand { command })
        .collect::<Vec<_>>();
    let preview_options = MergePreviewOptions {
        collect: collect_options_from_claims(&args.repo, &args.agent_id, claims, true, Vec::new()),
        forces: args.forces.into_force_options(),
        require_validation: args.require_validation,
        review_intent,
    };
    let report = merge::merge_apply_report_with_megafile_policy_and_local_git_options(
        MergeApplyOptions {
            preview: preview_options,
            candidate_validation_commands,
            reviewed_watermark,
        },
        validation_evidence,
        megafile_policy,
        local_git,
    );
    let mut report = match report {
        Ok(report) => report,
        Err(error) => {
            if let Some(review_error) = error.downcast_ref::<merge::MergePreviewFreshnessError>() {
                return deliver_merge_review_refusal(
                    review_error,
                    json,
                    &mut deliver_review_refusal,
                );
            }
            return Err(error);
        }
    };
    if report.status == merge::MergeApplyReportStatus::Blocked {
        if json {
            deliver_report(&report, true)?;
        }
        let message = report
            .error
            .clone()
            .unwrap_or_else(|| "merge apply refused".to_string());
        bail!("{message}");
    }
    if auto_reap_merged {
        let lifecycle_options = WorktreeLifecycleOptions {
            apply: apply_auto_reap,
            auto_reap_merged: true,
            candidate_agent_ids: Some(BTreeSet::from([lifecycle_agent_id])),
            merged_into_reference: lifecycle_trunk_ref,
            // A merge apply does not advance HEAD. Retain the selected lane's target cache
            // unless and until the lane itself is classified as fully merged and reaped.
            remove_targets: false,
            ..WorktreeLifecycleOptions::default()
        };
        match WorktreeManager::new(lifecycle_repo).lifecycle(lifecycle_options) {
            Ok(lifecycle) => report.lifecycle = Some(lifecycle),
            Err(error) => {
                let context = if report.applied {
                    format!(
                        "merge was applied, but merged-lane lifecycle classification failed; \
                         do not retry the merge: {error:#}"
                    )
                } else {
                    format!(
                        "merge was not blocked, but merged-lane lifecycle classification failed: \
                         {error:#}"
                    )
                };
                report.error = Some(context.clone());
                deliver_report(&report, json)?;
                bail!("{context}");
            }
        }
    }
    deliver_report(&report, json)
}

fn load_reviewed_merge_preview(
    path: Option<&Path>,
) -> std::result::Result<merge::MergePreviewFreshnessWatermark, merge::MergePreviewFreshnessError> {
    let path = path.ok_or(merge::MergePreviewFreshnessError::MissingReviewedEvidence)?;
    let bytes = std::fs::read(path).map_err(|source| {
        merge::MergePreviewFreshnessError::malformed(format!(
            "failed to read reviewed evidence {}: {source}",
            path.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|source| {
        merge::MergePreviewFreshnessError::malformed(format!(
            "reviewed evidence is not valid JSON: {source}"
        ))
    })?;
    crate::merge_freshness::reviewed_merge_preview_watermark_from_json(&value)
}

fn deliver_merge_review_refusal<E>(
    error: E,
    json: bool,
    deliver: &mut impl FnMut(&merge::MergeApplyReviewRefusalEnvelope, bool) -> Result<()>,
) -> Result<()>
where
    E: std::borrow::Borrow<merge::MergePreviewFreshnessError>,
{
    let error = error.borrow();
    let message = error.to_string();
    if json {
        let refusal = merge::MergeApplyReviewRefusalEnvelope::from_error(error);
        deliver(&refusal, true)?;
    }
    bail!(message)
}

/// Reap authenticated managed worktrees whose branches are fully contained in
/// the current local HEAD branch. Dirty, claimed, leased, and unmerged lanes
/// stay in place. Candidate selectors disable pathname-only orphan pruning so
/// this completion hook cannot demand a machine-global binding.
fn reap_merged_managed_worktrees(repo: &Path) -> Result<Option<WorktreeLifecycleReport>> {
    let git = crate::git_repository::open(repo).with_context(|| {
        format!(
            "failed to open repository {} for merged worktree reaping",
            repo.display()
        )
    })?;
    let head = match git.head() {
        Ok(head) => head,
        Err(_) => return Ok(None),
    };
    if !head.is_branch() {
        return Ok(None);
    }
    let Ok(trunk_ref) = head.name().map(str::to_owned) else {
        return Ok(None);
    };
    if !trunk_ref.starts_with("refs/heads/") {
        return Ok(None);
    }

    let state_path = git.commondir().join("maco").join("state");
    match std::fs::symlink_metadata(&state_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect managed worktree state at {}",
                    state_path.display()
                )
            })
        }
    }

    let manager = WorktreeManager::new(repo);
    let candidate_agent_ids = manager
        .list()
        .context("failed to list managed worktrees for merged reaping")?
        .into_iter()
        .map(|record| record.name)
        .collect::<BTreeSet<_>>();
    if candidate_agent_ids.is_empty() {
        return Ok(None);
    }

    manager
        .lifecycle(WorktreeLifecycleOptions {
            apply: true,
            auto_reap_merged: true,
            candidate_agent_ids: Some(candidate_agent_ids),
            merged_into_reference: Some(trunk_ref),
            ..WorktreeLifecycleOptions::default()
        })
        .map(Some)
        .context("merged-lane worktree reaping failed")
}

fn print_merged_worktree_reap_summary(report: &WorktreeLifecycleReport, json: bool) {
    if json {
        return;
    }
    let Some(gc) = report.worktree_gc.as_ref() else {
        return;
    };
    println!(
        "Merged worktree reap: considered={} removed={} protected={} retained={}",
        gc.considered_count, gc.removed_count, gc.protected_count, gc.retained_count
    );
}

fn finish_with_merged_worktree_reap(repo: &Path, json: bool, outcome: Result<()>) -> Result<()> {
    let reap = match reap_merged_managed_worktrees(repo) {
        Ok(Some(report)) => {
            print_merged_worktree_reap_summary(&report, json);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    match (outcome, reap) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error).context(
            "command succeeded, but merged worktree reaping failed; do not blindly retry the command",
        ),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(reap_error)) => Err(primary).context(format!(
            "merged worktree reaping also failed: {reap_error:#}"
        )),
    }
}

#[derive(Debug, Subcommand)]
enum MergeSubcommand {
    /// Preview whether an agent worktree diff can be applied to the primary worktree.
    Preview(MergePreviewArgs),
    /// Apply an agent worktree diff to the primary worktree after safety checks.
    Apply(MergeApplyArgs),
    /// Ask a structurally neutral arbiter to prepare, but never apply, a collision resolution.
    Arbitrate(MergeArbitrateArgs),
}

#[derive(Debug, Clone, Copy, Args)]
struct MergeLocalGitTimeoutArgs {
    /// Candidate snapshot Git diff deadline in seconds.
    ///
    /// The CLI value overrides MACO_MERGE_LOCAL_GIT_TIMEOUT_SECONDS; the
    /// environment value overrides the 120-second default.
    #[arg(
        long,
        env = "MACO_MERGE_LOCAL_GIT_TIMEOUT_SECONDS",
        default_value_t = merge::DEFAULT_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS,
        value_parser = merge::parse_local_git_process_timeout_seconds
    )]
    local_git_timeout_seconds: u64,
}

impl Default for MergeLocalGitTimeoutArgs {
    fn default() -> Self {
        Self {
            local_git_timeout_seconds: merge::DEFAULT_LOCAL_GIT_PROCESS_TIMEOUT_SECONDS,
        }
    }
}

impl MergeLocalGitTimeoutArgs {
    fn options(self) -> Result<merge::MergeLocalGitOptions> {
        merge::MergeLocalGitOptions::from_seconds(self.local_git_timeout_seconds)
            .map_err(Into::into)
    }
}

#[derive(Debug, Args)]
struct MergePreviewArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, use an envelope containing the exact current candidate.validation_binding and passed reports; legacy arrays are unbound.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require passed validation evidence bound exactly to the current candidate snapshot.
    #[arg(long)]
    require_validation: bool,
    /// Validate a temporary merged candidate; recursive candidate or submodule changes block apply.
    #[arg(long = "validation-command")]
    validation_command: Vec<String>,
    /// Block threshold-crossing megafiles unless this is their exact typed decomposition.
    #[arg(long)]
    block_megafiles: bool,
    /// Exact threshold-crossing file handled by a typed megafile_decomposition assignment.
    #[arg(long)]
    decomposition_target: Option<PathBuf>,
    /// Finalized accepted supervise run containing the typed decomposition evidence.
    #[arg(long)]
    decomposition_run_id: Option<String>,
    #[command(flatten)]
    megafile_thresholds: MegafileThresholdArgs,
    #[command(flatten)]
    forces: MergeForceArgs,
    #[command(flatten)]
    local_git: MergeLocalGitTimeoutArgs,
    /// After a non-blocked merge result, classify this lane for guarded merged-lane reaping.
    #[arg(long, requires = "trunk_ref")]
    auto_reap_merged: bool,
    /// Exact local trunk reference used to verify that the lane is fully merged.
    #[arg(long, value_name = "REF", requires = "auto_reap_merged")]
    trunk_ref: Option<String>,
    /// Apply an eligible merge lifecycle reap; requires --auto-reap-merged.
    #[arg(long, requires = "auto_reap_merged")]
    apply_auto_reap: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MergeApplyArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, use an exact candidate-bound envelope; legacy arrays are unbound. Repeat to supply multiple files.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require an exact candidate-bound passed report or a passed candidate validation command.
    #[arg(long)]
    require_validation: bool,
    /// Validate a temporary merged candidate; recursive candidate or submodule changes block apply.
    #[arg(long = "validation-command")]
    validation_command: Vec<String>,
    /// Block threshold-crossing megafiles unless this is their exact typed decomposition.
    #[arg(long)]
    block_megafiles: bool,
    /// Exact threshold-crossing file handled by a typed megafile_decomposition assignment.
    #[arg(long)]
    decomposition_target: Option<PathBuf>,
    /// Finalized accepted supervise run containing the typed decomposition evidence.
    #[arg(long)]
    decomposition_run_id: Option<String>,
    #[command(flatten)]
    megafile_thresholds: MegafileThresholdArgs,
    #[command(flatten)]
    forces: MergeForceArgs,
    #[command(flatten)]
    local_git: MergeLocalGitTimeoutArgs,
    /// After a non-blocked merge result, classify this lane for guarded merged-lane reaping.
    #[arg(long, requires = "trunk_ref")]
    auto_reap_merged: bool,
    /// Exact local trunk reference used to verify that the lane is fully merged.
    #[arg(long, value_name = "REF", requires = "auto_reap_merged")]
    trunk_ref: Option<String>,
    /// Apply an eligible merge lifecycle reap; requires --auto-reap-merged.
    #[arg(long, requires = "auto_reap_merged")]
    apply_auto_reap: bool,
    /// Previously reviewed merge preview JSON or nested freshness watermark.
    #[arg(long, value_name = "PATH")]
    reviewed_watermark: Option<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MergeArbitrateArgs {
    /// First collision side: a stable agent id or the reserved literal `primary`.
    #[arg(value_name = "FIRST_SIDE")]
    first_side: String,
    /// Second collision side: a distinct stable agent id or the reserved literal `primary`.
    #[arg(value_name = "SECOND_SIDE")]
    second_side: String,
    /// Stable identity for the fresh neutral arbiter; must differ from both sides.
    #[arg(long)]
    arbiter_id: String,
    /// Stable run id for private, digest-bound arbitration artifacts.
    #[arg(long)]
    run_id: String,
    /// Repository path. Arbitration never mutates its primary worktree.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claim for an agent first side. Repeat to provide multiple claims.
    #[arg(long = "first-claim")]
    first_claim: Vec<PathBuf>,
    /// Explicit claim for an agent second side. Repeat to provide multiple claims.
    #[arg(long = "second-claim")]
    second_claim: Vec<PathBuf>,
    /// Candidate-bound validation command. At least one is required.
    #[arg(long = "validation-command", required = true)]
    validation_command: Vec<String>,
    /// Explicitly accept a preserved, validated proposal. A later ordinary merge apply is still required.
    #[arg(long)]
    approve: bool,
    /// Codex-compatible executable used through the existing trusted local agent boundary.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Seconds before the neutral arbiter subprocess is terminated.
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
    /// Optional managed-worktree root for the fresh neutral arbitration worktree.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// Exact reviewed config used to gate cleanup of private runtime output staging.
    #[arg(long)]
    machine_global_config: PathBuf,
    /// Reviewed root id whose canonical root must contain the actual private runtime root.
    #[arg(long)]
    machine_global_runtime_root_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn arbitration_side_from_cli(
    participant: String,
    claimed_paths: Vec<PathBuf>,
    position: &str,
) -> Result<ArbitrationSideSpec> {
    if participant == "primary" {
        if !claimed_paths.is_empty() {
            bail!(
                "{position} arbitration side is primary, so --{position}-claim is not applicable"
            );
        }
        Ok(ArbitrationSideSpec::Primary)
    } else {
        Ok(ArbitrationSideSpec::Agent {
            agent_id: participant,
            claimed_paths,
        })
    }
}

impl MergePreviewArgs {
    fn review_intent(&self) -> Result<merge::MergeApplyReviewIntent> {
        merge_apply_review_intent(
            &self.validation_command,
            self.require_validation,
            self.auto_reap_merged,
            self.trunk_ref.as_deref(),
            self.apply_auto_reap,
        )
    }

    fn megafile_policy(&self) -> Result<MegafileMergePolicy> {
        let decomposition_run_id = self
            .decomposition_run_id
            .as_deref()
            .map(RunId::new)
            .transpose()?;
        validate_decomposition_cli_pair(
            self.decomposition_target.as_deref(),
            decomposition_run_id.as_ref(),
        )?;
        Ok(MegafileMergePolicy {
            block: self.block_megafiles,
            decomposition_target: self.decomposition_target.clone(),
            decomposition_run_id,
            thresholds: self
                .megafile_thresholds
                .configured_thresholds()
                .unwrap_or_else(MegafileThresholds::provisional_bootstrap),
        })
    }
}

impl MergeApplyArgs {
    fn review_intent(&self) -> Result<merge::MergeApplyReviewIntent> {
        merge_apply_review_intent(
            &self.validation_command,
            self.require_validation,
            self.auto_reap_merged,
            self.trunk_ref.as_deref(),
            self.apply_auto_reap,
        )
    }

    fn megafile_policy(&self) -> Result<MegafileMergePolicy> {
        let decomposition_run_id = self
            .decomposition_run_id
            .as_deref()
            .map(RunId::new)
            .transpose()?;
        validate_decomposition_cli_pair(
            self.decomposition_target.as_deref(),
            decomposition_run_id.as_ref(),
        )?;
        Ok(MegafileMergePolicy {
            block: self.block_megafiles,
            decomposition_target: self.decomposition_target.clone(),
            decomposition_run_id,
            thresholds: self
                .megafile_thresholds
                .configured_thresholds()
                .unwrap_or_else(MegafileThresholds::provisional_bootstrap),
        })
    }
}

fn merge_apply_review_intent(
    validation_commands: &[String],
    require_validation_after_candidate: bool,
    auto_reap_merged: bool,
    trunk_ref: Option<&str>,
    apply_auto_reap: bool,
) -> Result<merge::MergeApplyReviewIntent> {
    let intent = merge::MergeApplyReviewIntent {
        candidate_validation_commands: validation_commands.to_vec(),
        require_validation_after_candidate,
        auto_reap_merged,
        trunk_ref: trunk_ref.map(str::to_owned),
        apply_auto_reap,
    };
    intent.validate()?;
    Ok(intent)
}

fn validate_decomposition_cli_pair(target: Option<&Path>, run_id: Option<&RunId>) -> Result<()> {
    match (target, run_id) {
        (Some(_), None) => {
            bail!("--decomposition-target requires --decomposition-run-id with finalized evidence")
        }
        (None, Some(_)) => bail!("--decomposition-run-id requires --decomposition-target"),
        _ => Ok(()),
    }
}

#[derive(Debug, Args)]
struct MergeForceArgs {
    /// Continue when the primary worktree has local changes.
    #[arg(long)]
    force_dirty_primary: bool,
    /// Continue when the agent branch was based on an older primary HEAD.
    #[arg(long)]
    force_stale_base: bool,
    /// Continue when the agent changed paths outside its claims.
    #[arg(long)]
    force_unclaimed_edits: bool,
    /// Continue when supplied validation reports include failures.
    #[arg(long)]
    force_validation_failures: bool,
    /// Allow three-way apply checks when a direct apply check fails.
    #[arg(long)]
    force_apply_conflicts: bool,
}

impl MergeForceArgs {
    fn into_force_options(self) -> MergeForceOptions {
        MergeForceOptions {
            allow_dirty_primary: self.force_dirty_primary,
            allow_stale_base: self.force_stale_base,
            allow_unclaimed_edits: self.force_unclaimed_edits,
            allow_validation_failures: self.force_validation_failures,
            allow_apply_conflicts: self.force_apply_conflicts,
        }
    }
}

#[derive(Debug, Args)]
struct PrCommand {
    #[command(subcommand)]
    command: PrSubcommand,
}

impl PrCommand {
    fn run(self) -> Result<()> {
        match self.command {
            PrSubcommand::Preview(args) => {
                let json = args.json;
                let require_validation = args.require_validation;
                let (options, validation_evidence) = pr_options_from_preview_args(args)?;
                let report = publication::preview_pr_with_validation_evidence(
                    options,
                    require_validation,
                    validation_evidence,
                )?;
                print_pr_publication_report(&report, json)
            }
            PrSubcommand::Publish(args) => {
                let json = args.json;
                let require_validation = args.require_validation;
                let (options, validation_evidence) = pr_options_from_publish_args(args)?;
                let report = publication::publish_pr_with_validation_evidence(
                    options,
                    require_validation,
                    validation_evidence,
                )?;
                let blocked_message = report.next_action.clone();
                print_pr_publication_report(&report, json)?;
                if report.status == PrPublicationStatus::Blocked {
                    bail!("pr publish refused: {blocked_message}");
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum PrSubcommand {
    /// Preview whether an agent worktree is ready to publish as a pull request.
    Preview(PrPreviewArgs),
    /// Publish an exact reviewed commit through an explicit forge with retry reconciliation.
    Publish(PrPublishArgs),
}

#[derive(Debug, Args)]
struct PrPreviewArgs {
    /// Stable agent id used when the worktree was created.
    #[arg(required_unless_present = "from_branch")]
    agent_id: Option<String>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required_unless_present = "from_branch")]
    claim: Vec<PathBuf>,
    /// Publish committed work from this local branch instead of a managed agent worktree.
    #[arg(long)]
    from_branch: Option<String>,
    /// Build a deterministic squash import commit on this local base branch before publishing.
    #[arg(long, requires = "from_branch")]
    squash_onto: Option<String>,
    /// Exclude a repository-local path from the published branch snapshot. Repeat for multiple paths.
    #[arg(long = "exclude", requires = "from_branch")]
    exclude: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, copy the exact current preview.candidate.validation_binding into an envelope with passed reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require passed validation evidence bound exactly to this PR candidate snapshot.
    #[arg(long)]
    require_validation: bool,
    /// Forge label recorded in the preview report.
    #[arg(long, default_value = "fake", value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Mark the eventual pull request ready for review instead of draft.
    #[arg(long)]
    ready: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PrPublishArgs {
    /// Stable agent id used when the worktree was created.
    #[arg(required_unless_present = "from_branch")]
    agent_id: Option<String>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required_unless_present = "from_branch")]
    claim: Vec<PathBuf>,
    /// Publish committed work from this local branch instead of a managed agent worktree.
    #[arg(long)]
    from_branch: Option<String>,
    /// Build a deterministic squash import commit on this local base branch before publishing.
    #[arg(long, requires = "from_branch")]
    squash_onto: Option<String>,
    /// Exclude a repository-local path from the published branch snapshot. Repeat for multiple paths.
    #[arg(long = "exclude", requires = "from_branch")]
    exclude: Vec<PathBuf>,
    /// Candidate-bound validation envelope produced after previewing the clean, committed candidate; legacy report arrays are unbound.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require a clean committed candidate and passed evidence bound exactly to its current preview binding.
    #[arg(long)]
    require_validation: bool,
    /// Forge adapter. `github` binds origin host/owner/repo, verifies the OID receipt, and journals retry state.
    #[arg(long, value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Mark the pull request ready for review instead of draft.
    #[arg(long)]
    ready: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IssueCommand {
    #[command(subcommand)]
    command: IssueSubcommand,
}

impl IssueCommand {
    fn run(self) -> Result<()> {
        match self.command {
            IssueSubcommand::Preview(args) => {
                let json = args.json;
                let report = publication::preview_issue(issue_options_from_args(
                    args.repo,
                    args.title,
                    args.body,
                    args.body_file,
                    args.label,
                    args.forge,
                )?)?;
                print_query_report(&report, json)
            }
            IssueSubcommand::Create(args) => {
                let json = args.json;
                let report = publication::create_issue(issue_options_from_args(
                    args.repo,
                    args.title,
                    args.body,
                    args.body_file,
                    args.label,
                    args.forge,
                )?)?;
                print_query_report(&report, json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum IssueSubcommand {
    /// Preview issue content after redaction.
    Preview(IssuePreviewArgs),
    /// Create an issue through an explicit forge.
    Create(IssueCreateArgs),
}

#[derive(Debug, Args)]
struct IssuePreviewArgs {
    /// Issue title.
    #[arg(long)]
    title: String,
    /// Issue body text.
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// File containing issue body text.
    #[arg(long, conflicts_with = "body")]
    body_file: Option<PathBuf>,
    /// Issue label. Repeat for multiple labels.
    #[arg(long = "label")]
    label: Vec<String>,
    /// Repository path used only by forge adapters that need repository context.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Forge label recorded in the preview report. Preview never creates remote issues.
    #[arg(long, default_value = "fake", value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IssueCreateArgs {
    /// Issue title.
    #[arg(long)]
    title: String,
    /// Issue body text.
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// File containing issue body text.
    #[arg(long, conflicts_with = "body")]
    body_file: Option<PathBuf>,
    /// Issue label. Repeat for multiple labels.
    #[arg(long = "label")]
    label: Vec<String>,
    /// Repository path used only by forge adapters that need repository context.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Forge adapter. `fake` is deterministic and local-only; `github` shells out explicitly.
    #[arg(long, value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn pr_options_from_preview_args(
    args: PrPreviewArgs,
) -> Result<(PrPublicationOptions, ValidationEvidenceBundle)> {
    let agent_id = pr_publication_agent_id(args.agent_id, args.from_branch.as_deref())?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &agent_id)?;
    Ok((
        PrPublicationOptions {
            repo: args.repo,
            agent_id,
            claimed_paths: args.claim,
            validations: Vec::new(),
            forge: args.forge,
            draft: !args.ready,
            from_branch: args.from_branch,
            squash_onto: args.squash_onto,
            exclude_paths: args.exclude,
        },
        validation_evidence,
    ))
}

fn pr_options_from_publish_args(
    args: PrPublishArgs,
) -> Result<(PrPublicationOptions, ValidationEvidenceBundle)> {
    let agent_id = pr_publication_agent_id(args.agent_id, args.from_branch.as_deref())?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &agent_id)?;
    Ok((
        PrPublicationOptions {
            repo: args.repo,
            agent_id,
            claimed_paths: args.claim,
            validations: Vec::new(),
            forge: args.forge,
            draft: !args.ready,
            from_branch: args.from_branch,
            squash_onto: args.squash_onto,
            exclude_paths: args.exclude,
        },
        validation_evidence,
    ))
}

fn pr_publication_agent_id(agent_id: Option<String>, from_branch: Option<&str>) -> Result<String> {
    match (agent_id, from_branch) {
        (Some(agent_id), None) => Ok(agent_id),
        (None, Some(branch)) => publication::branch_publication_agent_id(branch),
        (Some(_), Some(_)) => {
            bail!("agent id positional argument cannot be combined with --from-branch")
        }
        (None, None) => bail!("provide an agent id or --from-branch"),
    }
}

fn issue_options_from_args(
    repo: PathBuf,
    title: String,
    body: Option<String>,
    body_file: Option<PathBuf>,
    labels: Vec<String>,
    forge: ForgeKind,
) -> Result<IssuePublicationOptions> {
    let body = match (body, body_file) {
        (Some(body), None) => body,
        (None, Some(path)) => {
            BoundedRegularReader::read_tree_no_follow_utf8(&path, MAX_ISSUE_BODY_FILE_BYTES)
                .with_context(|| format!("failed to read issue body file {}", path.display()))?
        }
        (None, None) => String::new(),
        (Some(_), Some(_)) => bail!("use either --body or --body-file, not both"),
    };
    Ok(IssuePublicationOptions {
        repo,
        title,
        body,
        labels,
        forge,
    })
}

#[derive(Debug, Serialize)]
struct OrchestrationCollectReport {
    repo: PathBuf,
    summary_json: PathBuf,
    candidates: Vec<MergeCandidate>,
}

fn collect_orchestration_results(
    repo: &Path,
    summary_json: &Path,
    diff_summary_char_limit: usize,
) -> Result<OrchestrationCollectReport> {
    let contents =
        BoundedRegularReader::read_tree_no_follow(summary_json, MAX_ORCHESTRATION_SUMMARY_BYTES)
            .with_context(|| format!("failed to read summary JSON {}", summary_json.display()))?;
    let summary: Value = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse summary JSON {}", summary_json.display()))?;
    let agents = summary
        .get("agents")
        .and_then(Value::as_array)
        .context("summary JSON must contain an agents array")?;
    if agents.len() > MAX_ORCHESTRATION_SUMMARY_AGENTS {
        bail!("orchestration summary exceeds its {MAX_ORCHESTRATION_SUMMARY_AGENTS}-agent limit");
    }
    let mut candidates = Vec::new();
    let mut total_paths = 0_usize;
    let mut total_reports = 0_usize;

    for agent in agents {
        let agent_id = agent
            .get("id")
            .and_then(Value::as_str)
            .context("summary agent is missing string id")?;
        if agent_id.is_empty() || agent_id.len() > MAX_ORCHESTRATION_AGENT_ID_BYTES {
            bail!("summary agent id must contain 1..={MAX_ORCHESTRATION_AGENT_ID_BYTES} bytes");
        }
        let claims = agent_paths_from_summary(agent)
            .with_context(|| format!("summary agent '{agent_id}' has invalid paths"))?;
        total_paths = total_paths
            .checked_add(claims.len())
            .context("orchestration summary path count overflowed")?;
        if total_paths > MAX_ORCHESTRATION_SUMMARY_PATHS {
            bail!("orchestration summary exceeds its {MAX_ORCHESTRATION_SUMMARY_PATHS}-path limit");
        }
        let validations = validation_reports_from_summary(agent).with_context(|| {
            format!("summary agent '{agent_id}' has invalid validation reports")
        })?;
        validate_cli_validation_reports(&validations)?;
        total_reports = total_reports
            .checked_add(validations.len())
            .context("orchestration summary report count overflowed")?;
        if total_reports > MAX_VALIDATION_REPORTS {
            bail!("orchestration summary exceeds its validation report limit");
        }
        candidates.push(merge::collect_agent_result(MergeCollectOptions {
            repo: repo.to_path_buf(),
            agent_id: agent_id.to_string(),
            claimed_paths: claims,
            include_full_diff: false,
            diff_summary_char_limit,
            validations,
        })?);
    }

    candidates.sort_by(|left, right| left.metadata.agent_id.cmp(&right.metadata.agent_id));
    Ok(OrchestrationCollectReport {
        repo: repo.to_path_buf(),
        summary_json: summary_json.to_path_buf(),
        candidates,
    })
}

fn agent_paths_from_summary(agent: &Value) -> Result<Vec<PathBuf>> {
    let paths = agent
        .get("paths")
        .and_then(Value::as_array)
        .context("agent summary must contain paths array")?;
    paths
        .iter()
        .map(|path| {
            let path = path.as_str().context("agent path must be a string")?;
            if path.len() > 4096 || Path::new(path).components().count() > 256 {
                bail!("agent path exceeds its byte or component limit");
            }
            normalize_repo_relative_path(path).map_err(anyhow::Error::from)
        })
        .collect()
}

fn validation_reports_from_summary(agent: &Value) -> Result<Vec<ValidationReport>> {
    if agent.get("validation").is_some()
        || agent.get("validations").is_some()
        || agent.get("reports").is_some()
    {
        merge::validation_reports_from_json(agent)
    } else {
        Ok(Vec::new())
    }
}

fn load_validation_evidence(paths: &[PathBuf], agent_id: &str) -> Result<ValidationEvidenceBundle> {
    if paths.len() > MAX_VALIDATION_INPUT_FILES {
        bail!("validation evidence exceeds its input file count limit");
    }
    let mut evidence = ValidationEvidenceBundle::default();
    let mut total_bytes = 0_u64;
    let mut total_reports = 0_usize;
    for path in paths {
        let contents =
            BoundedRegularReader::read_tree_no_follow(path, MAX_VALIDATION_INPUT_FILE_BYTES)
                .with_context(|| format!("failed to read validation report {}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(contents.len()).unwrap_or(u64::MAX))
            .context("validation evidence byte count overflowed")?;
        if total_bytes > MAX_VALIDATION_INPUT_TOTAL_BYTES {
            bail!("validation evidence exceeds its aggregate byte limit");
        }
        let value: Value = serde_json::from_slice(&contents)
            .with_context(|| format!("failed to parse validation report {}", path.display()))?;
        let parsed = merge::validation_evidence_from_json_for_agent(&value, Some(agent_id))
            .with_context(|| format!("invalid validation report {}", path.display()))?;
        let reports = parsed.reports();
        validate_cli_validation_reports(&reports)?;
        total_reports = total_reports
            .checked_add(reports.len())
            .context("validation report count overflowed")?;
        if total_reports > MAX_VALIDATION_REPORTS {
            bail!("validation evidence exceeds its report count limit");
        }
        evidence.extend(parsed);
    }
    Ok(evidence)
}

fn validate_cli_validation_reports(reports: &[ValidationReport]) -> Result<()> {
    if reports.len() > MAX_VALIDATION_REPORTS {
        bail!("validation evidence exceeds its report count limit");
    }
    for report in reports {
        if report.name.len() > MAX_VALIDATION_REPORT_NAME_BYTES
            || report
                .message
                .as_ref()
                .is_some_and(|message| message.len() > MAX_VALIDATION_REPORT_MESSAGE_BYTES)
            || report.paths.len() > MAX_VALIDATION_REPORT_PATHS
        {
            bail!("validation report exceeds its structural input limits");
        }
        for path in &report.paths {
            if path.as_os_str().len() > 4096 || path.components().count() > 256 {
                bail!("validation report path exceeds its input limits");
            }
            normalize_repo_relative_path(path)
                .context("validation report path must be repository-relative")?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct SemanticSymbolQueryReport {
    query: String,
    matches: Vec<repo_semantic::SemanticSymbol>,
}

#[derive(Debug, Serialize)]
struct SemanticRiskQueryReport {
    #[serde(flatten)]
    semantic: repo_semantic::SemanticRiskReport,
    megafile_hotspots: Vec<MegafileAssessment>,
}

impl SemanticSymbolQueryReport {
    fn from_map(map: &SemanticRepoMap, query: &str) -> Self {
        let mut matches = map
            .symbols
            .iter()
            .filter(|symbol| symbol.name == query || symbol.qualified_path.join("::") == query)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.cmp(&right.span))
                .then_with(|| left.name.cmp(&right.name))
        });
        Self {
            query: query.to_string(),
            matches,
        }
    }
}

#[derive(Debug, Serialize)]
struct SemanticPathQueryReport {
    query: PathBuf,
    files: Vec<repo_semantic::SemanticFile>,
    symbols: Vec<repo_semantic::SemanticSymbol>,
    imports: Vec<repo_semantic::SemanticImport>,
    re_exports: Vec<repo_semantic::SemanticReExport>,
    dependencies: Vec<repo_semantic::SemanticDependency>,
    errors: Vec<repo_semantic::SemanticScanError>,
}

impl SemanticPathQueryReport {
    fn from_map(map: &SemanticRepoMap, query: &Path) -> Self {
        let query = normalize_display_path(query);
        Self {
            query: query.clone(),
            files: map
                .files
                .iter()
                .filter(|file| file.path == query)
                .cloned()
                .collect(),
            symbols: map
                .symbols
                .iter()
                .filter(|symbol| symbol.file == query)
                .cloned()
                .collect(),
            imports: map
                .imports
                .iter()
                .filter(|import| import.file == query)
                .cloned()
                .collect(),
            re_exports: map
                .re_exports
                .iter()
                .filter(|export| export.file == query)
                .cloned()
                .collect(),
            dependencies: map
                .dependencies
                .iter()
                .filter(|dependency| {
                    dependency.from_file == query
                        || dependency.to_file.as_deref() == Some(query.as_path())
                })
                .cloned()
                .collect(),
            errors: map
                .errors
                .iter()
                .filter(|error| error.file == query)
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct LlmProvidersReport {
    providers: Vec<LlmProviderInfo>,
    network_providers_required: bool,
    network_providers_configured: bool,
}

#[derive(Debug, Serialize)]
struct LlmProviderInfo {
    id: String,
    model: String,
    kind: String,
    configured: bool,
    network_required: bool,
    notes: String,
    capabilities: ProviderCapabilities,
}

#[derive(Debug, Serialize)]
struct LlmPromptPreviewReport {
    task_file: PathBuf,
    agent_id: String,
    claimed_paths: Vec<PathBuf>,
    prompt: crate::llm::Prompt,
    rendered: String,
    redactions: crate::llm::RedactionSummary,
    provider: LlmProviderInfo,
}

fn build_prompt_preview(args: LlmPromptPreviewArgs) -> Result<LlmPromptPreviewReport> {
    let repo = discover_repo_root(&args.repo)?;
    let task =
        BoundedRegularReader::read_tree_no_follow_utf8(&args.task_file, MAX_PROMPT_TASK_BYTES)
            .with_context(|| format!("failed to read task file {}", args.task_file.display()))?;
    let mut context = PromptContext::new(task, &args.agent_id);
    if args.paths.len() > MAX_PROMPT_PATHS {
        bail!("prompt preview exceeds its {MAX_PROMPT_PATHS}-path input limit");
    }
    let mut claimed_paths = args
        .paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    claimed_paths.sort();
    claimed_paths.dedup();

    let mut excerpt_bytes = 0_usize;
    for path in &claimed_paths {
        context = context.with_claimed_path(path.clone(), "explicit prompt preview path");
        let content = BoundedRegularReader::read_relative_optional_utf8(
            &repo,
            path,
            MAX_PROMPT_EXCERPT_BYTES,
        )
        .with_context(|| format!("failed to read prompt path {}", path.display()))?;
        let Some(content) = content else {
            continue;
        };
        excerpt_bytes = excerpt_bytes
            .checked_add(content.len())
            .context("prompt preview excerpt byte count overflowed")?;
        if excerpt_bytes > MAX_PROMPT_EXCERPT_TOTAL_BYTES {
            bail!(
                "prompt preview excerpts exceed their {MAX_PROMPT_EXCERPT_TOTAL_BYTES}-byte aggregate limit"
            );
        }
        context = context.with_repo_excerpt(
            RepoExcerpt::new(path.clone(), content).with_language(language_for_path(path)),
        );
    }

    let provider = LlmProviderInfo {
        id: "fake".to_string(),
        model: "deterministic-fake".to_string(),
        kind: "local_fake".to_string(),
        configured: true,
        network_required: false,
        notes: "Prompt preview only; no provider call is made.".to_string(),
        capabilities: ProviderCapabilities::local_fake(),
    };
    let prompt = context.assemble_prompt(&Redactor::new());
    let rendered = prompt.render();
    if rendered.chars().count() > context.budget.max_input_chars {
        bail!(
            "prompt preview exceeds its {}-character input budget",
            context.budget.max_input_chars
        );
    }
    let redactions = prompt.redactions.clone();

    Ok(LlmPromptPreviewReport {
        task_file: args.task_file,
        agent_id: args.agent_id,
        claimed_paths,
        prompt,
        rendered,
        redactions,
        provider,
    })
}

fn run_agent_from_args(args: RunAgentArgs) -> Result<AgentRunReport> {
    if args.provider != "fake" {
        bail!(
            "provider '{}' is not configured for agent run; only local fake is available",
            args.provider
        );
    }

    let proposal_path = args
        .fake_proposal
        .context("fake provider agent run requires --fake-proposal <proposal.json>")?;
    let proposal = load_fake_proposal(&proposal_path)?;
    let task =
        BoundedRegularReader::read_tree_no_follow_utf8(&args.task_file, MAX_AGENT_TASK_BYTES)
            .with_context(|| format!("failed to read task file {}", args.task_file.display()))?;
    let request_id = args
        .request_id
        .unwrap_or_else(|| agent::default_request_id(&args.agent_id));
    let model = args
        .model
        .unwrap_or_else(|| agent::default_model().to_string());
    let mut provider = FakeProvider::new("fake", model.clone());
    provider.push_response(request_id.clone(), proposal);

    agent::run_agent_with_provider(
        AgentRunOptions {
            repo: args.repo,
            agent_id: args.agent_id,
            task,
            request_id: Some(request_id),
            model: Some(model),
            claimed_paths: args.paths,
            validation_commands: args
                .validation_commands
                .into_iter()
                .map(AgentValidationCommand::required)
                .collect(),
            keep_claims: args.keep_claims,
            worktree_reuse: args.reuse,
            provider_command_policy: if args.allow_provider_commands {
                ProviderCommandPolicy::AllowUnsafeShell
            } else {
                ProviderCommandPolicy::Disabled
            },
            command_timeout: Duration::from_secs(args.command_timeout_seconds),
        },
        &mut provider,
    )
}

fn load_fake_proposal(path: &Path) -> Result<WorkProposal> {
    let contents = BoundedRegularReader::read_tree_no_follow(path, MAX_FAKE_PROPOSAL_BYTES)
        .with_context(|| format!("failed to read fake proposal {}", path.display()))?;
    let proposal: WorkProposal = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse fake proposal {}", path.display()))?;
    if proposal.commands.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.patches.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.notes.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.rendered_len() > 32 * 1024
    {
        bail!("fake proposal exceeds its structural or output budget");
    }
    Ok(proposal)
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn normalize_display_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref().components().collect()
}

fn language_for_path(path: &Path) -> String {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => "rust",
        Some("md") => "markdown",
        Some("toml") => "toml",
        Some("json") => "json",
        Some("yaml" | "yml") => "yaml",
        Some("sh" | "bash") => "shell",
        _ => "text",
    }
    .to_string()
}

fn parse_agent_worktree_reuse_policy(
    value: &str,
) -> std::result::Result<AgentWorktreeReusePolicy, String> {
    match value {
        "clean" => Ok(AgentWorktreeReusePolicy::Clean),
        "required" => Ok(AgentWorktreeReusePolicy::Required),
        "fresh" => Ok(AgentWorktreeReusePolicy::Fresh),
        _ => Err("expected one of: clean, required, fresh".to_string()),
    }
}

fn parse_positive_seconds(value: &str) -> std::result::Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "expected a positive integer number of seconds".to_string())?;
    if seconds == 0 {
        Err("timeout must be greater than zero seconds".to_string())
    } else {
        Ok(seconds)
    }
}

fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| "expected a positive 64-bit unsigned integer".to_string())?;
    if value == 0 {
        Err("value must be greater than zero".to_string())
    } else {
        Ok(value)
    }
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "expected a positive integer".to_string())?;
    if value == 0 {
        Err("value must be greater than zero".to_string())
    } else {
        Ok(value)
    }
}

fn parse_positive_finite_f64(value: &str) -> std::result::Result<f64, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "expected a finite positive number".to_string())?;
    if !value.is_finite() || value <= 0.0 {
        Err("value must be finite and greater than zero".to_string())
    } else {
        Ok(value)
    }
}

fn parse_worktree_reuse_policy(value: &str) -> std::result::Result<WorktreeReusePolicy, String> {
    match value {
        "clean" => Ok(WorktreeReusePolicy::Clean),
        "required" => Ok(WorktreeReusePolicy::Required),
        "fresh" => Ok(WorktreeReusePolicy::Fresh),
        "reset" => Ok(WorktreeReusePolicy::Reset),
        _ => Err("expected one of: clean, required, fresh, reset".to_string()),
    }
}

fn parse_semantic_coordination_mode(
    value: &str,
) -> std::result::Result<SemanticCoordinationMode, String> {
    match value {
        "off" => Ok(SemanticCoordinationMode::Off),
        "warn" => Ok(SemanticCoordinationMode::Warn),
        "block" => Ok(SemanticCoordinationMode::Block),
        _ => Err("expected one of: off, warn, block".to_string()),
    }
}

fn parse_forge_kind(value: &str) -> std::result::Result<ForgeKind, String> {
    ForgeKind::parse(value)
}

fn parse_inbox_permission_mode(value: &str) -> std::result::Result<InboxPermissionMode, String> {
    InboxPermissionMode::parse(value)
}

fn parse_evaluation_execution(
    value: &str,
) -> std::result::Result<crate::evaluation::EvaluationExecution, String> {
    match value {
        "deterministic-fake" => Ok(crate::evaluation::EvaluationExecution::DeterministicFake),
        "real-provider" => Ok(crate::evaluation::EvaluationExecution::RealProvider),
        _ => Err("expected one of: deterministic-fake, real-provider".to_string()),
    }
}

fn live_clock(value: Option<&str>) -> Result<LiveClock> {
    match value {
        Some(value) => LiveClock::parse(value),
        None => Ok(LiveClock::now()),
    }
}

fn print_repository_info(info: &RepositoryInfo, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(info)?);
    } else {
        let head = info.head.as_deref().unwrap_or("<unborn>");
        println!("Repository: {}", info.path.display());
        println!("Git dir: {}", info.git_dir.display());
        println!("HEAD: {head}");
    }
    Ok(())
}

fn print_repo_map(map: &RepoMap, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(map)?);
    } else if map.entries.is_empty() {
        println!("Repository: {}", map.root.display());
        println!("No entries found.");
    } else {
        println!("Repository: {}", map.root.display());
        for entry in &map.entries {
            let size = entry
                .size_bytes
                .map(|size| size.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{}\t{}\t{}\t{}",
                entry.path.display(),
                repo_entry_kind_label(entry.kind),
                size,
                entry.category
            );
        }
    }
    Ok(())
}

fn print_semantic_repo_map(map: &SemanticRepoMap, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(map)?);
    } else {
        println!("Repository: {}", map.root.display());
        println!("Rust files: {}", map.files.len());
        println!("Symbols: {}", map.symbols.len());
        println!("Imports: {}", map.imports.len());
        println!("Re-exports: {}", map.re_exports.len());
        println!("Dependencies: {}", map.dependencies.len());
        if !map.errors.is_empty() {
            println!("Errors: {}", map.errors.len());
        }
        for symbol in &map.symbols {
            println!(
                "{}\t{:?}\t{}",
                symbol.file.display(),
                symbol.kind,
                symbol.qualified_path.join("::")
            );
        }
    }
    Ok(())
}

fn print_query_report<T: Serialize + std::fmt::Debug>(report: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{report:#?}");
    }
    Ok(())
}

fn resolve_run_id_for_run(
    repo: &Path,
    family: RunArtifactFamily,
    explicit: Option<&str>,
    json: bool,
) -> Result<ResolvedRunId> {
    match artifacts::resolve_run_id(repo, family, explicit) {
        Ok(resolved) => Ok(resolved),
        Err(error) => {
            if json {
                let report = RunArtifactRefusalReport::new(repo, family, explicit, &error);
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Err(error)
        }
    }
}

#[derive(Debug, Serialize)]
struct RunArtifactRefusalReport {
    family: RunArtifactFamily,
    success: bool,
    status: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_dir: Option<PathBuf>,
    error_kind: &'static str,
    message: String,
    next_action: &'static str,
}

impl RunArtifactRefusalReport {
    fn new(
        repo: &Path,
        family: RunArtifactFamily,
        explicit: Option<&str>,
        error: &anyhow::Error,
    ) -> Self {
        let run_id = explicit.map(ToOwned::to_owned);
        let run_dir = explicit
            .and_then(|value| RunId::new(value).ok())
            .and_then(|run_id| {
                artifacts::discover_repo_root(repo)
                    .ok()
                    .map(|repo| (repo, run_id))
            })
            .map(|(_, run_id)| family.run_root().join(run_id.as_str()));
        Self {
            family,
            success: false,
            status: "refused",
            run_id,
            run_dir,
            error_kind: "run_artifact_refused",
            message: error.to_string(),
            next_action: "choose a new --run-id or prune old artifacts first",
        }
    }
}

fn print_semantic_coordination_report(
    report: &SemanticCoordinationReport,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("Semantic intent: {}", report.intent.token.get());
        println!("Agent: {}", report.intent.agent_id);
        println!("Persisted: {}", report.persisted);
        println!(
            "Conflicts: blocking={} advisory={}",
            report.blocking_conflict_count, report.advisory_conflict_count
        );
        for conflict in &report.conflicts {
            println!(
                "  {:?}\t{:?}\t{}",
                conflict.severity, conflict.kind, conflict.message
            );
        }
    }
    Ok(())
}

fn print_merge_candidate(candidate: &MergeCandidate, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(candidate)?);
    } else {
        println!("Agent: {}", candidate.metadata.agent_id);
        println!("Worktree: {}", candidate.metadata.worktree_path.display());
        println!("Changed paths: {}", candidate.changed_paths.len());
        for path in &candidate.changed_paths {
            println!("  {}", path.display());
        }
        if !candidate.unclaimed_changed_paths.is_empty() {
            println!("Unclaimed edits:");
            for path in &candidate.unclaimed_changed_paths {
                println!("  {}", path.display());
            }
        }
        if !candidate.diff.summary.text.is_empty() {
            println!("{}", candidate.diff.summary.text);
        }
    }
    Ok(())
}

fn print_merge_preview(preview: &MergeApplyPreview, json: bool) -> Result<()> {
    if json {
        let watermark =
            crate::merge_freshness::MergePreviewFreshnessWatermark::capture_from_preview(preview)?;
        let mut value = serde_json::to_value(preview)?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "freshness_watermark".to_string(),
                serde_json::to_value(watermark)?,
            );
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print_merge_candidate(&preview.candidate, false)?;
        println!("Readiness: {:?}", preview.safety.readiness.status);
        if !preview.safety.readiness.blockers.is_empty() {
            println!("Blockers: {:?}", preview.safety.readiness.blockers);
        }
        if !preview.safety.readiness.forced.is_empty() {
            println!("Forced: {:?}", preview.safety.readiness.forced);
        }
        for warning in &preview.safety.megafile_warnings {
            println!(
                "Megafile warning: {} ({:?})",
                warning.path.display(),
                warning.signals
            );
        }
    }
    Ok(())
}

fn print_merge_apply_report(report: &MergeApplyReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!(
            "Merge apply: {}",
            if report.applied {
                "applied"
            } else {
                "nothing to apply"
            }
        );
        println!("Readiness: {:?}", report.preview.safety.readiness.status);
        if !report.recorded_collision_paths.is_empty() {
            println!("Recorded merge collision paths:");
            for path in &report.recorded_collision_paths {
                println!("  {}", path.display());
            }
        }
        if let Some(decomposition) = &report.accepted_decomposition {
            println!(
                "Accepted megafile decomposition: {}",
                decomposition.path.display()
            );
        }
        if let Some(lifecycle) = &report.lifecycle {
            print_worktree_lifecycle_report(lifecycle, false)?;
        }
        if let Some(error) = &report.error {
            println!("Error: {error}");
        }
    }
    Ok(())
}

fn print_merge_apply_review_refusal(
    refusal: &merge::MergeApplyReviewRefusalEnvelope,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(refusal)?);
    }
    Ok(())
}

fn print_merge_arbitration_report(report: &MergeArbitrationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!("Merge arbitration outcome: {:?}", report.outcome);
    println!("Run: {}", report.run_id);
    println!("Neutral arbiter: {}", report.arbiter_id);
    println!(
        "Neutral worktree: {} ({})",
        report.neutral_worktree.path.display(),
        report.neutral_worktree.branch
    );
    println!("Exact reviewed base: {}", report.reviewed_base_oid);
    println!("First side: {:?}", report.sides[0]);
    println!("Second side: {:?}", report.sides[1]);
    println!("Approved: {}", report.approved);
    println!(
        "Rationale artifact: {} sha256={}",
        report.rationale_artifact, report.rationale_sha256
    );
    if let Some(candidate_artifact) = &report.candidate_artifact {
        let candidate_sha256 = report
            .candidate_sha256
            .as_deref()
            .context("arbitration candidate artifact is missing its digest")?;
        println!(
            "Candidate artifact: {} sha256={}",
            candidate_artifact, candidate_sha256
        );
    } else {
        println!("Candidate artifact: none");
    }
    println!("Candidate status: {:?}", report.candidate_status);
    println!("Validation commands:");
    for command in &report.validation_commands {
        println!("  {command}");
    }
    println!("Primary worktree mutated: {}", report.primary_mutated);
    println!(
        "Later ordinary human-invoked merge apply required: {}",
        report.later_ordinary_merge_apply_required
    );
    println!(
        "Arbitration never applies to primary; use a later ordinary merge preview/apply gate."
    );
    Ok(())
}

fn print_pr_publication_report(report: &PrPublicationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("PR publication: {:?}", report.status);
        println!("Agent: {}", report.agent_id);
        println!("Branch: {}", report.branch);
        println!("Base: {}", report.base);
        println!("Readiness: {:?}", report.readiness);
        if !report.blockers.is_empty() {
            println!("Blockers: {:?}", report.blockers);
        }
        if let Some(url) = &report.pr_url {
            println!("URL: {url}");
        }
        println!("Next: {}", report.next_action);
    }
    Ok(())
}

fn repo_entry_kind_label(kind: RepoEntryKind) -> &'static str {
    match kind {
        RepoEntryKind::Directory => "dir",
        RepoEntryKind::File => "file",
        RepoEntryKind::Symlink => "symlink",
        RepoEntryKind::Other => "other",
    }
}

#[derive(Debug, Serialize)]
struct PlanValidationReport {
    plan_file: PathBuf,
    agent_count: usize,
    path_claim_count: usize,
    dependency_count: usize,
}

fn print_plan_validation_report(report: &PlanValidationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("Plan valid: {}", report.plan_file.display());
        println!("Agents: {}", report.agent_count);
        println!("Path claims: {}", report.path_claim_count);
        println!("Dependencies: {}", report.dependency_count);
    }
    Ok(())
}

fn print_orchestration_summary(summary: &OrchestrationSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
    } else {
        let status = if summary.success {
            "succeeded"
        } else {
            "failed"
        };
        println!("Orchestration: {status}");
        println!("Repository: {}", summary.repo.display());
        for agent in &summary.agents {
            let exit = agent
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{}\t{}\texit={}\t{}",
                agent.id,
                agent_status_label(agent.status),
                exit,
                agent
                    .worktree
                    .as_ref()
                    .map(|worktree| worktree.path.display().to_string())
                    .unwrap_or_else(|| "<no worktree>".to_string())
            );
            if let Some(error) = &agent.error {
                println!("  {error}");
            }
        }
        if !summary.release_errors.is_empty() {
            println!("Release errors:");
            for error in &summary.release_errors {
                println!("  {error}");
            }
        }
    }
    Ok(())
}

fn print_agent_run_report(report: &AgentRunReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        let status = if report.success {
            "succeeded"
        } else {
            "failed"
        };
        println!("Agent run: {status}");
        println!("Agent: {}", report.agent_id);
        println!("Provider: {}", report.provider_id);
        println!("Worktree: {}", report.worktree.path.display());
        println!("Changed paths: {}", report.candidate.changed_paths.len());
        for path in &report.candidate.changed_paths {
            println!("  {}", path.display());
        }
        if !report.candidate.unclaimed_changed_paths.is_empty() {
            println!("Unclaimed edits:");
            for path in &report.candidate.unclaimed_changed_paths {
                println!("  {}", path.display());
            }
        }
        if let Some(error) = &report.error {
            println!("  {error}");
        }
    }
    Ok(())
}

fn print_agent_run_failure_report(report: &AgentRunFailureReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AgentListReport {
    observed_coordination_depth: u32,
    agents: Vec<AgentListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AgentListEntry {
    #[serde(flatten)]
    process: AgentProcessRecord,
    observed_depth: u32,
}

fn agent_list_report(processes: &[AgentProcessRecord]) -> AgentListReport {
    let observed = observe_hierarchy(processes.iter().map(|process| ObservedHierarchyNode {
        id: process.task_id.as_str(),
        parent: process.parent.as_deref(),
        coordinator: is_coordinator_role_label(&process.role),
    }));
    AgentListReport {
        observed_coordination_depth: observed.coordination_depth,
        agents: processes
            .iter()
            .map(|process| AgentListEntry {
                observed_depth: observed.depths.get(&process.task_id).copied().unwrap_or(0),
                process: process.clone(),
            })
            .collect(),
    }
}

fn print_agent_processes(processes: &[AgentProcessRecord], json: bool) -> Result<()> {
    let report = agent_list_report(processes);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.agents.is_empty() {
        println!("No live MACO agents registered.");
        println!(
            "observed_coordination_depth\t{}",
            report.observed_coordination_depth
        );
    } else {
        println!(
            "observed_coordination_depth\t{}",
            report.observed_coordination_depth
        );
        for agent in &report.agents {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                agent.process.pid,
                agent.process.role,
                agent.process.run_id,
                agent.process.task_id,
                agent.process.parent.as_deref().unwrap_or("-"),
                agent.observed_depth,
                agent.process.repo.display(),
                agent.process.launch_timestamp_ms,
                agent.process.argv.join(" ")
            );
        }
    }
    Ok(())
}

fn print_agent_stop_report(report: &AgentStopReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.stopped.is_empty() {
        println!("No live MACO agents matched the selected run.");
    } else {
        for stopped in &report.stopped {
            println!(
                "{:?}\t{}\t{}\t{}",
                stopped.outcome,
                stopped.process.pid,
                stopped.process.run_id,
                stopped.process.task_id
            );
        }
    }
    Ok(())
}

fn print_worktree_lifecycle_report(report: &WorktreeLifecycleReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Worktree lifecycle: {} ({})",
        if report.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if report.dry_run { "dry-run" } else { "apply" }
    );
    println!("Merged auto-reap: {}", report.auto_reap_merged);
    println!(
        "Retry supersession: {:?}{}",
        report.retry.status,
        report
            .retry
            .predecessor_agent_id
            .as_deref()
            .map(|agent_id| format!(" ({agent_id})"))
            .unwrap_or_default()
    );
    if report.reconciliation.enabled {
        println!(
            "Startup reconciliation: {} finding(s), {} record(s) forgotten, {} registration(s) pruned, {} directory(s) quarantined",
            report.reconciliation.entries.len(),
            report.reconciliation.forgotten_record_count,
            report.reconciliation.pruned_registration_count,
            report.reconciliation.quarantined_directory_count,
        );
        for entry in &report.reconciliation.entries {
            println!(
                "  {}\t{:?}\t{:?}\t{}",
                entry.name,
                entry.state,
                entry.action,
                entry.path.display()
            );
        }
    }
    if let Some(gc) = &report.worktree_gc {
        println!(
            "Worktrees: considered={}, {}={}, retained={}, protected={}",
            gc.considered_count,
            if gc.dry_run {
                "would_remove"
            } else {
                "removed"
            },
            gc.removed_count,
            gc.retained_count,
            gc.protected_count
        );
    }
    println!(
        "Git worktree prune: {:?}, stale={}, pruned={}, protected={}",
        report.repository_prune.status,
        report.repository_prune.stale_registration_count,
        report.repository_prune.pruned_registration_count,
        report.repository_prune.protected_registration_count,
    );
    if let Some(artifacts) = &report.artifact_prune {
        println!(
            "O2-launch artifacts: candidates={}, deleted={}, kept={}, refused={}",
            artifacts.delete_candidate_count,
            artifacts.deleted_count,
            artifacts.kept_count,
            artifacts.refused_unfinalized_count
        );
        println!(
            "Artifact safety: reclaim_unverifiable={}, external_writers_stopped={}",
            artifacts.reclaim_unverifiable, artifacts.external_writers_stopped
        );
    }
    println!("Apparent bytes checked: {}", report.apparent_checked_bytes);
    println!(
        "Projected reclaimable bytes: {}",
        report.projected_reclaimable_bytes
    );
    println!(
        "Actually reclaimed bytes: {}",
        report.actual_reclaimed_bytes
    );
    Ok(())
}

fn agent_status_label(status: AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Pending => "pending",
        AgentRunStatus::Succeeded => "succeeded",
        AgentRunStatus::Failed => "failed",
        AgentRunStatus::Skipped => "skipped",
    }
}

fn print_worktree_record(record: &WorktreeRecord, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(record)?);
    } else {
        println!("Worktree: {}", record.name);
        println!("Branch: {}", record.branch);
        println!("Path: {}", record.path.display());
    }
    Ok(())
}

fn print_worktree_create_lifecycle_report(
    record: &WorktreeRecord,
    lifecycle: &WorktreeLifecycleReport,
    json: bool,
) -> Result<()> {
    if json {
        #[derive(Serialize)]
        struct Report<'a> {
            worktree: &'a WorktreeRecord,
            lifecycle: &'a WorktreeLifecycleReport,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Report {
                worktree: record,
                lifecycle,
            })?
        );
    } else {
        print_worktree_record(record, false)?;
        print_worktree_lifecycle_report(lifecycle, false)?;
    }
    Ok(())
}

fn print_worktree_gc_report(report: &WorktreeGcReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Worktree GC: {}{}",
        if report.dry_run { "dry-run" } else { "applied" },
        if report.targets_only {
            " targets-only"
        } else {
            ""
        }
    );
    println!("Considered: {}", report.considered_count);
    println!("Removed: {}", report.removed_count);
    println!("Protected: {}", report.protected_count);
    println!("Retained: {}", report.retained_count);
    println!("Targets cleaned: {}", report.target_removed_count);
    println!("Orphans pruned: {}", report.orphan_removed_count);
    println!(
        "Apparent bytes considered: {}",
        report.apparent_considered_bytes
    );
    println!(
        "Estimated bytes reclaimable: {}",
        report.estimated_reclaimable_bytes
    );
    println!(
        "Estimated bytes reclaimed: {}",
        report.estimated_reclaimed_bytes
    );
    for path in &report.allowed_untracked_paths {
        println!(
            "Allowed untracked path: {}",
            worktree_report_path_text(path)
        );
    }
    for entry in &report.entries {
        let branch = entry.branch.as_deref().unwrap_or("-");
        let target = entry
            .target_path
            .as_ref()
            .map(|path| format!(" target={}", path.display()))
            .unwrap_or_default();
        let gate_denial = entry
            .gate_denial
            .as_ref()
            .map(|denial| format!(" gate-denial={}", denial.denial_id.as_str()))
            .unwrap_or_default();
        let retention = entry
            .retention_operation_id
            .map(|operation_id| format!(" retention-operation={}", operation_id.get()))
            .unwrap_or_default();
        let untracked = worktree_gc_untracked_suffix(&entry.untracked_paths);
        let liveness = worktree_target_liveness_suffix(entry.target_liveness.as_ref());
        println!(
            "{}\t{}\t{}\t{}\t{}{}{}{}{}{}",
            worktree_gc_status_label(entry.status),
            worktree_gc_reason_label(entry.reason),
            entry.name,
            branch,
            entry.path.display(),
            target,
            gate_denial,
            retention,
            untracked,
            liveness
        );
    }
    Ok(())
}

fn print_worktree_sweep_report(report: &WorktreeSweepReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let removal_label = if report.dry_run {
        "Would remove"
    } else {
        "Removed"
    };
    let target_label = if report.dry_run {
        "Targets would clean"
    } else {
        "Targets cleaned"
    };
    let target_action_count = if report.dry_run {
        report
            .repositories
            .iter()
            .filter_map(|repository| repository.gc_report.as_ref())
            .map(worktree_gc_target_action_count)
            .sum()
    } else {
        report.target_removed_count
    };
    let orphan_label = if report.dry_run {
        "Orphans would prune"
    } else {
        "Orphans pruned"
    };
    println!(
        "Workspace worktree sweep: {}{}",
        if report.dry_run { "dry-run" } else { "applied" },
        if report.targets_only {
            " targets-only"
        } else {
            ""
        }
    );
    println!("Workspace: {}", report.workspace.display());
    println!(
        "Discovery: {} (roots={})",
        worktree_sweep_discovery_status_label(report.discovery_status),
        report.worktree_root_discovered_count
    );
    if let Some(warning) = worktree_sweep_discovery_warning(report.discovery_status) {
        println!("{warning}");
    }
    for path in &report.allowed_untracked_paths {
        println!(
            "Allowed untracked path: {}",
            worktree_report_path_text(path)
        );
    }
    println!(
        "Discovered roots: total={} inspected={} skipped-before-gc={} gc-failed={} total-failures={}",
        report.repository_discovered_count,
        report.repository_inspected_count,
        report.repository_pre_gc_skipped_count,
        report.repository_gc_failed_count,
        report.repository_failure_count
    );
    println!("Considered: {}", report.considered_count);
    println!("{removal_label}: {}", report.removed_count);
    println!("Protected: {}", report.protected_count);
    println!("Retained: {}", report.retained_count);
    println!("{target_label}: {target_action_count}");
    println!("{orphan_label}: {}", report.orphan_removed_count);
    println!(
        "Apparent bytes considered: {}",
        report.apparent_considered_bytes
    );
    println!(
        "Estimated bytes reclaimable: {}",
        report.estimated_reclaimable_bytes
    );
    println!(
        "Estimated bytes reclaimed: {}",
        report.estimated_reclaimed_bytes
    );

    for repository in &report.repositories {
        let resolved_repository = repository
            .repository
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "Repository group={} root-kind={} status={} repository={} worktree-root={} gc-attempted={} effects-may-have-occurred={}",
            repository.group,
            worktree_sweep_root_kind_label(repository.root_kind),
            worktree_sweep_repository_status_label(repository.status),
            resolved_repository,
            repository.worktree_root.display(),
            repository.gc_attempted,
            repository.effects_may_have_occurred
        );
        if let Some(failure) = &repository.failure {
            println!(
                "  Failure: kind={} message={}",
                worktree_sweep_failure_kind_label(failure.kind),
                failure.message
            );
        }
        if let Some(gc_report) = &repository.gc_report {
            let target_action_label = if gc_report.dry_run {
                "targets-would-clean"
            } else {
                "targets-cleaned"
            };
            println!(
                "  GC: considered={} {}={} protected={} retained={} {}={} orphans={} apparent-bytes={} reclaimable-bytes={} reclaimed-bytes={}",
                gc_report.considered_count,
                if gc_report.dry_run {
                    "would-remove"
                } else {
                    "removed"
                },
                gc_report.removed_count,
                gc_report.protected_count,
                gc_report.retained_count,
                target_action_label,
                worktree_gc_target_action_count(gc_report),
                gc_report.orphan_removed_count,
                gc_report.apparent_considered_bytes,
                gc_report.estimated_reclaimable_bytes,
                gc_report.estimated_reclaimed_bytes
            );
            for entry in &gc_report.entries {
                let branch = entry.branch.as_deref().unwrap_or("-");
                let untracked = worktree_gc_untracked_suffix(&entry.untracked_paths);
                let liveness = worktree_target_liveness_suffix(entry.target_liveness.as_ref());
                println!(
                    "    {}\t{}\t{}\t{}\t{}{}{}",
                    worktree_gc_status_label(entry.status),
                    worktree_gc_reason_label(entry.reason),
                    entry.name,
                    branch,
                    entry.path.display(),
                    untracked,
                    liveness
                );
            }
        }
    }
    Ok(())
}

fn worktree_gc_untracked_suffix(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        String::new()
    } else {
        format!(
            " untracked={}",
            paths
                .iter()
                .map(|path| worktree_report_path_text(path))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

fn worktree_target_liveness_suffix(evidence: Option<&WorktreeTargetLivenessEvidence>) -> String {
    let Some(evidence) = evidence else {
        return String::new();
    };
    format!(
        " target-liveness-pid={} target-liveness-source={} target-liveness-cause={}",
        evidence
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        worktree_target_liveness_source_label(evidence.source),
        worktree_target_liveness_cause_label(evidence.cause),
    )
}

fn worktree_target_liveness_source_label(source: WorktreeTargetLivenessSource) -> &'static str {
    match source {
        WorktreeTargetLivenessSource::CargoTargetDir => "cargo-target-dir",
        WorktreeTargetLivenessSource::DefaultCargoTarget => "default-cargo-target",
        WorktreeTargetLivenessSource::ProcessEnvironment => "process-environment",
        WorktreeTargetLivenessSource::ProcessCommandLine => "process-command-line",
        WorktreeTargetLivenessSource::ProcessCwd => "process-cwd",
        WorktreeTargetLivenessSource::ProcessExecutable => "process-executable",
        WorktreeTargetLivenessSource::ProcessFileDescriptor => "process-file-descriptor",
        WorktreeTargetLivenessSource::ProcScan => "proc-scan",
        WorktreeTargetLivenessSource::MountNamespace => "mount-namespace",
        WorktreeTargetLivenessSource::Platform => "platform",
        WorktreeTargetLivenessSource::TargetIdentity => "target-identity",
    }
}

fn worktree_target_liveness_cause_label(cause: WorktreeTargetLivenessCause) -> &'static str {
    match cause {
        WorktreeTargetLivenessCause::PathOverlap => "path-overlap",
        WorktreeTargetLivenessCause::CargoLikeProcessInLane => "cargo-like-process-in-lane",
        WorktreeTargetLivenessCause::ReadFailed => "read-failed",
        WorktreeTargetLivenessCause::InvalidValue => "invalid-value",
        WorktreeTargetLivenessCause::LimitExceeded => "limit-exceeded",
        WorktreeTargetLivenessCause::TimedOut => "timed-out",
        WorktreeTargetLivenessCause::Unsupported => "unsupported",
        WorktreeTargetLivenessCause::NamespaceUnresolved => "namespace-unresolved",
        WorktreeTargetLivenessCause::IdentityChanged => "identity-changed",
    }
}

fn worktree_sweep_discovery_status_label(status: WorktreeSweepDiscoveryStatus) -> &'static str {
    match status {
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered => "no-roots-discovered",
        WorktreeSweepDiscoveryStatus::RootsDiscovered => "roots-discovered",
    }
}

fn worktree_sweep_discovery_warning(status: WorktreeSweepDiscoveryStatus) -> Option<&'static str> {
    match status {
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered => {
            Some("WARNING: no worktree roots were discovered; this is not a clean-sweep result.")
        }
        WorktreeSweepDiscoveryStatus::RootsDiscovered => None,
    }
}

fn worktree_sweep_root_kind_label(kind: WorktreeSweepRootKind) -> &'static str {
    match kind {
        WorktreeSweepRootKind::WorkspaceManaged => "workspace-managed",
        WorktreeSweepRootKind::RepositoryLocal => "repository-local",
    }
}

fn worktree_gc_target_action_count(report: &WorktreeGcReport) -> usize {
    if report.dry_run {
        report
            .entries
            .iter()
            .filter(|entry| entry.reason == WorktreeGcReason::TargetWouldRemove)
            .count()
    } else {
        report.target_removed_count
    }
}

fn worktree_sweep_repository_status_label(status: WorktreeSweepRepositoryStatus) -> &'static str {
    match status {
        WorktreeSweepRepositoryStatus::Inspected => "inspected",
        WorktreeSweepRepositoryStatus::Skipped => "skipped",
        WorktreeSweepRepositoryStatus::Failed => "failed",
    }
}

fn worktree_sweep_failure_kind_label(kind: WorktreeSweepFailureKind) -> &'static str {
    match kind {
        WorktreeSweepFailureKind::RepositoryOpen => "repository_open",
        WorktreeSweepFailureKind::RepositoryAssociation => "repository_association",
        WorktreeSweepFailureKind::AmbiguousRepository => "ambiguous_repository",
        WorktreeSweepFailureKind::GarbageCollection => "garbage_collection",
    }
}

fn worktree_gc_status_label(status: WorktreeGcStatus) -> &'static str {
    match status {
        WorktreeGcStatus::Removed => "removed",
        WorktreeGcStatus::WouldRemove => "would-remove",
        WorktreeGcStatus::Retained => "retained",
        WorktreeGcStatus::Protected => "protected",
        WorktreeGcStatus::OrphanPruned => "orphan-pruned",
        WorktreeGcStatus::OrphanQuarantined => "orphan-quarantined",
        WorktreeGcStatus::OrphanWouldPrune => "orphan-would-prune",
    }
}

fn worktree_gc_reason_label(reason: WorktreeGcReason) -> &'static str {
    match reason {
        WorktreeGcReason::FinishedBranch => "finished-branch",
        WorktreeGcReason::SupersededLane => "superseded-lane",
        WorktreeGcReason::UnmergedBranch => "unmerged-branch",
        WorktreeGcReason::RetentionKeep => "retention-keep",
        WorktreeGcReason::ExcludedCurrentWorktree => "excluded-current-worktree",
        WorktreeGcReason::Dirty => "dirty",
        WorktreeGcReason::UntrackedOnly => "untracked-only",
        WorktreeGcReason::ActiveLease => "active-lease",
        WorktreeGcReason::ActiveClaim => "active-claim",
        WorktreeGcReason::TargetRemoved => "target-removed",
        WorktreeGcReason::TargetWouldRemove => "target-would-remove",
        WorktreeGcReason::LiveTarget => "live-target",
        WorktreeGcReason::TargetLivenessUnknown => "target-liveness-unknown",
        WorktreeGcReason::TargetIdentityChanged => "target-identity-changed",
        WorktreeGcReason::SizeMeasurementFailed => "size-measurement-failed",
        WorktreeGcReason::NoTarget => "no-target",
        WorktreeGcReason::UnregisteredOrphan => "unregistered-orphan",
        WorktreeGcReason::MachineGlobalGate => "machine-global-gate",
    }
}

fn print_path_claim(label: &str, claim: &crate::sync::PathClaim, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claim)?);
    } else {
        println!("{label}: {}", claim.token.get());
        println!("Agent: {}", claim.agent_id);
        println!("Paths:");
        for path in &claim.paths {
            println!("  {}", path.display());
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ClaimTelemetryCliReport<'a> {
    #[serde(flatten)]
    legacy_claim: &'a crate::sync::PathClaim,
    claim: &'a crate::sync::PathClaim,
    warnings: &'a [MegafileClaimWarning],
}

fn print_claim_telemetry_outcome(outcome: &ClaimTelemetryOutcome, json: bool) -> Result<()> {
    if json {
        let report = ClaimTelemetryCliReport {
            legacy_claim: &outcome.claim,
            claim: &outcome.claim,
            warnings: &outcome.warnings,
        };
        print_query_report(&report, true)
    } else {
        print_path_claim("Claim", &outcome.claim, false)?;
        for warning in &outcome.warnings {
            println!("Warning: {warning:#?}");
        }
        Ok(())
    }
}

fn print_claims(claims: &[crate::sync::PathClaim], json: bool, empty_message: &str) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else if claims.is_empty() {
        println!("{empty_message}");
    } else {
        for claim in claims {
            let paths = claim
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("{}\t{}\t{}", claim.token.get(), claim.agent_id, paths);
        }
    }
    Ok(())
}

fn print_claim_statuses(claims: &[ClaimStatusReport], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else if claims.is_empty() {
        println!("No active claims.");
    } else {
        for status in claims {
            let paths = status
                .claim
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{}\t{}\trun={}\tstate={}\t{}",
                status.claim.token.get(),
                status.claim.agent_id,
                status.owner_run_id.as_deref().unwrap_or("<unattributed>"),
                status.owner_run_state.as_str(),
                paths,
            );
        }
    }
    Ok(())
}

fn print_claim_liveness(claims: &[ClaimLivenessReport], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else if claims.is_empty() {
        println!("No active claims.");
    } else {
        for report in claims {
            println!(
                "{}\t{}\t{:?}\theartbeat={}\tstale_after={}\tsupersedes={}",
                report.claim_id,
                report.claim.agent_id,
                report.state,
                report
                    .heartbeat_unix_seconds
                    .map_or_else(|| "<unknown>".to_string(), |value| value.to_string()),
                report
                    .stale_after_seconds
                    .map_or_else(|| "<unknown>".to_string(), |value| value.to_string()),
                report.supersedes.as_deref().unwrap_or("<none>"),
            );
            if let Some(ambiguity) = &report.ambiguity {
                println!("  Ambiguity: {ambiguity}");
            }
        }
    }
    Ok(())
}

fn print_owner_report(report: &OwnerReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if let Some(owner) = &report.owner {
        println!("{}\t{}", report.path.display(), owner);
    } else {
        println!("{}\t<unclaimed>", report.path.display());
    }
    Ok(())
}
