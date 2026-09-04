use std::{
    ffi::OsString,
    fs,
    sync::{Mutex, MutexGuard},
};

use git2::Signature;

use super::*;

static MERGE_LOCAL_GIT_TIMEOUT_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

fn inbox_intake_args(argv: &[&str]) -> IntakeInboxArgs {
    let parsed = Cli::try_parse_from(argv).expect("inbox intake arguments should parse");
    let Command::Inbox(InboxCommand {
        command: InboxSubcommand::Intake(args),
    }) = parsed.command
    else {
        panic!("expected inbox intake command");
    };
    args
}

fn pr_intake_producer_report(success: bool) -> crate::pr_intake::PrIntakeProducerReport {
    crate::pr_intake::PrIntakeProducerReport {
        version: 1,
        repository: Some("github.com/acme/repo".to_string()),
        number: Some(17),
        delivery_id: Some("delivery".to_string()),
        logical_id: Some("logical".to_string()),
        effect_id: Some("effect".to_string()),
        disposition: if success {
            crate::pr_intake::PrIntakeProducerDisposition::Launched
        } else {
            crate::pr_intake::PrIntakeProducerDisposition::Refused
        },
        success,
        intake_report: None,
        refusal: (!success).then(|| {
            crate::pr_intake::PrIntakeProducerRefusalCause::CatalogUnavailable {
                detail: "catalog unavailable".to_string(),
            }
        }),
        grants_merge_permission: false,
        auto_merge_performed: false,
    }
}

#[test]
fn inbox_intake_parses_exact_operator_inputs_and_positive_u64_max() {
    let maximum = u64::MAX.to_string();
    let args = inbox_intake_args(&[
        "maco",
        "inbox",
        "intake",
        "--pr",
        &maximum,
        "--repo",
        "repo",
        "--codex-bin",
        "review-codex",
        "--json",
    ]);

    assert_eq!(args.pr, u64::MAX);
    assert_eq!(args.repo, PathBuf::from("repo"));
    assert_eq!(args.codex_bin, Some(PathBuf::from("review-codex")));
    assert!(args.json);

    let defaults = inbox_intake_args(&["maco", "inbox", "intake", "--pr", "1"]);
    assert_eq!(defaults.repo, PathBuf::from("."));
    assert_eq!(defaults.codex_bin, None);
    assert!(!defaults.json);
}

#[test]
fn inbox_intake_rejects_missing_or_non_positive_u64_values() {
    assert!(Cli::try_parse_from(["maco", "inbox", "intake"]).is_err());
    assert!(Cli::try_parse_from(["maco", "inbox", "intake", "--pr"]).is_err());
    for invalid in ["0", "-1", "not-a-number", "18446744073709551616"] {
        assert!(
            Cli::try_parse_from(["maco", "inbox", "intake", "--pr", invalid]).is_err(),
            "invalid PR number {invalid:?} must be rejected"
        );
    }
}

#[test]
fn inbox_intake_rejects_caller_controlled_trust_fields() {
    for flag in [
        "--github",
        "--permission",
        "--run-id",
        "--max-items",
        "--dry-run",
        "--envelope",
        "--model",
        "--actor",
        "--head",
        "--base",
        "--repository",
        "--provider",
        "--delivery-id",
        "--effect-id",
    ] {
        let argv = ["maco", "inbox", "intake", "--pr", "17", flag, "attacker"];
        assert!(
            Cli::try_parse_from(argv).is_err(),
            "trust-field injection {flag} must be rejected"
        );
    }
}

#[test]
fn inbox_intake_maps_only_fixed_production_options() {
    let args = inbox_intake_args(&[
        "maco",
        "inbox",
        "intake",
        "--pr",
        "17",
        "--repo",
        "repo",
        "--codex-bin",
        "review-codex",
    ]);
    let options = inbox_intake_options(&args).expect("fixed intake options");

    assert_eq!(options.repo, PathBuf::from("repo"));
    assert_eq!(options.run_id.as_str(), PR_INTAKE_PLACEHOLDER_RUN_ID);
    assert!(options.github);
    assert_eq!(
        options.permission_mode,
        Some(InboxPermissionMode::GithubFull)
    );
    assert!(!options.dry_run);
    assert_eq!(options.max_items, None);
    assert_eq!(options.codex_bin, Some(PathBuf::from("review-codex")));
    assert!(options.machine_global.is_none());
}

#[test]
fn inbox_intake_dispatch_seam_delivers_typed_report_before_failure() {
    let args = inbox_intake_args(&["maco", "inbox", "intake", "--pr", "17", "--json"]);
    let expected = pr_intake_producer_report(false);
    let produced = expected.clone();
    let mut observed_options = None;
    let mut delivered = None;

    let error = run_inbox_intake_controller(
        args,
        |options, number| {
            observed_options = Some((options, number));
            produced
        },
        |report, json| {
            delivered = Some((report.clone(), json));
            Ok(())
        },
    )
    .expect_err("unsuccessful producer report must return an error");

    let (options, number) = observed_options.expect("producer invocation");
    assert_eq!(number, 17);
    assert!(options.github);
    assert_eq!(
        options.permission_mode,
        Some(InboxPermissionMode::GithubFull)
    );
    assert_eq!(delivered, Some((expected, true)));
    assert_eq!(error.to_string(), "authenticated PR intake failed");
}

#[test]
fn inbox_intake_dispatch_seam_returns_success_after_typed_delivery() {
    let args = inbox_intake_args(&["maco", "inbox", "intake", "--pr", "17"]);
    let expected = pr_intake_producer_report(true);
    let first_json = serde_json::to_string_pretty(&expected).expect("serialize typed report");
    let second_json = serde_json::to_string_pretty(&expected).expect("repeat serialization");
    assert_eq!(first_json, second_json);
    assert_eq!(
        serde_json::from_str::<crate::pr_intake::PrIntakeProducerReport>(&first_json)
            .expect("round-trip typed report"),
        expected
    );
    let produced = expected.clone();
    let mut delivered = None;

    run_inbox_intake_controller(
        args,
        |_, _| produced,
        |report, json| {
            delivered = Some((report.clone(), json));
            Ok(())
        },
    )
    .expect("successful producer report");

    assert_eq!(delivered, Some((expected, false)));
}

struct MergeLocalGitTimeoutEnvironmentGuard {
    _lock: MutexGuard<'static, ()>,
    previous: Option<OsString>,
}

impl MergeLocalGitTimeoutEnvironmentGuard {
    fn install_unset() -> Self {
        let lock = MERGE_LOCAL_GIT_TIMEOUT_ENVIRONMENT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::env::var_os(merge::LOCAL_GIT_PROCESS_TIMEOUT_ENV);
        // SAFETY: this guard serializes every merge CLI parser test that can observe this
        // process-global variable and restores the exact prior value before releasing the lock.
        unsafe { std::env::remove_var(merge::LOCAL_GIT_PROCESS_TIMEOUT_ENV) };
        Self {
            _lock: lock,
            previous,
        }
    }

    fn set(&self, value: &str) {
        // SAFETY: the guard holds the environment lock for its entire lifetime.
        unsafe { std::env::set_var(merge::LOCAL_GIT_PROCESS_TIMEOUT_ENV, value) };
    }
}

impl Drop for MergeLocalGitTimeoutEnvironmentGuard {
    fn drop(&mut self) {
        // SAFETY: restoration occurs while the guard still holds the environment lock.
        unsafe {
            match &self.previous {
                Some(previous) => std::env::set_var(merge::LOCAL_GIT_PROCESS_TIMEOUT_ENV, previous),
                None => std::env::remove_var(merge::LOCAL_GIT_PROCESS_TIMEOUT_ENV),
            }
        }
    }
}

#[test]
fn artifact_prune_parses_family_age_size_and_unfinalized_grace() {
    let parsed = Cli::try_parse_from([
        "maco",
        "artifacts",
        "prune",
        "--family",
        "program",
        "--repo",
        "repo",
        "--keep",
        "3",
        "--max-age-seconds",
        "86400",
        "--max-total-bytes",
        "1048576",
        "--unfinalized-grace-seconds",
        "3600",
        "--reclaim-unverifiable",
        "--acknowledge-external-writers-stopped",
        "--dry-run",
        "--json",
    ])
    .expect("artifact retention flags should parse");
    let Command::Artifacts(RepositoryArtifactsCommand {
        command: RepositoryArtifactsSubcommand::Prune(args),
    }) = parsed.command
    else {
        panic!("expected repository artifact prune command");
    };
    assert_eq!(args.family, ArtifactRetentionFamilyArg::Program);
    assert_eq!(args.policy.repo, PathBuf::from("repo"));
    assert_eq!(args.policy.keep, 3);
    assert_eq!(args.policy.max_age_seconds, Some(86_400));
    assert_eq!(args.policy.max_total_bytes, Some(1_048_576));
    assert_eq!(args.policy.unfinalized_grace_seconds, 3_600);
    assert!(args.policy.reclaim_unverifiable);
    assert!(args.policy.acknowledge_external_writers_stopped);
    assert!(args.policy.dry_run);
    assert!(args.policy.json);

    for family in [
        "autopilot",
        "consult",
        "inbox",
        "supervise",
        "o2-autopilot",
        "inbox-workspace",
        "program",
    ] {
        Cli::try_parse_from(["maco", "artifacts", "prune", "--family", family])
            .unwrap_or_else(|error| panic!("retention family {family} must parse: {error}"));
    }
}

#[test]
fn worktree_sweep_defaults_to_dry_run_and_requires_workspace() {
    let parsed =
        Cli::try_parse_from(["maco", "worktree", "sweep", "--workspace", "/srv/workspace"])
            .expect("workspace sweep should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Sweep(args),
    }) = parsed.command
    else {
        panic!("expected worktree sweep command");
    };
    assert_eq!(args.workspace, PathBuf::from("/srv/workspace"));
    assert!(!args.apply, "workspace sweep must default to dry-run");
    assert!(!args.keep_targets);
    assert!(!args.targets_only);
    assert_eq!(args.max_age_seconds, None);
    assert_eq!(args.max_count, None);
    assert_eq!(args.max_total_bytes, None);
    assert!(!args.json);

    let error = Cli::try_parse_from(["maco", "worktree", "sweep"])
        .expect_err("workspace sweep must require --workspace");
    assert!(error.to_string().contains("--workspace"));
}

#[test]
fn worktree_sweep_zero_root_formatter_emits_prominent_warning() {
    let warning = worktree_sweep_discovery_warning(WorktreeSweepDiscoveryStatus::NoRootsDiscovered)
        .expect("zero-root sweep warning");
    assert!(warning.starts_with("WARNING:"));
    assert!(warning.contains("not a clean-sweep result"));
    assert_eq!(
        worktree_sweep_discovery_warning(WorktreeSweepDiscoveryStatus::RootsDiscovered),
        None
    );
}

#[test]
fn worktree_sweep_parses_apply_retention_target_and_json_flags() {
    let parsed = Cli::try_parse_from([
        "maco",
        "worktree",
        "sweep",
        "--workspace",
        "workspace",
        "--apply",
        "--max-age-seconds",
        "86400",
        "--max-count",
        "12",
        "--max-total-bytes",
        "10737418240",
        "--keep-targets",
        "--allow-untracked-path",
        "TASK.md",
        "--allow-untracked-path",
        "notes/output.txt",
        "--json",
    ])
    .expect("fully configured workspace sweep should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Sweep(args),
    }) = parsed.command
    else {
        panic!("expected worktree sweep command");
    };
    assert_eq!(args.workspace, PathBuf::from("workspace"));
    assert!(args.apply);
    assert_eq!(args.max_age_seconds, Some(86_400));
    assert_eq!(args.max_count, Some(12));
    assert_eq!(args.max_total_bytes, Some(10_737_418_240));
    assert!(args.keep_targets);
    assert!(!args.targets_only);
    assert_eq!(
        args.allow_untracked_paths,
        vec![PathBuf::from("TASK.md"), PathBuf::from("notes/output.txt")]
    );
    assert!(args.json);
}

#[test]
fn worktree_lifecycle_defaults_all_automation_off_and_dry_run() {
    let parsed = Cli::try_parse_from(["maco", "worktree", "lifecycle"])
        .expect("default lifecycle pass should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Lifecycle(args),
    }) = parsed.command
    else {
        panic!("expected worktree lifecycle command");
    };
    assert_eq!(args.repo, PathBuf::from("."));
    assert!(!args.apply, "lifecycle must default to dry-run");
    assert!(!args.auto_reap_merged);
    assert_eq!(args.trunk_ref, None);
    assert_eq!(args.retry_successor, None);
    assert!(!args.startup_reconciliation);
    assert!(!args.destructive_reconciliation);
    assert!(!args.o2_launch_retention);
    assert_eq!(args.worktree_root, None);
    assert_eq!(args.max_age_seconds, None);
    assert_eq!(args.max_count, None);
    assert_eq!(args.max_total_bytes, None);
    assert!(!args.keep_targets);
    assert!(args.allow_untracked_paths.is_empty());
    assert_eq!(args.artifact_keep, None);
    assert_eq!(args.artifact_max_age_seconds, None);
    assert_eq!(args.artifact_max_total_bytes, None);
    assert_eq!(args.artifact_unfinalized_grace_seconds, None);
    assert!(!args.reclaim_unverifiable);
    assert!(!args.acknowledge_external_writers_stopped);
    assert_eq!(args.machine_global_config, None);
    assert_eq!(args.machine_global_worktree_root_id, None);
    assert_eq!(args.machine_global_correlation, None);
    assert!(!args.json);
}

#[test]
fn worktree_create_retry_supersession_is_explicit_and_apply_is_separate() {
    let parsed = Cli::try_parse_from(["maco", "worktree", "create", "task-r2"])
        .expect("ordinary create should parse unchanged");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Create(args),
    }) = parsed.command
    else {
        panic!("expected worktree create command");
    };
    assert!(!args.supersede_retry_predecessor);
    assert!(!args.apply_retry_supersession);
    assert!(!args.o2_launch_retention_defaults);

    assert!(Cli::try_parse_from([
        "maco",
        "worktree",
        "create",
        "task-r2",
        "--apply-retry-supersession",
    ])
    .is_err());
    let parsed = Cli::try_parse_from([
        "maco",
        "worktree",
        "create",
        "task-r2",
        "--supersede-retry-predecessor",
        "--apply-retry-supersession",
        "--o2-launch-retention-defaults",
    ])
    .expect("explicit retry supersession should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Create(args),
    }) = parsed.command
    else {
        panic!("expected worktree create command");
    };
    assert!(args.supersede_retry_predecessor);
    assert!(args.apply_retry_supersession);
    assert!(args.o2_launch_retention_defaults);
}

#[test]
fn worktree_lifecycle_parses_explicit_automation_and_safety_inputs() {
    let parsed = Cli::try_parse_from([
        "maco",
        "worktree",
        "lifecycle",
        "--repo",
        "repo",
        "--apply",
        "--auto-reap-merged",
        "--trunk-ref",
        "refs/heads/main",
        "--retry-successor",
        "agent-task-r2",
        "--startup-reconciliation",
        "--destructive-reconciliation",
        "--o2-launch-retention",
        "--worktree-root",
        "lanes",
        "--max-age-seconds",
        "86400",
        "--max-count",
        "8",
        "--max-total-bytes",
        "1073741824",
        "--keep-targets",
        "--allow-untracked-path",
        "TASK.md",
        "--artifact-keep",
        "6",
        "--artifact-max-age-seconds",
        "172800",
        "--artifact-max-total-bytes",
        "536870912",
        "--artifact-unfinalized-grace-seconds",
        "604800",
        "--reclaim-unverifiable",
        "--acknowledge-external-writers-stopped",
        "--machine-global-config",
        "machine-global.json",
        "--machine-global-worktree-root-id",
        "worktrees",
        "--machine-global-correlation",
        "startup-65",
        "--json",
    ])
    .expect("explicit lifecycle automation should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Lifecycle(args),
    }) = parsed.command
    else {
        panic!("expected worktree lifecycle command");
    };
    assert_eq!(args.repo, PathBuf::from("repo"));
    assert!(args.apply);
    assert!(args.auto_reap_merged);
    assert_eq!(args.trunk_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!(args.retry_successor.as_deref(), Some("agent-task-r2"));
    assert!(args.startup_reconciliation);
    assert!(args.destructive_reconciliation);
    assert!(args.o2_launch_retention);
    assert_eq!(args.worktree_root, Some(PathBuf::from("lanes")));
    assert_eq!(args.max_age_seconds, Some(86_400));
    assert_eq!(args.max_count, Some(8));
    assert_eq!(args.max_total_bytes, Some(1_073_741_824));
    assert!(args.keep_targets);
    assert_eq!(args.allow_untracked_paths, vec![PathBuf::from("TASK.md")]);
    assert_eq!(args.artifact_keep, Some(6));
    assert_eq!(args.artifact_max_age_seconds, Some(172_800));
    assert_eq!(args.artifact_max_total_bytes, Some(536_870_912));
    assert_eq!(args.artifact_unfinalized_grace_seconds, Some(604_800));
    assert!(args.reclaim_unverifiable);
    assert!(args.acknowledge_external_writers_stopped);
    assert_eq!(
        args.machine_global_config,
        Some(PathBuf::from("machine-global.json"))
    );
    assert_eq!(
        args.machine_global_worktree_root_id.as_deref(),
        Some("worktrees")
    );
    assert_eq!(
        args.machine_global_correlation.as_deref(),
        Some("startup-65")
    );
    assert!(args.json);
}

#[test]
fn worktree_lifecycle_rejects_unscoped_destructive_and_artifact_flags() {
    for args in [
        vec![
            "maco",
            "worktree",
            "lifecycle",
            "--destructive-reconciliation",
        ],
        vec![
            "maco",
            "worktree",
            "lifecycle",
            "--startup-reconciliation",
            "--destructive-reconciliation",
        ],
        vec!["maco", "worktree", "lifecycle", "--artifact-keep", "3"],
        vec!["maco", "worktree", "lifecycle", "--reclaim-unverifiable"],
        vec![
            "maco",
            "worktree",
            "lifecycle",
            "--acknowledge-external-writers-stopped",
        ],
    ] {
        assert!(
            Cli::try_parse_from(args).is_err(),
            "dependent safety flag must fail closed"
        );
    }
}

#[test]
fn existing_worktree_gc_keeps_apply_by_default_contract() {
    let parsed = Cli::try_parse_from(["maco", "worktree", "gc", "--repo", "repo"])
        .expect("existing worktree gc command should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Gc(args),
    }) = parsed.command
    else {
        panic!("expected worktree gc command");
    };
    assert_eq!(args.repo, PathBuf::from("repo"));
    assert!(!args.dry_run, "worktree gc must remain apply-by-default");
    assert!(!args.targets_only);
    assert_eq!(args.max_total_bytes, None);
    assert!(args.allow_untracked_paths.is_empty());
}

#[test]
fn worktree_gc_parses_apparent_byte_retention() {
    let parsed = Cli::try_parse_from(["maco", "worktree", "gc", "--max-total-bytes", "2147483648"])
        .expect("size retention should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Gc(args),
    }) = parsed.command
    else {
        panic!("expected worktree gc command");
    };
    assert_eq!(args.max_total_bytes, Some(2_147_483_648));
}

#[test]
fn worktree_gc_parses_repeatable_exact_untracked_allowlist() {
    let parsed = Cli::try_parse_from([
        "maco",
        "worktree",
        "gc",
        "--allow-untracked-path",
        "TASK.md",
        "--allow-untracked-path",
        "worker/output.json",
    ])
    .expect("repeatable untracked allowlist should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Gc(args),
    }) = parsed.command
    else {
        panic!("expected worktree gc command");
    };
    assert_eq!(
        args.allow_untracked_paths,
        vec![
            PathBuf::from("TASK.md"),
            PathBuf::from("worker/output.json")
        ]
    );
}

#[test]
fn worktree_gc_and_sweep_parse_targets_only_mode() {
    let gc = Cli::try_parse_from(["maco", "worktree", "gc", "--targets-only"])
        .expect("target-only GC should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Gc(gc),
    }) = gc.command
    else {
        panic!("expected worktree gc command");
    };
    assert!(gc.targets_only);

    let sweep = Cli::try_parse_from([
        "maco",
        "worktree",
        "sweep",
        "--workspace",
        "workspace",
        "--targets-only",
    ])
    .expect("target-only sweep should parse");
    let Command::Worktree(WorktreeCommand {
        command: WorktreeSubcommand::Sweep(sweep),
    }) = sweep.command
    else {
        panic!("expected worktree sweep command");
    };
    assert!(sweep.targets_only);
    assert!(!sweep.apply);
}

#[test]
fn worktree_sweep_dry_run_target_summary_counts_would_remove_entries() {
    let dry_run = WorktreeGcReport {
        dry_run: true,
        remove_targets: true,
        targets_only: false,
        max_age_seconds: None,
        max_count: Some(1),
        max_total_bytes: None,
        allowed_untracked_paths: Vec::new(),
        considered_count: 1,
        removed_count: 0,
        protected_count: 0,
        retained_count: 1,
        target_removed_count: 0,
        orphan_removed_count: 0,
        apparent_considered_bytes: 0,
        estimated_reclaimable_bytes: 0,
        estimated_reclaimed_bytes: 0,
        entries: vec![crate::worktree::WorktreeGcEntry {
            name: "retained-lane".to_string(),
            branch: Some("maco/retained-lane".to_string()),
            path: PathBuf::from("/workspace/.maco/worktrees/repo/retained-lane"),
            status: WorktreeGcStatus::Retained,
            reason: WorktreeGcReason::TargetWouldRemove,
            target_path: Some(PathBuf::from(
                "/workspace/.maco/worktrees/repo/retained-lane/target",
            )),
            target_liveness: None,
            apparent_worktree_bytes: None,
            apparent_target_bytes: None,
            untracked_paths: Vec::new(),
            gate_denial: None,
            retention_operation_id: None,
        }],
    };
    assert_eq!(worktree_gc_target_action_count(&dry_run), 1);

    let mut applied = dry_run.clone();
    applied.dry_run = false;
    applied.target_removed_count = 2;
    assert_eq!(worktree_gc_target_action_count(&applied), 2);
}

#[test]
fn worktree_target_liveness_evidence_has_actionable_human_rendering() {
    let evidence = WorktreeTargetLivenessEvidence {
        pid: Some(1234),
        source: WorktreeTargetLivenessSource::DefaultCargoTarget,
        cause: WorktreeTargetLivenessCause::CargoLikeProcessInLane,
    };
    assert_eq!(
        worktree_target_liveness_suffix(Some(&evidence)),
        " target-liveness-pid=1234 target-liveness-source=default-cargo-target \
             target-liveness-cause=cargo-like-process-in-lane"
    );
    assert_eq!(worktree_target_liveness_suffix(None), "");
}

#[test]
fn supervise_run_requires_complete_machine_global_binding() {
    let complete = Cli::try_parse_from([
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ])
    .expect("complete supervise machine-global binding should parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(complete),
    }) = complete.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(
        complete.machine_global_config,
        Some(PathBuf::from("/tmp/maco-machine-global.json"))
    );
    assert_eq!(
        complete.machine_global_runtime_root_id.as_deref(),
        Some("runtime")
    );

    for incomplete in [
        vec!["maco", "supervise", "run", "plan.json"],
        vec![
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
        ],
        vec![
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ],
    ] {
        let error = Cli::try_parse_from(incomplete)
            .expect_err("missing or partial supervise binding must fail closed");
        let rendered = error.to_string();
        assert!(
            rendered.contains("--machine-global-config")
                || rendered.contains("--machine-global-runtime-root-id"),
            "binding refusal must name the missing obligation: {rendered}"
        );
    }
}

#[test]
fn merge_arbitration_is_an_explicit_typed_opt_in() {
    let agent_primary = Cli::try_parse_from([
        "maco",
        "merge",
        "arbitrate",
        "agent-a",
        "primary",
        "--arbiter-id",
        "neutral-review",
        "--run-id",
        "collision-1",
        "--first-claim",
        "src/lib.rs",
        "--validation-command",
        "cargo test",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
        "--approve",
    ])
    .expect("agent-primary arbitration should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Arbitrate(agent_primary),
    }) = agent_primary.command
    else {
        panic!("expected merge arbitrate command");
    };
    assert_eq!(agent_primary.first_side, "agent-a");
    assert_eq!(agent_primary.second_side, "primary");
    assert_eq!(agent_primary.first_claim, vec![PathBuf::from("src/lib.rs")]);
    assert!(agent_primary.second_claim.is_empty());
    assert_eq!(agent_primary.arbiter_id, "neutral-review");
    assert_eq!(agent_primary.validation_command, vec!["cargo test"]);
    assert_eq!(
        agent_primary.machine_global_runtime_root_id,
        "runtime".to_string()
    );
    assert!(agent_primary.approve);

    let agent_agent = Cli::try_parse_from([
        "maco",
        "merge",
        "arbitrate",
        "agent-a",
        "agent-b",
        "--arbiter-id",
        "neutral-review",
        "--run-id",
        "collision-2",
        "--first-claim",
        "src",
        "--second-claim",
        "src/lib.rs",
        "--validation-command",
        "cargo check",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ])
    .expect("agent-agent arbitration should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Arbitrate(agent_agent),
    }) = agent_agent.command
    else {
        panic!("expected merge arbitrate command");
    };
    assert_eq!(agent_agent.first_side, "agent-a");
    assert_eq!(agent_agent.second_side, "agent-b");
    assert_eq!(agent_agent.second_claim, vec![PathBuf::from("src/lib.rs")]);
    assert!(!agent_agent.approve);

    let missing_config = Cli::try_parse_from([
        "maco",
        "merge",
        "arbitrate",
        "agent-a",
        "primary",
        "--arbiter-id",
        "neutral-review",
        "--run-id",
        "collision-missing-config",
        "--first-claim",
        "src",
        "--validation-command",
        "cargo check",
        "--machine-global-runtime-root-id",
        "runtime",
    ])
    .expect_err("merge arbitration must declare a machine-global config");
    assert!(
        missing_config
            .to_string()
            .contains("--machine-global-config"),
        "missing-config refusal must identify the launch obligation"
    );

    let missing_root_id = Cli::try_parse_from([
        "maco",
        "merge",
        "arbitrate",
        "agent-a",
        "primary",
        "--arbiter-id",
        "neutral-review",
        "--run-id",
        "collision-missing-root",
        "--first-claim",
        "src",
        "--validation-command",
        "cargo check",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
    ])
    .expect_err("merge arbitration must declare a machine-global runtime root id");
    assert!(
        missing_root_id
            .to_string()
            .contains("--machine-global-runtime-root-id"),
        "missing-root refusal must identify the launch obligation"
    );

    assert!(Cli::try_parse_from(["maco", "merge", "arbitrate"]).is_err());
    assert!(Cli::try_parse_from([
        "maco",
        "merge",
        "arbitrate",
        "agent-a",
        "primary",
        "--arbiter-id",
        "neutral-review",
        "--run-id",
        "collision-3",
    ])
    .is_err());
}

#[test]
fn existing_merge_preview_and_apply_parsing_remains_separate_from_arbitration() {
    let _environment = MergeLocalGitTimeoutEnvironmentGuard::install_unset();
    let preview = Cli::try_parse_from([
        "maco",
        "merge",
        "preview",
        "agent-a",
        "--claim",
        "src/lib.rs",
        "--require-validation",
        "--json",
    ])
    .expect("existing preview command should still parse");
    assert!(matches!(
        preview.command,
        Command::Merge(MergeCommand {
            command: MergeSubcommand::Preview(_)
        })
    ));

    let apply = Cli::try_parse_from([
        "maco",
        "merge",
        "apply",
        "agent-a",
        "--claim",
        "src/lib.rs",
        "--validation-command",
        "cargo test",
        "--json",
    ])
    .expect("existing apply command should still parse");
    assert!(matches!(
        apply.command,
        Command::Merge(MergeCommand {
            command: MergeSubcommand::Apply(_)
        })
    ));
}

fn parse_merge_local_git_timeout(
    subcommand: &str,
    trailing_args: &[&str],
) -> std::result::Result<u64, clap::Error> {
    let mut args = vec!["maco", "merge", subcommand, "agent-a"];
    args.extend_from_slice(trailing_args);
    let parsed = Cli::try_parse_from(args)?;
    match parsed.command {
        Command::Merge(MergeCommand {
            command: MergeSubcommand::Preview(args),
        }) => Ok(args.local_git.local_git_timeout_seconds),
        Command::Merge(MergeCommand {
            command: MergeSubcommand::Apply(args),
        }) => Ok(args.local_git.local_git_timeout_seconds),
        _ => panic!("expected merge preview or apply command"),
    }
}

#[test]
fn merge_local_git_timeout_flag_and_clap_env_wire_preview_and_apply_with_typed_bounds() {
    let environment = MergeLocalGitTimeoutEnvironmentGuard::install_unset();
    assert_eq!(
        MergeLocalGitTimeoutArgs::default().local_git_timeout_seconds,
        120
    );
    let command = Cli::command();
    let merge = command.find_subcommand("merge").expect("merge subcommand");
    for subcommand in ["preview", "apply"] {
        let timeout = merge
            .find_subcommand(subcommand)
            .expect("merge timeout subcommand")
            .get_arguments()
            .find(|argument| argument.get_id().as_str() == "local_git_timeout_seconds")
            .expect("merge local Git timeout argument");
        assert_eq!(
            timeout.get_env(),
            Some(std::ffi::OsStr::new("MACO_MERGE_LOCAL_GIT_TIMEOUT_SECONDS"))
        );
    }

    let preview = Cli::try_parse_from([
        "maco",
        "merge",
        "preview",
        "agent-a",
        "--local-git-timeout-seconds",
        "900",
    ])
    .expect("merge preview local Git timeout should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Preview(preview),
    }) = preview.command
    else {
        panic!("expected merge preview command");
    };
    assert_eq!(preview.local_git.local_git_timeout_seconds, 900);

    let apply = Cli::try_parse_from([
        "maco",
        "merge",
        "apply",
        "agent-a",
        "--local-git-timeout-seconds",
        "900",
    ])
    .expect("merge apply local Git timeout should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Apply(apply),
    }) = apply.command
    else {
        panic!("expected merge apply command");
    };
    assert_eq!(apply.local_git.local_git_timeout_seconds, 900);

    for subcommand in ["preview", "apply"] {
        for (invalid, expected) in [
            ("0", "between 1 and 86400 seconds"),
            ("86401", "between 1 and 86400 seconds"),
            ("not-a-number", "integer number of seconds"),
        ] {
            let error = Cli::try_parse_from([
                "maco",
                "merge",
                subcommand,
                "agent-a",
                "--local-git-timeout-seconds",
                invalid,
            ])
            .expect_err("invalid local Git timeout must be rejected");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
            assert!(error.to_string().contains(expected));
        }
    }

    environment.set("37");
    for subcommand in ["preview", "apply"] {
        assert_eq!(
            parse_merge_local_git_timeout(subcommand, &[])
                .expect("environment local Git timeout should parse"),
            37
        );
    }

    environment.set("not-a-number");
    for subcommand in ["preview", "apply"] {
        assert_eq!(
            parse_merge_local_git_timeout(subcommand, &["--local-git-timeout-seconds", "901"],)
                .expect("CLI local Git timeout should override the environment"),
            901
        );
    }

    for subcommand in ["preview", "apply"] {
        for (invalid, expected) in [
            ("0", "between 1 and 86400 seconds"),
            ("86401", "between 1 and 86400 seconds"),
            ("not-a-number", "integer number of seconds"),
        ] {
            environment.set(invalid);
            let error = parse_merge_local_git_timeout(subcommand, &[])
                .expect_err("invalid environment local Git timeout must be rejected");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
            assert!(error.to_string().contains(expected));
        }
    }
}

#[test]
fn merge_auto_reap_is_default_off_and_apply_requires_classification() {
    let _environment = MergeLocalGitTimeoutEnvironmentGuard::install_unset();
    let parsed = Cli::try_parse_from(["maco", "merge", "apply", "agent-a"])
        .expect("default merge apply should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Apply(args),
    }) = parsed.command
    else {
        panic!("expected merge apply command");
    };
    assert!(!args.auto_reap_merged);
    assert!(!args.apply_auto_reap);
    assert_eq!(args.trunk_ref, None);

    assert!(
        Cli::try_parse_from(["maco", "merge", "apply", "agent-a", "--apply-auto-reap",]).is_err()
    );

    let parsed = Cli::try_parse_from([
        "maco",
        "merge",
        "apply",
        "agent-a",
        "--auto-reap-merged",
        "--trunk-ref",
        "refs/heads/main",
        "--apply-auto-reap",
    ])
    .expect("explicit merge lifecycle apply should parse");
    let Command::Merge(MergeCommand {
        command: MergeSubcommand::Apply(args),
    }) = parsed.command
    else {
        panic!("expected merge apply command");
    };
    assert!(args.auto_reap_merged);
    assert!(args.apply_auto_reap);
    assert_eq!(args.trunk_ref.as_deref(), Some("refs/heads/main"));
}

#[test]
fn merge_apply_json_delivers_unclaimed_edits_denial_to_integration_controller() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::create_dir_all(repo_path.join("src")).expect("create src");
    fs::write(repo_path.join("README.md"), "# Smoke\n").expect("write README");
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .expect("write lib");
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    let mut index = repo.index().expect("open index");
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    drop(tree);
    drop(repo);

    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create test worktree");
    fs::write(
        worktree.path.join("README.md"),
        "# Smoke\n\nclaimed change\n",
    )
    .expect("edit claimed path");
    fs::write(
        worktree.path.join("src/lib.rs"),
        "pub fn ok() -> bool { false }\n",
    )
    .expect("edit unclaimed path");

    let reviewed_watermark = write_reviewed_merge_preview(
        &repo_path,
        "agent-a",
        vec![PathBuf::from("README.md")],
        MergeForceOptions::default(),
        merge::MergeApplyReviewIntent {
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            ..Default::default()
        },
    );

    let args = MergeApplyArgs {
        agent_id: "agent-a".to_string(),
        repo: repo_path.clone(),
        claim: vec![PathBuf::from("README.md")],
        validation_report: Vec::new(),
        require_validation: false,
        validation_command: Vec::new(),
        block_megafiles: false,
        decomposition_target: None,
        decomposition_run_id: None,
        megafile_thresholds: MegafileThresholdArgs::default(),
        reviewed_watermark: Some(reviewed_watermark),
        local_git: MergeLocalGitTimeoutArgs::default(),
        forces: MergeForceArgs {
            force_dirty_primary: false,
            force_stale_base: false,
            force_unclaimed_edits: false,
            force_validation_failures: false,
            force_apply_conflicts: false,
        },
        auto_reap_merged: true,
        trunk_ref: Some("refs/heads/main".to_string()),
        apply_auto_reap: false,
        json: true,
    };
    let mut delivered = None;
    let error = run_merge_apply_controller(
        args,
        |report, json| {
            assert!(json);
            delivered = Some(report.clone());
            Ok(())
        },
        |_refusal, _json| panic!("exact reviewed blocked preview must not be refused"),
    )
    .expect_err("unclaimed merge edit must remain blocked");

    assert!(error.to_string().contains("unclaimed_edits"));
    let report = delivered.expect("integration controller must receive the blocked report");
    assert_eq!(report.status, merge::MergeApplyReportStatus::Blocked);
    assert!(!report.applied);
    assert!(
        report.lifecycle.is_none(),
        "blocked merge must not run its lifecycle hook"
    );
    let denial = report
        .gate_denials
        .iter()
        .find(|denial| {
            matches!(
                denial.reason,
                crate::gate_denial::GateDenialReason::MergeRemediation {
                    blocker: merge::ApplyBlocker::UnclaimedEdits
                }
            )
        })
        .expect("delivered unclaimed-edits merge denial");
    assert_eq!(
        denial.route,
        crate::gate_denial::GateDenialRoute::IntegrationController
    );
    assert_eq!(denial.context.owner, "agent-a");
    assert_eq!(
        denial.context.source,
        crate::gate_denial::GateCheckSource::MergeScope
    );
    assert_eq!(denial.context.paths, vec![PathBuf::from("src/lib.rs")]);
    assert_eq!(
        denial.next_safe_operation,
        crate::gate_denial::NextSafeOperation::RemediateUnclaimedMergeEdits
    );
    let correlation_id = denial.correction_correlation_id.as_str();
    assert!(!correlation_id.is_empty());
    assert!(correlation_id.len() <= 128);
    assert!(correlation_id.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
    }));
}

#[test]
fn merge_apply_auto_reap_waits_for_trunk_then_reaps_on_finalization_rerun() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Before\n").expect("write README");
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    let mut index = repo.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    drop(tree);
    drop(repo);

    let worktree = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-merge-hook".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create test worktree");
    fs::write(worktree.path.join("README.md"), "# After\n").expect("edit agent README");
    let agent_repo = crate::git_repository::open(&worktree.path).expect("open agent repository");
    let mut index = agent_repo.index().expect("open agent index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage agent README");
    index.write().expect("write agent index");
    let tree_id = index.write_tree().expect("write agent tree");
    let tree = agent_repo.find_tree(tree_id).expect("find agent tree");
    let parent = agent_repo
        .head()
        .expect("agent HEAD")
        .peel_to_commit()
        .expect("agent parent commit");
    agent_repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "agent change",
            &tree,
            &[&parent],
        )
        .expect("commit agent change");
    drop(parent);
    drop(tree);
    drop(agent_repo);

    let reviewed_watermark = write_reviewed_merge_preview(
        &repo_path,
        "agent-merge-hook",
        vec![PathBuf::from("README.md")],
        MergeForceOptions::default(),
        merge::MergeApplyReviewIntent {
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            ..Default::default()
        },
    );

    let args = MergeApplyArgs {
        agent_id: "agent-merge-hook".to_string(),
        repo: repo_path.clone(),
        claim: vec![PathBuf::from("README.md")],
        validation_report: Vec::new(),
        require_validation: false,
        validation_command: Vec::new(),
        block_megafiles: false,
        decomposition_target: None,
        decomposition_run_id: None,
        megafile_thresholds: MegafileThresholdArgs::default(),
        reviewed_watermark: Some(reviewed_watermark),
        local_git: MergeLocalGitTimeoutArgs::default(),
        forces: MergeForceArgs {
            force_dirty_primary: false,
            force_stale_base: false,
            force_unclaimed_edits: false,
            force_validation_failures: false,
            force_apply_conflicts: false,
        },
        auto_reap_merged: true,
        trunk_ref: Some("refs/heads/main".to_string()),
        apply_auto_reap: false,
        json: true,
    };
    let mut delivered = None;
    run_merge_apply_controller(
        args,
        |report, json| {
            assert!(json);
            delivered = Some(report.clone());
            Ok(())
        },
        |_refusal, _json| panic!("exact reviewed apply must not be refused"),
    )
    .expect("merge and lifecycle classification should succeed");

    let report = delivered.expect("merge report");
    assert_eq!(report.status, merge::MergeApplyReportStatus::Applied);
    assert!(report.applied);
    let lifecycle = report.lifecycle.expect("opt-in lifecycle report");
    assert!(lifecycle.enabled);
    assert!(lifecycle.dry_run);
    let gc = lifecycle
        .worktree_gc
        .expect("targeted worktree classification");
    assert_eq!(gc.considered_count, 1);
    assert_eq!(gc.removed_count, 0);
    assert_eq!(gc.entries.len(), 1);
    assert_eq!(gc.entries[0].reason, WorktreeGcReason::UnmergedBranch);
    assert!(worktree.path.exists(), "unmerged lane must remain present");

    let primary = crate::git_repository::open(&repo_path).expect("reopen primary");
    let lane_oid = primary
        .find_branch("maco/agent-merge-hook", git2::BranchType::Local)
        .expect("lane branch")
        .get()
        .target()
        .expect("lane branch target");
    primary
        .reference("refs/heads/main", lane_oid, true, "test merge finalization")
        .expect("advance trunk to lane commit");
    let lane_commit = primary.find_commit(lane_oid).expect("lane commit");
    primary
        .reset(lane_commit.as_object(), git2::ResetType::Hard, None)
        .expect("refresh primary worktree and index");
    drop(lane_commit);
    drop(primary);

    let reviewed_watermark = write_reviewed_merge_preview(
        &repo_path,
        "agent-merge-hook",
        vec![PathBuf::from("README.md")],
        MergeForceOptions {
            allow_stale_base: true,
            ..MergeForceOptions::default()
        },
        merge::MergeApplyReviewIntent {
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            apply_auto_reap: true,
            ..Default::default()
        },
    );

    let args = MergeApplyArgs {
        agent_id: "agent-merge-hook".to_string(),
        repo: repo_path,
        claim: vec![PathBuf::from("README.md")],
        validation_report: Vec::new(),
        require_validation: false,
        validation_command: Vec::new(),
        block_megafiles: false,
        decomposition_target: None,
        decomposition_run_id: None,
        megafile_thresholds: MegafileThresholdArgs::default(),
        reviewed_watermark: Some(reviewed_watermark),
        local_git: MergeLocalGitTimeoutArgs::default(),
        forces: MergeForceArgs {
            force_dirty_primary: false,
            force_stale_base: true,
            force_unclaimed_edits: false,
            force_validation_failures: false,
            force_apply_conflicts: false,
        },
        auto_reap_merged: true,
        trunk_ref: Some("refs/heads/main".to_string()),
        apply_auto_reap: true,
        json: true,
    };
    let mut finalized = None;
    run_merge_apply_controller(
        args,
        |report, json| {
            assert!(json);
            finalized = Some(report.clone());
            Ok(())
        },
        |_refusal, _json| panic!("exact reviewed finalization must not be refused"),
    )
    .expect("fully merged finalization rerun should reap the lane");
    let finalized = finalized.expect("finalized report");
    let lifecycle = finalized.lifecycle.expect("final lifecycle report");
    let gc = lifecycle.worktree_gc.expect("final GC report");
    assert_eq!(gc.removed_count, 1, "{gc:#?}");
    assert_eq!(gc.entries[0].status, WorktreeGcStatus::Removed);
    assert_eq!(gc.entries[0].reason, WorktreeGcReason::FinishedBranch);
    assert!(!worktree.path.exists());
}

fn write_reviewed_merge_preview(
    repo_path: &Path,
    agent_id: &str,
    claims: Vec<PathBuf>,
    forces: MergeForceOptions,
    review_intent: merge::MergeApplyReviewIntent,
) -> PathBuf {
    let require_validation = review_intent.require_validation_after_candidate;
    let preview = preview_merge_from_args(
        repo_path.to_path_buf(),
        agent_id.to_string(),
        claims,
        Vec::new(),
        forces,
        require_validation,
        review_intent,
        MegafileMergePolicy::default(),
        merge::MergeLocalGitOptions::default(),
    )
    .expect("capture reviewed merge preview");
    let watermark = merge::MergePreviewFreshnessWatermark::capture_from_preview(&preview)
        .expect("capture reviewed merge watermark");
    let mut value = serde_json::to_value(preview).expect("serialize reviewed merge preview");
    value.as_object_mut().expect("preview object").insert(
        "freshness_watermark".to_string(),
        serde_json::to_value(watermark).expect("serialize reviewed watermark"),
    );
    let path = repo_path
        .join(".git")
        .join(format!("reviewed-preview-{agent_id}.json"));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("encode reviewed preview"),
    )
    .expect("write reviewed preview");
    path
}

fn init_committed_repo(repo_path: &Path) -> git2::Signature<'static> {
    WorktreeManager::init_repository(repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Before\n").expect("write README");
    let repo = crate::git_repository::open(repo_path).expect("open repository");
    let mut index = repo.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    signature
}

fn commit_worktree_file(
    worktree: &Path,
    relative: &str,
    contents: &str,
    message: &str,
    signature: &Signature<'_>,
) {
    fs::write(worktree.join(relative), contents).expect("write worktree file");
    let repo = crate::git_repository::open(worktree).expect("open worktree");
    let mut index = repo.index().expect("open worktree index");
    index
        .add_path(Path::new(relative))
        .expect("stage worktree file");
    index.write().expect("write worktree index");
    let tree_id = index.write_tree().expect("write worktree tree");
    let tree = repo.find_tree(tree_id).expect("find worktree tree");
    let parent = repo
        .head()
        .expect("worktree HEAD")
        .peel_to_commit()
        .expect("worktree parent");
    repo.commit(
        Some("HEAD"),
        signature,
        signature,
        message,
        &tree,
        &[&parent],
    )
    .expect("commit worktree file");
}

fn create_test_lane(repo_path: &Path, agent_id: &str) -> WorktreeRecord {
    WorktreeManager::new(repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: agent_id.to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create test worktree")
}

#[test]
fn completion_reap_skips_when_no_managed_worktrees_exist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    init_committed_repo(&repo_path);
    assert!(reap_merged_managed_worktrees(&repo_path)
        .expect("reap should succeed")
        .is_none());
    assert!(
        !repo_path.join(".git/maco").exists(),
        "completion reap must not create MACO state in a repository that never used managed worktrees"
    );
}

#[test]
fn completion_reap_removes_merged_and_preserves_unmerged_and_dirty_worktrees() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let signature = init_committed_repo(&repo_path);
    let merged = create_test_lane(&repo_path, "agent-merged");
    let unmerged = create_test_lane(&repo_path, "agent-unmerged");
    let dirty = create_test_lane(&repo_path, "agent-dirty");

    commit_worktree_file(
        &merged.path,
        "merged.txt",
        "merged\n",
        "merged work",
        &signature,
    );
    commit_worktree_file(
        &unmerged.path,
        "unmerged.txt",
        "unmerged\n",
        "unmerged work",
        &signature,
    );
    fs::write(dirty.path.join("README.md"), "# dirty local work\n").expect("dirty worktree");

    let primary = crate::git_repository::open(&repo_path).expect("reopen primary");
    let lane_oid = primary
        .find_branch("maco/agent-merged", git2::BranchType::Local)
        .expect("merged lane branch")
        .get()
        .target()
        .expect("merged lane target");
    primary
        .reference("refs/heads/main", lane_oid, true, "absorb merged lane")
        .expect("advance trunk to merged lane");
    let lane_commit = primary.find_commit(lane_oid).expect("merged lane commit");
    primary
        .reset(lane_commit.as_object(), git2::ResetType::Hard, None)
        .expect("refresh primary after absorbing merged lane");
    drop(lane_commit);
    drop(primary);

    let report = reap_merged_managed_worktrees(&repo_path)
        .expect("reap leak scenarios")
        .expect("managed lanes should enable lifecycle");
    let gc = report
        .worktree_gc
        .as_ref()
        .expect("merged auto-reap should run GC");
    assert_eq!(gc.considered_count, 3, "{gc:#?}");
    assert_eq!(gc.removed_count, 1, "{gc:#?}");
    assert_eq!(gc.protected_count, 1, "{gc:#?}");
    assert_eq!(gc.retained_count, 1, "{gc:#?}");

    let merged_entry = gc
        .entries
        .iter()
        .find(|entry| entry.name == "agent-merged")
        .expect("merged entry");
    assert_eq!(merged_entry.status, WorktreeGcStatus::Removed);
    assert_eq!(merged_entry.reason, WorktreeGcReason::FinishedBranch);
    assert!(!merged.path.exists(), "merged worktree must be reclaimed");

    let unmerged_entry = gc
        .entries
        .iter()
        .find(|entry| entry.name == "agent-unmerged")
        .expect("unmerged entry");
    assert_eq!(unmerged_entry.status, WorktreeGcStatus::Retained);
    assert_eq!(unmerged_entry.reason, WorktreeGcReason::UnmergedBranch);
    assert!(
        unmerged.path.exists(),
        "unmerged work must not be destroyed without opt-in"
    );

    let dirty_entry = gc
        .entries
        .iter()
        .find(|entry| entry.name == "agent-dirty")
        .expect("dirty entry");
    assert_eq!(dirty_entry.status, WorktreeGcStatus::Protected);
    assert_eq!(dirty_entry.reason, WorktreeGcReason::Dirty);
    assert!(
        dirty.path.exists(),
        "dirty worktree must remain until cleaned or explicitly forced"
    );

    let primary = crate::git_repository::open(&repo_path).expect("reopen after reap");
    assert!(
        primary
            .find_branch("maco/agent-merged", git2::BranchType::Local)
            .is_ok(),
        "GC retains merged branch refs; unpinning the worktree is what makes later deletion possible"
    );
    assert!(primary
        .find_branch("maco/agent-unmerged", git2::BranchType::Local)
        .is_ok());
    assert!(primary
        .find_branch("maco/agent-dirty", git2::BranchType::Local)
        .is_ok());
}

#[test]
fn primary_arbitration_side_rejects_agent_claims_before_execution() {
    let error = arbitration_side_from_cli(
        "primary".to_string(),
        vec![PathBuf::from("src/lib.rs")],
        "second",
    )
    .expect_err("primary side must not accept an agent claim");
    assert!(error
        .to_string()
        .contains("--second-claim is not applicable"));
}

#[test]
fn supervise_plan_requires_exactly_one_positional_or_goal_source() {
    let positional =
        Cli::try_parse_from(["maco", "supervise", "plan", "task.txt", "--repo", "repo"])
            .expect("positional task source should parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Plan(positional),
    }) = positional.command
    else {
        panic!("expected supervise plan command");
    };
    assert_eq!(positional.task_file, Some(PathBuf::from("task.txt")));
    assert_eq!(positional.from_goal, None);
    assert_eq!(positional.repo, PathBuf::from("repo"));

    let from_goal = Cli::try_parse_from(["maco", "supervise", "plan", "--from-goal", "goal.md"])
        .expect("--from-goal source should parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Plan(from_goal),
    }) = from_goal.command
    else {
        panic!("expected supervise plan command");
    };
    assert_eq!(from_goal.task_file, None);
    assert_eq!(from_goal.from_goal, Some(PathBuf::from("goal.md")));

    assert!(Cli::try_parse_from(["maco", "supervise", "plan"]).is_err());
    assert!(Cli::try_parse_from([
        "maco",
        "supervise",
        "plan",
        "task.txt",
        "--from-goal",
        "goal.md",
    ])
    .is_err());
}

#[test]
fn supervise_run_requires_exactly_one_plan_or_goal_source() {
    let retention = [
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ];
    let mut positional = vec!["maco", "supervise", "run", "plan.json"];
    positional.extend(retention);
    let positional = Cli::try_parse_from(positional).expect("positional source must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = positional.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(args.supervisor_plan, Some(PathBuf::from("plan.json")));
    assert_eq!(args.from_goal, None);

    let mut from_goal = vec!["maco", "supervise", "run", "--from-goal", "goal.md"];
    from_goal.extend(retention);
    let from_goal = Cli::try_parse_from(from_goal).expect("goal source must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = from_goal.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(args.supervisor_plan, None);
    assert_eq!(args.from_goal, Some(PathBuf::from("goal.md")));

    let mut missing = vec!["maco", "supervise", "run"];
    missing.extend(retention);
    assert!(Cli::try_parse_from(missing).is_err());
    let mut conflicting = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--from-goal",
        "goal.md",
    ];
    conflicting.extend(retention);
    assert!(Cli::try_parse_from(conflicting).is_err());
}

#[test]
fn supervise_admission_flags_parse_and_reject_zero() {
    let parsed = Cli::try_parse_from([
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--max-concurrent-children",
        "12",
        "--provider-inflight-limit",
        "9",
        "--host-memory-available-mib",
        "8192",
        "--host-memory-per-child-mib",
        "1024",
        "--host-fd-available",
        "640",
        "--host-fds-per-child",
        "128",
        "--host-disk-available-mib",
        "9000",
        "--host-disk-per-child-mib",
        "1000",
        "--host-fallback-children",
        "2",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ])
    .expect("positive admission flags parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = parsed.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(args.max_concurrent_children.configured_limit(), Some(12));
    assert_eq!(args.provider_inflight_limit, Some(9));
    assert_eq!(args.host_memory_available_mib, Some(8_192));
    assert_eq!(args.host_fd_available, Some(640));
    assert_eq!(args.host_disk_available_mib, Some(9_000));

    for flag in [
        "--provider-inflight-limit",
        "--host-memory-available-mib",
        "--host-memory-per-child-mib",
        "--host-fd-available",
        "--host-fds-per-child",
        "--host-disk-available-mib",
        "--host-disk-per-child-mib",
        "--host-fallback-children",
    ] {
        assert!(Cli::try_parse_from([
            "maco",
            "supervise",
            "run",
            "plan.json",
            flag,
            "0",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .is_err());
    }
}

#[test]
fn supervise_parses_repository_local_quota_config() {
    let mut argv = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--quota-config",
        "config/operator-quota.json",
    ];
    argv.extend([
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ]);
    let parsed = Cli::try_parse_from(argv).expect("quota config must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = parsed.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(
        args.quota_config,
        Some(PathBuf::from("config/operator-quota.json"))
    );
}

#[test]
fn retired_autopilot_plan_and_run_capture_legacy_argv_and_fail_before_side_effects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing_input = temp.path().join("missing-input.json");
    let untouched_repo = temp.path().join("untouched-repo");
    let missing_runtime = temp.path().join("missing-codex");

    for subcommand in ["plan", "run"] {
        let legacy_args = vec![
            missing_input.as_os_str().to_owned(),
            OsString::from("--from-goal"),
            OsString::from("missing-goal.md"),
            OsString::from("--run-id"),
            OsString::from("../invalid-run-id"),
            OsString::from("--codex-bin"),
            missing_runtime.as_os_str().to_owned(),
            OsString::from("--repo"),
            untouched_repo.as_os_str().to_owned(),
        ];
        let mut argv = vec![
            OsString::from("maco"),
            OsString::from("autopilot"),
            OsString::from(subcommand),
        ];
        argv.extend(legacy_args.clone());

        let parsed = Cli::try_parse_from(argv).expect("legacy autopilot argv must parse opaquely");
        let Command::Autopilot(command) = parsed.command else {
            panic!("expected retired autopilot command");
        };
        let captured = match &command.command {
            AutopilotSubcommand::Plan(args) | AutopilotSubcommand::Run(args) => &args._legacy_args,
            _ => panic!("expected retired autopilot plan/run command"),
        };
        assert_eq!(captured, &legacy_args);

        let error = command
            .run()
            .expect_err("retired autopilot execution must fail");
        assert_eq!(error.to_string(), RETIRED_AUTOPILOT_EXECUTION_MESSAGE);
        assert!(
            !untouched_repo.exists(),
            "retired autopilot must fail before writing artifacts"
        );
    }
}

#[test]
fn supervise_budget_flags_parse_validate_and_bind_hard_limits() {
    let retention = [
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ];
    let mut argv = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--max-tokens",
        "12000",
        "--max-cost-usd",
        "1.25",
        "--max-duration-seconds",
        "900",
    ];
    argv.extend(retention);
    let parsed = Cli::try_parse_from(argv).expect("budget flags must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = parsed.command
    else {
        panic!("expected supervise run command");
    };
    let budget = args.budget;
    assert_eq!(budget.limits().hard_tokens, Some(12_000));
    assert_eq!(budget.limits().hard_cost_usd, Some(1.25));
    assert_eq!(budget.max_duration_seconds(), Some(900));
    assert!(budget.rolling_quota().is_none());

    for (flag, value) in [
        ("--max-tokens", "0"),
        ("--max-cost-usd", "0"),
        ("--max-cost-usd", "NaN"),
        ("--max-cost-usd", "inf"),
        ("--max-duration-seconds", "0"),
    ] {
        let mut invalid = vec!["maco", "supervise", "run", "plan.json", flag, value];
        invalid.extend(retention);
        assert!(
            Cli::try_parse_from(invalid).is_err(),
            "supervise accepted nonsense {flag}={value}"
        );
    }

    let mut aliases = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--max-total-tokens",
        "2",
        "--max-total-cost-usd",
        "0.5",
        "--max-total-duration-seconds",
        "3",
    ];
    aliases.extend(retention);
    assert!(Cli::try_parse_from(aliases).is_ok());

    let mut argv = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--max-rolling-tokens",
        "50000",
        "--max-rolling-cost-usd",
        "12.5",
        "--rolling-window-seconds",
        "3600",
    ];
    argv.extend(retention);
    let parsed = Cli::try_parse_from(argv).expect("rolling budget flags must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = parsed.command
    else {
        panic!("expected supervise run command");
    };
    let rolling = args
        .budget
        .rolling_quota()
        .expect("rolling quota must bind from CLI flags");
    assert_eq!(rolling.max_tokens, Some(50_000));
    assert_eq!(rolling.max_cost_usd, Some(12.5));
    assert_eq!(rolling.window_seconds, 3_600);

    for (flag, value) in [
        ("--max-rolling-tokens", "0"),
        ("--max-rolling-cost-usd", "0"),
        ("--max-rolling-cost-usd", "NaN"),
        ("--rolling-window-seconds", "0"),
    ] {
        let mut invalid = vec!["maco", "supervise", "run", "plan.json", flag, value];
        invalid.extend(retention);
        assert!(
            Cli::try_parse_from(invalid).is_err(),
            "supervise accepted nonsense {flag}={value}"
        );
    }
}

#[test]
fn supervise_run_accepts_only_canonical_parent_nodes() {
    let retention = [
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ];
    let mut valid = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--parent-node",
        "driver-root",
    ];
    valid.extend(retention);
    let parsed = Cli::try_parse_from(valid).expect("parent node must parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Run(args),
    }) = parsed.command
    else {
        panic!("expected supervise run command");
    };
    assert_eq!(args.parent_node.as_deref(), Some("driver-root"));

    let mut invalid = vec![
        "maco",
        "supervise",
        "run",
        "plan.json",
        "--parent-node",
        "invalid/parent",
    ];
    invalid.extend(retention);
    assert!(Cli::try_parse_from(invalid).is_err());
}

#[test]
fn supervise_resume_accepts_run_identity_and_query_output_options() {
    let parsed = Cli::try_parse_from([
        "maco",
        "supervise",
        "resume",
        "interrupted-run",
        "--repo",
        "repo",
        "--json",
    ])
    .expect("supervise resume should parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Resume(resume),
    }) = parsed.command
    else {
        panic!("expected supervise resume command");
    };
    assert_eq!(resume.run_id, "interrupted-run");
    assert_eq!(resume.repo, PathBuf::from("repo"));
    assert!(resume.json);
}

#[test]
fn supervise_reaudit_requires_authenticated_source_scope_and_cleanup_binding() {
    let parsed = Cli::try_parse_from([
        "maco",
        "supervise",
        "re-audit",
        "source-run",
        "child-a",
        "--run-id",
        "destination-run",
        "--repo",
        "repo",
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
        "--json",
    ])
    .expect("complete supervise re-audit command should parse");
    let Command::Supervise(SuperviseCommand {
        command: SuperviseSubcommand::Reaudit(reaudit),
    }) = parsed.command
    else {
        panic!("expected supervise re-audit command");
    };
    assert_eq!(reaudit.source_run_id, "source-run");
    assert_eq!(reaudit.assignment_id, "child-a");
    assert_eq!(reaudit.run_id.as_deref(), Some("destination-run"));
    assert_eq!(reaudit.repo, PathBuf::from("repo"));
    assert_eq!(
        reaudit.machine_global_config,
        PathBuf::from("/tmp/maco-machine-global.json")
    );
    assert_eq!(reaudit.machine_global_runtime_root_id, "runtime");
    assert!(reaudit.json);

    assert!(
        Cli::try_parse_from(["maco", "supervise", "re-audit", "source-run", "child-a",]).is_err()
    );
}
