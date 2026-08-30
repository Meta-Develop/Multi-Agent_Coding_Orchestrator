mod support;

use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use multi_agent_coding_orchestrator::{orchestrator::RunId, sync_store::SyncStore};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::{collections::BTreeMap, path::PathBuf};
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_maco");
const MACHINE_GLOBAL_CONFIG_ENV: &str = "MACO_MACHINE_GLOBAL_CONFIG";
const MACHINE_GLOBAL_RUNTIME_ROOT_ID_ENV: &str = "MACO_MACHINE_GLOBAL_RUNTIME_ROOT_ID";

fn cli_without_machine_global_bindings() -> Command {
    let mut command = Command::new(BIN);
    command
        .env_remove(MACHINE_GLOBAL_CONFIG_ENV)
        .env_remove(MACHINE_GLOBAL_RUNTIME_ROOT_ID_ENV)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME");
    command
}

fn assert_literal_route_attempts_safe_defaults(output: &Output) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to resolve default machine-global binding"),
        "{stderr}"
    );
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
    assert!(!stderr.contains("unexpected argument"), "{stderr}");
}

#[test]
fn cli_literal_entrypoint_routes_quoted_literal_and_option_shaped_content() -> Result<()> {
    let literal = cli_without_machine_global_bindings()
        .args([
            r#"preserve "double quoted" and 'single quoted' text"#,
            "--without-treating-this-as-an-option",
        ])
        .output()
        .context("route quoted bare literal instruction")?;
    assert_literal_route_attempts_safe_defaults(&literal);
    Ok(())
}

#[test]
fn cli_literal_entrypoint_preserves_explicit_subcommands_and_top_level_help_and_version(
) -> Result<()> {
    for subcommand in [
        "init",
        "repo",
        "state",
        "worktree",
        "merge",
        "live",
        "pr",
        "issue",
        "sync",
        "machine-global",
        "coord",
        "orchestrate",
        "supervise",
        "consult",
        "inbox",
        "scope",
        "autopilot",
        "artifacts",
        "review",
        "agent",
        "agents",
        "llm",
        "evaluation",
        "eval-harness",
        "optimizer",
    ] {
        let explicit = cli_without_machine_global_bindings()
            .args([subcommand, "--help"])
            .output()
            .with_context(|| format!("run explicit {subcommand} help"))?;
        assert!(explicit.status.success());
        let explicit_stdout =
            String::from_utf8(explicit.stdout).context("decode explicit subcommand help")?;
        assert!(
            explicit_stdout.contains(&format!("Usage: maco {subcommand}")),
            "{explicit_stdout}"
        );
    }

    let help = cli_without_machine_global_bindings()
        .arg("--help")
        .output()
        .context("run top-level help")?;
    assert!(help.status.success());
    let help_stdout = String::from_utf8(help.stdout).context("decode top-level help")?;
    assert!(
        help_stdout.contains("Usage: maco <COMMAND>"),
        "{help_stdout}"
    );

    let version = cli_without_machine_global_bindings()
        .arg("--version")
        .output()
        .context("run top-level version")?;
    assert!(version.status.success());
    let version_stdout = String::from_utf8(version.stdout).context("decode top-level version")?;
    assert_eq!(
        version_stdout.trim(),
        format!("maco {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn cli_literal_entrypoint_double_dash_forces_subcommand_shaped_literal_but_not_top_level_option(
) -> Result<()> {
    let escaped = cli_without_machine_global_bindings()
        .args([
            "--",
            "repo",
            r#"is "quoted" instruction text"#,
            "--option-shaped-content",
        ])
        .output()
        .context("force subcommand-shaped literal instruction")?;
    assert_literal_route_attempts_safe_defaults(&escaped);

    let option = cli_without_machine_global_bindings()
        .arg("--not-a-maco-option")
        .output()
        .context("preserve option-shaped top-level argument")?;
    assert!(!option.status.success());
    let option_stderr = String::from_utf8_lossy(&option.stderr);
    assert!(option_stderr.contains("unexpected argument '--not-a-maco-option'"));
    assert!(!option_stderr.contains("default machine-global binding"));
    Ok(())
}

#[test]
fn cli_explicit_supervise_run_still_requires_machine_global_operands() -> Result<()> {
    let output = cli_without_machine_global_bindings()
        .args(["supervise", "run", "plan.json"])
        .output()
        .context("run explicit supervise without required machine-global operands")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--machine-global-config"), "{stderr}");
    assert!(
        stderr.contains("--machine-global-runtime-root-id"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("default machine-global binding"),
        "{stderr}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_private_runtime_root() -> Option<PathBuf> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let metadata = fs::symlink_metadata(&runtime).ok()?;
    (metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == uid
        && metadata.permissions().mode() & 0o077 == 0)
        .then_some(runtime)
}

#[cfg(target_os = "linux")]
fn write_literal_default_config(
    config: &Path,
    state_root: &Path,
    roots: &[(&str, &Path)],
) -> Result<()> {
    let parent = config.parent().context("default config parent")?;
    fs::create_dir_all(parent).context("create default config parent")?;
    fs::write(
        config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": roots
                .iter()
                .map(|(id, path)| serde_json::json!({
                    "id": id,
                    "path": path,
                    "protected_paths": [],
                    "quarantine_grace_seconds": 60
                }))
                .collect::<Vec<_>>()
        }))?,
    )
    .context("write default machine-global config")?;
    fs::set_permissions(config, fs::Permissions::from_mode(0o600))
        .context("secure default machine-global config")
}

#[cfg(target_os = "linux")]
fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure {}", path.display()))
}

#[cfg(target_os = "linux")]
fn run_literal_with_xdg_config(cwd: &Path, config_home: &Path) -> Result<Output> {
    cli_without_machine_global_bindings()
        .arg("resolve reviewed literal defaults")
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .context("run routed literal with XDG defaults")
}

#[cfg(target_os = "linux")]
fn assert_default_refusal(output: &Output, expected: &str) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to resolve default machine-global binding"),
        "{stderr}"
    );
    assert!(stderr.contains(expected), "{stderr}");
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn cli_literal_defaults_resolve_from_physical_xdg_and_home_outside_any_repository() -> Result<()> {
    let Some(runtime_root) = current_private_runtime_root() else {
        return Ok(());
    };
    let temp = TempDir::new().context("tempdir")?;

    let xdg = temp.path().join("xdg");
    let xdg_state = temp.path().join("xdg-state");
    create_private_dir(&xdg_state)?;
    write_literal_default_config(
        &xdg.join("maco/machine-global.json"),
        &xdg_state,
        &[("runtime", &runtime_root)],
    )?;
    let xdg_output = run_literal_with_xdg_config(temp.path(), &xdg)?;
    assert!(!xdg_output.status.success());
    let xdg_stderr = String::from_utf8_lossy(&xdg_output.stderr);
    assert!(xdg_stderr.contains("repository"), "{xdg_stderr}");
    assert!(
        !xdg_stderr.contains("default machine-global binding"),
        "{xdg_stderr}"
    );

    let home = temp.path().join("home");
    let home_state = temp.path().join("home-state");
    create_private_dir(&home_state)?;
    write_literal_default_config(
        &home.join(".config/maco/machine-global.json"),
        &home_state,
        &[("runtime", &runtime_root)],
    )?;
    let home_output = cli_without_machine_global_bindings()
        .arg("resolve reviewed HOME fallback")
        .current_dir(temp.path())
        .env("HOME", &home)
        .output()
        .context("run routed literal with HOME defaults")?;
    assert!(!home_output.status.success());
    let home_stderr = String::from_utf8_lossy(&home_output.stderr);
    assert!(home_stderr.contains("repository"), "{home_stderr}");
    assert!(
        !home_stderr.contains("default machine-global binding"),
        "{home_stderr}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn cli_concurrent_bare_invocations_reserve_distinct_generated_run_ids() -> Result<()> {
    let Some(runtime_root) = current_private_runtime_root() else {
        return Ok(());
    };
    let temp = TempDir::new().context("tempdir")?;
    let repo_paths = (0..2)
        .map(|index| {
            let root = temp.path().join(format!("repo-{index}"));
            fs::create_dir(&root)
                .with_context(|| format!("create concurrent repo root {index}"))?;
            create_committed_repo(&root)
        })
        .collect::<Result<Vec<_>>>()?;
    let xdg = temp.path().join("xdg");
    let state_root = temp.path().join("state");
    create_private_dir(&state_root)?;
    write_literal_default_config(
        &xdg.join("maco/machine-global.json"),
        &state_root,
        &[("runtime", &runtime_root)],
    )?;

    let children = repo_paths
        .iter()
        .enumerate()
        .map(|(index, repo_path)| {
            let mut command = cli_without_machine_global_bindings();
            command
                .arg(format!(
                    "Update README.md for concurrent literal invocation {index}"
                ))
                .current_dir(repo_path)
                .env("XDG_CONFIG_HOME", &xdg)
                .env("PATH", "")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
                .spawn()
                .with_context(|| format!("spawn concurrent bare invocation {index}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let outputs = children
        .into_iter()
        .enumerate()
        .map(|(index, child)| {
            child
                .wait_with_output()
                .with_context(|| format!("wait for concurrent bare invocation {index}"))
        })
        .collect::<Result<Vec<_>>>()?;
    for output in &outputs {
        assert!(!output.status.success());
    }

    let mut run_ids = repo_paths
        .iter()
        .map(|repo_path| {
            let run_root = repo_path.join(".maco/o2/runs");
            let mut entries = fs::read_dir(&run_root)
                .with_context(|| format!("read generated run root {}", run_root.display()))?
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    entry.file_type().ok()?.is_dir().then(|| entry.file_name())
                })
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 1, "generated entries in {run_root:?}");
            Ok(entries.pop().expect("one generated run directory"))
        })
        .collect::<Result<Vec<_>>>()?;
    run_ids.sort();
    run_ids.dedup();
    let stderr = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stderr))
        .collect::<Vec<_>>();
    assert_eq!(run_ids.len(), 2, "run ids: {run_ids:?}; stderr: {stderr:?}");
    assert!(run_ids
        .iter()
        .all(|run_id| run_id.to_string_lossy().starts_with("o2-")));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn cli_literal_defaults_refuse_missing_multiple_mismatched_symlinked_and_unsafe_roots() -> Result<()>
{
    let Some(runtime_root) = current_private_runtime_root() else {
        return Ok(());
    };
    let temp = TempDir::new().context("tempdir")?;

    let missing_xdg = temp.path().join("missing-xdg");
    fs::create_dir(&missing_xdg).context("create missing-config XDG root")?;
    let missing = run_literal_with_xdg_config(temp.path(), &missing_xdg)?;
    assert_default_refusal(&missing, "not a safe physical file");

    let mismatch_xdg = temp.path().join("mismatch-xdg");
    let mismatch_state = temp.path().join("mismatch-state");
    let mismatch_root = temp.path().join("mismatch-root");
    create_private_dir(&mismatch_state)?;
    create_private_dir(&mismatch_root)?;
    write_literal_default_config(
        &mismatch_xdg.join("maco/machine-global.json"),
        &mismatch_state,
        &[("not-runtime", &mismatch_root)],
    )?;
    let mismatch = run_literal_with_xdg_config(temp.path(), &mismatch_xdg)?;
    assert_default_refusal(&mismatch, "exactly one reviewed root");

    let multiple_xdg = temp.path().join("multiple-xdg");
    let multiple_state = temp.path().join("multiple-state");
    create_private_dir(&multiple_state)?;
    write_literal_default_config(
        &multiple_xdg.join("maco/machine-global.json"),
        &multiple_state,
        &[("runtime-a", &runtime_root), ("runtime-b", &runtime_root)],
    )?;
    let multiple = run_literal_with_xdg_config(temp.path(), &multiple_xdg)?;
    assert_default_refusal(&multiple, "overlap by canonical path components");

    let symlink_config_xdg = temp.path().join("symlink-config-xdg");
    let symlink_config_state = temp.path().join("symlink-config-state");
    let actual_config = temp.path().join("actual-machine-global.json");
    create_private_dir(&symlink_config_state)?;
    write_literal_default_config(
        &actual_config,
        &symlink_config_state,
        &[("runtime", &runtime_root)],
    )?;
    fs::create_dir_all(symlink_config_xdg.join("maco"))
        .context("create symlink-config XDG parent")?;
    symlink(
        &actual_config,
        symlink_config_xdg.join("maco/machine-global.json"),
    )
    .context("substitute default config with symlink")?;
    let symlink_config = run_literal_with_xdg_config(temp.path(), &symlink_config_xdg)?;
    assert_default_refusal(&symlink_config, "not a safe physical file");

    let symlink_root_xdg = temp.path().join("symlink-root-xdg");
    let symlink_root_state = temp.path().join("symlink-root-state");
    let runtime_alias = temp.path().join("runtime-alias");
    create_private_dir(&symlink_root_state)?;
    symlink(&runtime_root, &runtime_alias).context("create runtime-root symlink substitute")?;
    write_literal_default_config(
        &symlink_root_xdg.join("maco/machine-global.json"),
        &symlink_root_state,
        &[("runtime", &runtime_alias)],
    )?;
    let symlink_root = run_literal_with_xdg_config(temp.path(), &symlink_root_xdg)?;
    assert_default_refusal(&symlink_root, "failed to authenticate");

    let unsafe_xdg = temp.path().join("unsafe-xdg");
    let unsafe_state = temp.path().join("unsafe-state");
    let unsafe_root = temp.path().join("unsafe-root");
    create_private_dir(&unsafe_state)?;
    create_private_dir(&unsafe_root)?;
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o777))
        .context("make reviewed root unsafe")?;
    write_literal_default_config(
        &unsafe_xdg.join("maco/machine-global.json"),
        &unsafe_state,
        &[("runtime", &unsafe_root)],
    )?;
    let unsafe_output = run_literal_with_xdg_config(temp.path(), &unsafe_xdg)?;
    assert_default_refusal(&unsafe_output, "group/world-writable");
    Ok(())
}

#[test]
fn cli_literal_entrypoint_accepts_machine_global_environment_bindings() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let config = temp.path().join("machine-global.json");

    let config_only = cli_without_machine_global_bindings()
        .arg("environment binding probe")
        .current_dir(temp.path())
        .env(MACHINE_GLOBAL_CONFIG_ENV, &config)
        .output()
        .context("route literal with only the machine-global config environment binding")?;
    assert!(!config_only.status.success());
    let config_only_stderr = String::from_utf8_lossy(&config_only.stderr);
    let config_only_error = config_only_stderr
        .split("\n\nUsage:")
        .next()
        .context("read config-only missing-argument diagnostic")?;
    assert!(
        config_only_error.contains("--machine-global-runtime-root-id"),
        "{config_only_stderr}"
    );
    assert!(
        !config_only_error.contains("--machine-global-config"),
        "{config_only_stderr}"
    );

    let runtime_root_only = cli_without_machine_global_bindings()
        .arg("environment binding probe")
        .current_dir(temp.path())
        .env(MACHINE_GLOBAL_RUNTIME_ROOT_ID_ENV, "runtime")
        .output()
        .context("route literal with only the machine-global runtime-root environment binding")?;
    assert!(!runtime_root_only.status.success());
    let runtime_root_only_stderr = String::from_utf8_lossy(&runtime_root_only.stderr);
    let runtime_root_only_error = runtime_root_only_stderr
        .split("\n\nUsage:")
        .next()
        .context("read runtime-root-only missing-argument diagnostic")?;
    assert!(
        runtime_root_only_error.contains("--machine-global-config"),
        "{runtime_root_only_stderr}"
    );
    assert!(
        !runtime_root_only_error.contains("--machine-global-runtime-root-id"),
        "{runtime_root_only_stderr}"
    );

    let both = cli_without_machine_global_bindings()
        .arg("environment binding probe")
        .current_dir(temp.path())
        .env(MACHINE_GLOBAL_CONFIG_ENV, &config)
        .env(MACHINE_GLOBAL_RUNTIME_ROOT_ID_ENV, "runtime")
        .output()
        .context("route literal with both machine-global environment bindings")?;
    assert!(!both.status.success());
    let both_stderr = String::from_utf8_lossy(&both.stderr);
    assert!(both_stderr.contains("repository"), "{both_stderr}");
    assert!(
        !both_stderr.contains("the following required arguments were not provided"),
        "{both_stderr}"
    );
    Ok(())
}

#[cfg(unix)]
const ISSUE33_PINNED_WRAPPER_ENV: &str = "MACO_ISSUE33_PINNED_WRAPPER";
#[cfg(unix)]
const ISSUE33_PINNED_WRAPPER_SHA256: &str =
    "93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814";
#[cfg(unix)]
const ISSUE33_PINNED_CHECKOUT_HEAD: &str = "66f59aa253868d1dd909b012e04c548e7b669d2f";
const ISSUE33_CLAIMS_V1: &[u8] = include_bytes!("fixtures/issue33/agent-files-claims-v1.json");
const ISSUE33_CLAIMS_V1_SHA256: &str =
    "58076fb067d6bbc560926628b8930075d0674eae025b945619f0890000995291";
const ISSUE33_PHYSICAL_JOURNAL_ID: &str =
    "d9741d2f810d605133ddfb24bca389e7f1e96fd2a3da1bc5ca236da56519306f";
#[cfg(unix)]
const ISSUE33_FIXTURE_NAMESPACE: &str = "state";
#[cfg(unix)]
const ISSUE33_FIXTURE_JOURNAL: &str = "j";
#[cfg(unix)]
const ISSUE33_OPTIONAL_LOGICAL_ANCHOR: &str =
    ".snapshot-init-a61808fe40feb8b3433778bbc2ececcaa47c8c47fc1657f054c239efd3f0e984.json";
const ISSUE33_PHYSICAL_JOURNAL_MANIFEST: &str =
    include_str!("fixtures/issue33/authenticated-claims-state-v1.sha256");

#[cfg(target_os = "linux")]
#[test]
fn cli_sync_status_reports_live_supervise_run_ownership() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let run_id = RunId::new("status-live-run")?;
    let store = SyncStore::open(&repo_path)?;
    let claim =
        store.claim_paths_for_run(&run_id, "status-assignment", [PathBuf::from("README.md")])?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_eq!(status[0]["token"], claim.token.get());
    assert_eq!(status[0]["agent_id"], "status-assignment");
    assert_eq!(status[0]["owner_run_id"], "status-live-run");
    assert_eq!(status[0]["owner_run_state"], "active");
    assert_eq!(status[0]["owner_process_id"], std::process::id());

    let text = Command::new(BIN)
        .args(["sync", "status", "--repo", repo])
        .output()
        .context("run text sync status")?;
    assert!(text.status.success());
    let stdout = String::from_utf8(text.stdout).context("decode text sync status")?;
    assert!(stdout.contains(&format!("{}\tstatus-assignment", claim.token.get())));
    assert!(stdout.contains("run=status-live-run"));
    assert!(stdout.contains("state=active"));

    store.release(claim.token)?;
    Ok(())
}

#[test]
fn cli_sync_heartbeat_sweep_and_takeover_preserve_exclusive_ownership() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let claim = run_success_json([
        "sync",
        "claim",
        "owner",
        "src",
        "--repo",
        repo,
        "--heartbeat-interval-seconds",
        "1",
        "--stale-after-seconds",
        "2",
        "--json",
    ])?;
    assert_eq!(claim["token"], 1);
    assert_eq!(claim["agent_id"], "owner");

    let liveness = run_success_json(["sync", "liveness", "--repo", repo, "--json"])?;
    assert_eq!(liveness[0]["claim_id"], "claim-00000000000000000001");
    assert_eq!(liveness[0]["heartbeat_interval_seconds"], 1);
    assert_eq!(liveness[0]["stale_after_seconds"], 2);

    let wrong_owner = Command::new(BIN)
        .args([
            "sync",
            "heartbeat",
            "1",
            "not-owner",
            "--repo",
            repo,
            "--json",
        ])
        .output()
        .context("wrong-owner heartbeat")?;
    assert!(!wrong_owner.status.success());
    assert!(String::from_utf8_lossy(&wrong_owner.stderr).contains("does not exactly match"));

    let heartbeat =
        run_success_json(["sync", "heartbeat", "1", "owner", "--repo", repo, "--json"])?;
    assert_eq!(heartbeat["state"], "fresh");
    std::thread::sleep(std::time::Duration::from_secs(3));

    let sweep = run_success_json(["sync", "sweep", "--repo", repo, "--json"])?;
    assert_eq!(
        sweep["newly_takeover_eligible"][0],
        "claim-00000000000000000001"
    );
    let owner = run_success_json(["sync", "owner", "src/lib.rs", "--repo", repo, "--json"])?;
    assert_eq!(owner["owner"], "owner");

    let late_heartbeat = Command::new(BIN)
        .args(["sync", "heartbeat", "1", "owner", "--repo", repo, "--json"])
        .output()
        .context("late heartbeat")?;
    assert!(!late_heartbeat.status.success());
    assert!(String::from_utf8_lossy(&late_heartbeat.stderr).contains("cannot be revived"));

    let takeover = run_success_json([
        "sync",
        "takeover",
        "1",
        "successor",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(takeover["claim"]["token"], 2);
    assert_eq!(takeover["claim"]["agent_id"], "successor");
    assert_eq!(
        takeover["lineage"]["prior_claim_id"],
        "claim-00000000000000000001"
    );
    assert_eq!(
        takeover["liveness"]["supersedes"],
        "claim-00000000000000000001"
    );
    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("claim status")?.len(), 1);
    assert_eq!(status[0]["token"], 2);
    assert_eq!(status[0]["agent_id"], "successor");
    let history = run_success_json(["sync", "history", "--repo", repo, "--json"])?;
    assert_eq!(history.as_array().context("history")?.len(), 1);
    assert_eq!(history[0]["prior_agent_id"], "owner");
    assert_eq!(history[0]["successor_agent_id"], "successor");
    run_success_json(["sync", "release", "2", "--repo", repo, "--json"])?;
    let history_after_release = run_success_json(["sync", "history", "--repo", repo, "--json"])?;
    assert_eq!(history_after_release, history);
    Ok(())
}

#[cfg(unix)]
#[test]
fn cli_issue33_quarantine_then_attested_migration_restores_claim_consumers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let installed = install_issue33_unanchored_claim_state(&temp)?;
    let repo_path = installed.repo_path;
    let repository = installed.repository;
    let journal_root = installed.journal_root;

    let repo = repo_path.to_str().context("repo path utf8")?;
    assert_issue33_dev_unanchored_failure(
        ["sync", "status", "--repo", repo, "--json"],
        "run sync status against unanchored physical journal",
    )?;
    assert_issue33_dev_unanchored_failure(
        ["worktree", "gc", "--repo", repo, "--dry-run", "--json"],
        "run pre-recovery worktree gc dry-run against unanchored physical journal",
    )?;

    let fixture_source = issue33_physical_journal_fixture();
    let quarantine_root = repository
        .commondir()
        .join("maco/issue33-option-2-quarantine");
    fs::create_dir(&quarantine_root).context("create test-local option-2 quarantine")?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))
        .context("make test-local quarantine owner-private")?;
    let quarantined_namespace = quarantine_root.join("authenticated-claims-state-v1");
    fs::rename(&journal_root, &quarantined_namespace)
        .context("atomically quarantine the complete authenticated claims namespace")?;
    assert!(!journal_root.exists());
    assert!(quarantined_namespace.is_dir());
    let quarantined_journal = quarantined_namespace.join(ISSUE33_PHYSICAL_JOURNAL_ID);
    assert!(quarantined_journal.is_dir());
    assert!(
        fixture_source.is_dir(),
        "the checked-in physical-journal fixture must remain untouched"
    );

    let migration = run_success_json([
        "state",
        "migrate",
        "--repo",
        repo,
        "--apply",
        "--acknowledge-unauthenticated-claims-v1",
        "--expected-claims-v1-sha256",
        ISSUE33_CLAIMS_V1_SHA256,
        "--json",
    ])?;
    assert_eq!(migration["mode"], "apply");
    assert_eq!(migration["status"], "applied");
    assert_eq!(migration["manifest_generation"], 1);
    let claims_entry = migration["entries"]
        .as_array()
        .context("migration entries")?
        .iter()
        .find(|entry| entry["store"] == "claims")
        .context("claims migration entry")?;
    assert_eq!(
        claims_entry["provenance"],
        "operator_attested_unauthenticated_import"
    );
    assert_eq!(claims_entry["sha256"], ISSUE33_CLAIMS_V1_SHA256);

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    assert_issue33_claim_status(&status)?;

    let gc = run_success_json(["worktree", "gc", "--repo", repo, "--dry-run", "--json"])?;
    assert_eq!(gc["dry_run"], true);
    assert_eq!(gc["considered_count"], 0);
    assert_eq!(gc["removed_count"], 0);
    assert_eq!(gc["orphan_removed_count"], 0);
    assert!(
        quarantined_namespace.is_dir(),
        "successful consumers must preserve the complete quarantined namespace"
    );
    assert!(
        quarantined_journal.is_dir(),
        "the synthetic physical journal must remain inside the quarantined namespace"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "requires MACO_ISSUE33_PINNED_WRAPPER to name an operator-provided registry-pinned wrapper"]
fn cli_issue33_same_installed_state_proves_dev_pinned_asymmetry_and_gc_failure() -> Result<()> {
    let pinned_package = issue33_pinned_package_from_env()?;
    pinned_package
        .verify_identity()
        .context("verify registry-pinned package before invocation")?;
    let temp = TempDir::new().context("tempdir")?;
    let installed = install_issue33_unanchored_claim_state(&temp)?;
    let repo = installed.repo_path.to_str().context("repo path utf8")?;
    let claims_before =
        fs::read(installed.state_root.join("claims.json")).context("read installed claims-v1")?;
    let journal_before = issue33_journal_bytes(&installed.physical_journal)?;

    let pinned = Command::new(&pinned_package.wrapper)
        .args(["sync", "status", "--repo", repo, "--json"])
        .env("CARGO_TARGET_DIR", temp.path().join("pinned-target"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .output()
        .with_context(|| {
            format!(
                "run registry-pinned wrapper {} against installed Issue 33 state",
                pinned_package.wrapper.display()
            )
        })?;
    pinned_package
        .verify_identity()
        .context("verify registry-pinned package after invocation")?;
    assert!(
        pinned.status.success(),
        "registry-pinned sync status must succeed on the installed Issue 33 state; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&pinned.stdout),
        String::from_utf8_lossy(&pinned.stderr)
    );
    let pinned_status: Value =
        serde_json::from_slice(&pinned.stdout).context("parse registry-pinned sync status JSON")?;
    assert_issue33_claim_status(&pinned_status)?;
    assert!(
        !installed.state_root.join("claims.lock").exists(),
        "registry-pinned sync status must release its transient legacy claims lock"
    );

    assert_issue33_dev_unanchored_failure(
        ["sync", "status", "--repo", repo, "--json"],
        "run development sync status against the pinned-observed installed state",
    )?;
    assert_issue33_dev_unanchored_failure(
        [
            "worktree", "gc", "--repo", repo, "--dry-run", "--json",
        ],
        "run pre-recovery development worktree gc dry-run against the pinned-observed installed state",
    )?;

    assert_eq!(
        fs::read(installed.state_root.join("claims.json"))
            .context("reread installed claims-v1 after all three observations")?,
        claims_before,
        "all three observations must use the same unchanged claims-v1 bytes"
    );
    assert_eq!(
        issue33_journal_bytes(&installed.physical_journal)?,
        journal_before,
        "all three observations must use the same unchanged physical-journal bytes"
    );

    Ok(())
}

#[cfg(unix)]
struct Issue33InstalledState {
    repo_path: PathBuf,
    repository: Repository,
    state_root: PathBuf,
    journal_root: PathBuf,
    physical_journal: PathBuf,
}

#[cfg(unix)]
fn install_issue33_unanchored_claim_state(temp: &TempDir) -> Result<Issue33InstalledState> {
    let repo_path = create_committed_repo(temp.path())?;
    let repository = Repository::open(&repo_path).context("open repo")?;
    let state_root = repository.commondir().join("maco/state");
    fs::create_dir_all(&state_root).context("create temporary state root")?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .context("make temporary state root owner-private")?;
    write_private_test_state_file(
        &state_root.join("artifact_finalization_hmac_v1.key"),
        &[0x33; 32],
    )?;
    write_private_test_state_file(&state_root.join("repository_auth_epoch_v1"), &[0x34; 32])?;
    fs::write(state_root.join("claims.json"), ISSUE33_CLAIMS_V1)
        .context("write checksum-less claims-v1 fixture")?;
    fs::set_permissions(
        state_root.join("claims.json"),
        fs::Permissions::from_mode(0o600),
    )
    .context("make checksum-less claims-v1 fixture owner-private")?;

    let journal_root = state_root.join("authenticated-claims-state-v1");
    fs::create_dir(&journal_root).context("create temporary authenticated claims journal root")?;
    fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))
        .context("make temporary claims journal root owner-private")?;
    let physical_journal = journal_root.join(ISSUE33_PHYSICAL_JOURNAL_ID);
    let verified_manifest_files = verify_issue33_physical_journal_fixture()?;
    let copied_files = copy_issue33_physical_journal_fixture(&physical_journal)?;
    copy_issue33_optional_logical_anchor_fixture(&journal_root)?;
    assert_eq!(
        copied_files, verified_manifest_files,
        "the regression must install every synthetic physical-journal file"
    );

    Ok(Issue33InstalledState {
        repo_path,
        repository,
        state_root,
        journal_root,
        physical_journal,
    })
}

#[cfg(unix)]
struct Issue33PinnedPackage {
    wrapper: PathBuf,
    checkout: PathBuf,
}

#[cfg(unix)]
impl Issue33PinnedPackage {
    fn verify_identity(&self) -> Result<()> {
        anyhow::ensure!(
            issue33_sha256sum(&self.wrapper)? == ISSUE33_PINNED_WRAPPER_SHA256,
            "registry-pinned wrapper digest changed"
        );
        anyhow::ensure!(
            issue33_git_stdout(&self.checkout, &["rev-parse", "--verify", "HEAD^{commit}"])?
                == ISSUE33_PINNED_CHECKOUT_HEAD,
            "registry-pinned checkout HEAD changed"
        );
        anyhow::ensure!(
            issue33_git_stdout(
                &self.checkout,
                &["status", "--porcelain=v1", "--untracked-files=all"]
            )?
            .is_empty(),
            "registry-pinned checkout must have a clean index and worktree"
        );
        Ok(())
    }
}

#[cfg(unix)]
fn issue33_pinned_package_from_env() -> Result<Issue33PinnedPackage> {
    let wrapper = std::env::var_os(ISSUE33_PINNED_WRAPPER_ENV).with_context(|| {
        format!(
            "{ISSUE33_PINNED_WRAPPER_ENV} is required; set it to the absolute registry-backed .agents/scripts/maco wrapper"
        )
    })?;
    let wrapper = PathBuf::from(wrapper);
    anyhow::ensure!(
        wrapper.is_absolute(),
        "{ISSUE33_PINNED_WRAPPER_ENV} must be an absolute path"
    );
    let metadata = fs::metadata(&wrapper)
        .with_context(|| format!("inspect registry-pinned wrapper {}", wrapper.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{ISSUE33_PINNED_WRAPPER_ENV} is not a file: {}",
        wrapper.display()
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "{ISSUE33_PINNED_WRAPPER_ENV} is not executable: {}",
        wrapper.display()
    );
    let wrapper = fs::canonicalize(&wrapper)
        .with_context(|| format!("resolve registry-pinned wrapper {}", wrapper.display()))?;
    let scripts_dir = wrapper
        .parent()
        .context("registry-pinned wrapper has no scripts directory")?;
    let project_root = fs::canonicalize(scripts_dir.join("../.."))
        .context("resolve registry-pinned wrapper project root")?;
    let expected_wrapper = fs::canonicalize(project_root.join(".agents/scripts/maco"))
        .context("resolve expected project-local MACO wrapper")?;
    anyhow::ensure!(
        wrapper == expected_wrapper,
        "{ISSUE33_PINNED_WRAPPER_ENV} must resolve to <project>/.agents/scripts/maco"
    );
    let manifest = fs::canonicalize(
        project_root.join(".agents/external/multi-agent-coding-orchestrator/Cargo.toml"),
    )
    .context("resolve registry-pinned package manifest")?;
    let checkout = manifest
        .parent()
        .context("registry-pinned package manifest has no checkout parent")?
        .to_path_buf();
    let git_toplevel = fs::canonicalize(issue33_git_stdout(
        &checkout,
        &["rev-parse", "--show-toplevel"],
    )?)
    .context("resolve registry-pinned Git toplevel")?;
    anyhow::ensure!(
        checkout == git_toplevel,
        "registry-pinned manifest must resolve inside its Git checkout root"
    );

    Ok(Issue33PinnedPackage { wrapper, checkout })
}

#[cfg(unix)]
fn issue33_sha256sum(path: &Path) -> Result<String> {
    let output = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .with_context(|| format!("hash {}", path.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "sha256sum failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("decode sha256sum output for {}", path.display()))?;
    Ok(stdout
        .split_ascii_whitespace()
        .next()
        .context("sha256sum returned no digest")?
        .to_string())
}

#[cfg(unix)]
fn issue33_git_stdout(checkout: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(args)
        .output()
        .with_context(|| format!("run git in registry-pinned checkout {}", checkout.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "git failed in registry-pinned checkout {}: {}",
        checkout.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)
        .context("decode registry-pinned git output")?
        .trim()
        .to_string())
}

#[cfg(unix)]
fn assert_issue33_dev_unanchored_failure<const N: usize>(
    args: [&str; N],
    context: &str,
) -> Result<()> {
    let blocked = Command::new(BIN)
        .args(args)
        .env("RUST_BACKTRACE", "0")
        .output()
        .with_context(|| context.to_string())?;
    assert!(!blocked.status.success());
    assert_eq!(
        String::from_utf8_lossy(&blocked.stderr).trim(),
        format!(
            "Error: authenticated snapshot physical journal '{}' is not anchored by any signed logical state",
            ISSUE33_PHYSICAL_JOURNAL_ID
        )
    );
    Ok(())
}

#[cfg(unix)]
fn assert_issue33_claim_status(status: &Value) -> Result<()> {
    let claims = status.as_array().context("status claims")?;
    assert_eq!(claims.len(), 3);
    assert_eq!(
        claims
            .iter()
            .map(|claim| claim["token"].as_u64())
            .collect::<Vec<_>>(),
        vec![Some(20), Some(44), Some(66)]
    );
    assert_eq!(claims[0]["agent_id"], "o1-worktree-cleanup");
    assert_eq!(claims[0]["paths"], serde_json::json!([".maco"]));
    assert_eq!(claims[1]["agent_id"], "o1-guard-fix");
    assert_eq!(
        claims[1]["paths"],
        serde_json::json!([
            "scripts/audit-codex-terminal-role-launches",
            "scripts/check-development-handoff-clean"
        ])
    );
    assert_eq!(claims[2]["agent_id"], "history-rewrite-otherproj-o1");
    assert_eq!(
        claims[2]["paths"],
        serde_json::json!(["machine-root/projects/example/other-repo"])
    );
    Ok(())
}

#[cfg(unix)]
fn issue33_journal_bytes(journal: &Path) -> Result<BTreeMap<std::ffi::OsString, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(journal)
        .with_context(|| format!("enumerate installed journal {}", journal.display()))?
    {
        let entry = entry.context("inspect installed physical-journal entry")?;
        let metadata = entry
            .metadata()
            .context("inspect installed physical-journal metadata")?;
        anyhow::ensure!(
            metadata.is_file(),
            "installed physical-journal entry is not a regular file: {}",
            entry.path().display()
        );
        files.insert(
            entry.file_name(),
            fs::read(entry.path()).context("read installed physical-journal entry")?,
        );
    }
    Ok(files)
}

#[cfg(unix)]
fn write_private_test_state_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("make {} owner-private", path.display()))
}

#[cfg(unix)]
fn issue33_physical_journal_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/issue33")
        .join(ISSUE33_FIXTURE_NAMESPACE)
        .join(ISSUE33_FIXTURE_JOURNAL)
}

#[cfg(unix)]
fn verify_issue33_physical_journal_fixture() -> Result<usize> {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/issue33");
    let expected_parent = Path::new(ISSUE33_FIXTURE_NAMESPACE).join(ISSUE33_FIXTURE_JOURNAL);
    let mut manifest_names = Vec::new();

    for (index, line) in ISSUE33_PHYSICAL_JOURNAL_MANIFEST.lines().enumerate() {
        let (expected_hash, relative) = line
            .split_once("  ")
            .with_context(|| format!("parse physical-journal manifest line {}", index + 1))?;
        anyhow::ensure!(
            expected_hash.len() == 64
                && expected_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "physical-journal manifest line {} has an invalid SHA-256",
            index + 1
        );

        let relative = Path::new(relative);
        anyhow::ensure!(
            relative.parent() == Some(expected_parent.as_path()),
            "physical-journal manifest line {} is outside the synthetic journal",
            index + 1
        );
        let file_name = relative
            .file_name()
            .context("physical-journal manifest entry has no file name")?;
        let fixture_path = fixture_root.join(relative);
        let metadata = fs::symlink_metadata(&fixture_path).with_context(|| {
            format!("inspect fixture manifest entry {}", fixture_path.display())
        })?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "fixture manifest entry is not a regular file: {}",
            fixture_path.display()
        );

        let output = Command::new("sha256sum")
            .arg("--")
            .arg(&fixture_path)
            .output()
            .with_context(|| format!("hash fixture manifest entry {}", fixture_path.display()))?;
        anyhow::ensure!(
            output.status.success(),
            "sha256sum failed for {}: {}",
            fixture_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let stdout = std::str::from_utf8(&output.stdout)
            .with_context(|| format!("decode sha256sum output for {}", fixture_path.display()))?;
        let actual_hash = stdout
            .split_ascii_whitespace()
            .next()
            .context("sha256sum returned no digest")?;
        anyhow::ensure!(
            actual_hash == expected_hash,
            "fixture digest mismatch for {}: expected {}, got {}",
            fixture_path.display(),
            expected_hash,
            actual_hash
        );
        manifest_names.push(file_name.to_os_string());
    }

    manifest_names.sort();
    let source = issue33_physical_journal_fixture();
    let mut fixture_names = Vec::new();
    for entry in fs::read_dir(&source)
        .with_context(|| format!("enumerate synthetic journal {}", source.display()))?
    {
        let entry = entry.context("inspect synthetic physical-journal entry")?;
        let metadata = entry
            .metadata()
            .context("inspect synthetic physical-journal metadata")?;
        anyhow::ensure!(
            metadata.is_file(),
            "synthetic physical-journal entry is not a regular file: {}",
            entry.path().display()
        );
        fixture_names.push(entry.file_name());
    }
    fixture_names.sort();
    anyhow::ensure!(
        fixture_names == manifest_names,
        "physical-journal manifest does not name the complete synthetic journal"
    );

    Ok(manifest_names.len())
}

#[cfg(unix)]
fn copy_issue33_physical_journal_fixture(destination: &Path) -> Result<usize> {
    let source = issue33_physical_journal_fixture();
    fs::create_dir(destination)
        .with_context(|| format!("create copied journal {}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "make copied journal {} owner-private",
            destination.display()
        )
    })?;

    let mut copied_files = 0usize;
    for entry in fs::read_dir(&source)
        .with_context(|| format!("enumerate synthetic journal {}", source.display()))?
    {
        let entry = entry.context("inspect synthetic physical-journal entry")?;
        let metadata = entry
            .metadata()
            .context("inspect synthetic physical-journal metadata")?;
        if !metadata.is_file() {
            anyhow::bail!(
                "synthetic physical-journal entry is not a regular file: {}",
                entry.path().display()
            );
        }
        let copied = destination.join(entry.file_name());
        fs::copy(entry.path(), &copied)
            .with_context(|| format!("copy synthetic journal file {}", entry.path().display()))?;
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "make copied journal file {} owner-private",
                copied.display()
            )
        })?;
        copied_files = copied_files
            .checked_add(1)
            .context("synthetic journal file count overflowed")?;
    }
    Ok(copied_files)
}

#[cfg(unix)]
fn copy_issue33_optional_logical_anchor_fixture(destination: &Path) -> Result<()> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/issue33")
        .join(ISSUE33_FIXTURE_NAMESPACE)
        .join(ISSUE33_OPTIONAL_LOGICAL_ANCHOR);
    if !source.exists() {
        return Ok(());
    }
    let copied = destination.join(ISSUE33_OPTIONAL_LOGICAL_ANCHOR);
    fs::copy(&source, &copied)
        .with_context(|| format!("copy synthetic logical anchor {}", source.display()))?;
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "make synthetic logical anchor {} owner-private",
            copied.display()
        )
    })
}

#[test]
fn cli_repo_map_orchestrate_and_sync_status_json() -> Result<()> {
    support::require_containment!("cli_repo_map_orchestrate_and_sync_status_json");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
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
    .context("write plan")?;

    let map = run_success_json([
        "repo",
        "map",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert!(map["entries"].as_array().context("entries array")?.len() >= 2);

    let validation = run_success_json([
        "orchestrate",
        "validate",
        plan_path.to_str().context("plan path utf8")?,
        "--json",
    ])?;
    assert_eq!(validation["agent_count"], 1);

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        assert_orchestration_failed_closed(&summary)?;
        let status = run_success_json([
            "sync",
            "status",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])?;
        assert_eq!(status.as_array().context("status array")?.len(), 0);
        return Ok(());
    }
    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["stdout"]["text"], "true\n");

    let status = run_success_json([
        "sync",
        "status",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_orchestrate_failure_still_emits_json_summary() -> Result<()> {
    support::require_containment!("cli_orchestrate_failure_still_emits_json_summary");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "false"}
          ]
        }"#,
    )
    .context("write plan")?;

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("error string")?;
    assert!(
        error.contains("command exited") || error.contains("process-tree ownership"),
        "unexpected orchestration failure: {error}"
    );

    Ok(())
}

#[test]
fn cli_orchestrate_reports_committed_agent_change_and_patch() -> Result<()> {
    support::require_containment!("cli_orchestrate_reports_committed_agent_change_and_patch");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    let patch_dir = temp.path().join("patches");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {
              "id": "agent-a",
              "paths": ["README.md"],
              "command": "printf '# Smoke\n\ncommitted\n' > README.md && git add README.md && git -c user.name='maco test' -c user.email='maco-test@example.invalid' commit -m agent-change"
            }
          ]
        }"#,
    )
    .context("write plan")?;

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--patch-dir",
        patch_dir.to_str().context("patch dir utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        // The agent may legitimately edit its disposable worktree before the
        // confined command fails (for example at the commit step); captured
        // candidate patches may still be exported for inspection. Pin the
        // fail-closed boundary: a failed summary and no primary mutation.
        assert_eq!(summary["success"], false);
        assert_eq!(summary["agents"][0]["status"], "failed");
        assert!(summary["agents"][0]["error"].as_str().is_some());
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))?,
            "# Smoke\n"
        );
        return Ok(());
    }

    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["changed_paths"][0], "README.md");
    assert_eq!(
        summary["agents"][0]["patch_path"],
        patch_dir.join("agent-a.patch").to_string_lossy().as_ref()
    );
    let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).context("read patch")?;
    assert!(patch.contains("committed"));

    Ok(())
}

#[test]
fn cli_claim_conflict_still_emits_json_summary() -> Result<()> {
    support::require_containment!("cli_claim_conflict_still_emits_json_summary");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    run_success_json([
        "sync",
        "claim",
        "other-agent",
        "README.md",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
          ]
        }"#,
    )
    .context("write plan")?;

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    assert!(summary["agents"][0]["error"]
        .as_str()
        .context("error string")?
        .contains("failed to claim paths"));

    Ok(())
}

#[test]
fn cli_worktree_diff_uses_active_claims_for_json() -> Result<()> {
    support::require_containment!("cli_worktree_diff_uses_active_claims_for_json");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;
    run_success_json([
        "sync",
        "claim",
        "agent-a",
        "README.md",
        "--repo",
        repo,
        "--json",
    ])?;

    let diff = run_success_json(["worktree", "diff", "agent-a", "--repo", repo, "--json"])?;

    assert_eq!(diff["metadata"]["agent_id"], "agent-a");
    assert_eq!(diff["claimed_paths"][0], "README.md");
    assert_eq!(diff["changed_paths"][0], "README.md");
    assert_eq!(
        diff["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    assert!(diff["diff"]["summary"]["text"]
        .as_str()
        .context("diff summary")?
        .contains("changed"));

    Ok(())
}

#[test]
fn cli_worktree_pending_on_fresh_repo_creates_no_maco_state() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let maco_root = repo_path.join(".git").join("maco");
    assert!(!maco_root.exists());

    let pending = run_success_json(["worktree", "pending", "--repo", repo, "--json"])?;

    assert_eq!(pending.as_array().context("pending array")?.len(), 0);
    assert!(!maco_root.exists());
    let remove = Command::new(BIN)
        .args([
            "worktree",
            "remove",
            "agent-a",
            "--repo",
            repo,
            "--delete-branch",
            "--json",
        ])
        .output()
        .context("run unsupported non-force removal")?;
    assert!(!remove.status.success());
    assert!(String::from_utf8_lossy(&remove.stderr)
        .contains("non-force managed worktree removal is unsupported"));
    assert!(!maco_root.exists());
    Ok(())
}

#[test]
fn cli_worktree_create_derives_cleanliness_capability_on_clean_repo() -> Result<()> {
    support::require_containment!(
        "cli_worktree_create_derives_cleanliness_capability_on_clean_repo"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;

    let record = run_success_json([
        "worktree",
        "create",
        "agent-clean",
        "--repo",
        repo,
        "--json",
    ])?;

    assert_eq!(record["name"], "agent-clean");
    let worktree_path = Path::new(record["path"].as_str().context("worktree path string")?);
    assert!(worktree_path.is_dir());
    Ok(())
}

#[test]
fn cli_worktree_create_refuses_dirty_primary_with_actionable_error() -> Result<()> {
    support::require_containment!(
        "cli_worktree_create_refuses_dirty_primary_with_actionable_error"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(repo_path.join("dirty.txt"), "pending\n").context("write dirty file")?;

    let output = Command::new(BIN)
        .args([
            "worktree",
            "create",
            "agent-dirty",
            "--repo",
            repo,
            "--json",
        ])
        .output()
        .context("run dirty worktree create")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("capability-bound repository cleanliness input"),
        "expected capability-bound cleanliness context: {stderr}"
    );
    assert!(
        stderr.contains("primary repository is dirty"),
        "expected dirty-primary cause: {stderr}"
    );
    assert!(!repo_path.join(".git/maco").exists());
    Ok(())
}

#[test]
fn cli_semantic_map_and_queries_emit_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Worker;\nimpl Worker { pub fn new() -> Self { Worker } }\n",
    )
    .context("write semantic lib")?;

    let map = run_success_json(["repo", "map", "--semantic", "--repo", repo, "--json"])?;
    assert!(map["symbols"]
        .as_array()
        .context("symbols array")?
        .iter()
        .any(|symbol| symbol["name"] == "Worker"));

    let symbol = run_success_json([
        "repo", "query", "symbol", "Worker", "--repo", repo, "--json",
    ])?;
    assert_eq!(symbol["matches"][0]["name"], "Worker");

    let path = run_success_json([
        "repo",
        "query",
        "path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(path["files"][0]["path"], "src/lib.rs");
    assert!(path["symbols"]
        .as_array()
        .context("path symbols")?
        .iter()
        .any(|symbol| symbol["name"] == "new"));

    Ok(())
}

#[test]
fn cli_semantic_coord_preview_claim_conflict_status_and_release_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Worker;\n")
        .context("write semantic lib")?;

    let preview = run_success_json([
        "coord",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(preview["persisted"], false);
    assert_eq!(preview["has_blocking_conflicts"], false);
    assert_eq!(preview["intent"]["symbols"][0]["name"], "Worker");

    let claim = run_success_json([
        "coord",
        "claim",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(claim["persisted"], true);
    let token = claim["intent"]["token"].as_u64().context("claim token")?;

    let output = Command::new(BIN)
        .args([
            "coord", "claim", "agent-b", "--repo", repo, "--symbol", "Worker", "--json",
        ])
        .output()
        .context("run conflicting claim")?;
    assert!(!output.status.success());
    let conflict: Value = serde_json::from_slice(&output.stdout).context("parse conflict json")?;
    assert_eq!(conflict["persisted"], false);
    assert_eq!(conflict["has_blocking_conflicts"], true);
    assert!(conflict["conflicts"]
        .as_array()
        .context("conflicts array")?
        .iter()
        .any(|conflict| conflict["kind"] == "symbol_overlap"));

    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 1);

    let token_arg = token.to_string();
    let released =
        run_success_json_args(&["coord", "release", &token_arg, "--repo", repo, "--json"])?;
    assert_eq!(released["agent_id"], "agent-a");
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_semantic_coord_release_agent_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\n",
    )
    .context("write semantic lib")?;

    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Alpha", "--json",
    ])?;
    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Beta", "--json",
    ])?;

    let released = run_success_json([
        "coord",
        "release-agent",
        "agent-a",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(released.as_array().context("released array")?.len(), 2);
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_merge_preview_blocks_unclaimed_edits_json() -> Result<()> {
    support::require_containment!("cli_merge_preview_blocks_unclaimed_edits_json");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;

    let preview = run_success_json([
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--json",
    ])?;

    assert_eq!(preview["safety"]["readiness"]["status"], "blocked");
    assert!(preview["safety"]["readiness"]["blockers"]
        .as_array()
        .context("blockers array")?
        .iter()
        .any(|blocker| blocker == "unclaimed_edits"));
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"][0],
        "README.md"
    );

    Ok(())
}

#[test]
fn cli_llm_providers_and_prompt_preview_are_network_free_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    fs::write(
        &task_path,
        "Implement local-only prompt preview.\nAPI_TOKEN=secret\n",
    )
    .context("write task")?;

    let providers = run_success_json(["llm", "providers", "--json"])?;
    assert_eq!(providers["network_providers_required"], false);
    assert_eq!(providers["providers"][0]["id"], "fake");
    assert_eq!(providers["providers"][0]["network_required"], false);

    let preview = run_success_json([
        "llm",
        "prompt-preview",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(preview["agent_id"], "agent-a");
    assert_eq!(preview["provider"]["network_required"], false);
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("<redacted:secret>"));
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("src/lib.rs"));

    Ok(())
}

#[test]
fn cli_prompt_preview_refuses_paths_outside_the_repository() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    let secret_path = temp.path().join("outside-secret.txt");
    fs::write(&task_path, "Inspect the requested path.\n").context("write task")?;
    fs::write(&secret_path, "PROMPT_PREVIEW_OUTSIDE_SENTINEL\n").context("write secret")?;

    for candidate in [
        "../outside-secret.txt".to_string(),
        secret_path.to_string_lossy().into_owned(),
    ] {
        let output = Command::new(BIN)
            .args([
                "llm",
                "prompt-preview",
                task_path.to_str().context("task path utf8")?,
                "--agent-id",
                "agent-a",
                "--path",
                &candidate,
                "--repo",
                repo_path.to_str().context("repo path utf8")?,
                "--json",
            ])
            .output()
            .context("run prompt preview")?;
        assert!(!output.status.success());
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("PROMPT_PREVIEW_OUTSIDE_SENTINEL")
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("PROMPT_PREVIEW_OUTSIDE_SENTINEL")
        );
    }

    Ok(())
}

#[test]
fn cli_prompt_preview_preserves_directory_and_planned_file_scopes() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    fs::write(&task_path, "新しいファイルを追加します。\n").context("write task")?;

    let preview = run_success_json([
        "llm",
        "prompt-preview",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "src",
        "--path",
        "src/planned.rs",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;

    let claimed_paths = preview["claimed_paths"]
        .as_array()
        .context("claimed paths")?;
    assert!(claimed_paths.iter().any(|path| path == "src"));
    assert!(claimed_paths.iter().any(|path| path == "src/planned.rs"));
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("新しいファイルを追加します"));

    Ok(())
}

#[test]
fn bounded_external_cli_inputs_fail_before_creating_work() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let oversized = temp.path().join("oversized-input");
    File::create(&oversized)
        .context("create oversized input")?
        .set_len(64 * 1024 * 1024 + 1)
        .context("size oversized input")?;
    let task = temp.path().join("task.md");
    fs::write(&task, "Update README\n").context("task")?;

    for args in [
        vec![
            "consult",
            "ask",
            "--question-file",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "issue",
            "preview",
            "--title",
            "bounded input",
            "--body-file",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "orchestrate",
            "collect",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task.to_str().context("task path utf8")?,
            "--agent-id",
            "bounded-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
    ] {
        let output = Command::new(BIN)
            .args(args)
            .output()
            .context("run bounded input")?;
        assert!(!output.status.success());
    }

    let repo = Repository::open(&repo_path).context("open repo")?;
    assert!(repo
        .find_branch("maco/bounded-agent", git2::BranchType::Local)
        .is_err());
    assert!(!repo_path.join(".maco/consult").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn external_cli_file_inputs_refuse_symlink_leafs_before_work() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let question = temp.path().join("question.md");
    let issue = temp.path().join("issue.md");
    let summary = temp.path().join("summary.json");
    let task = temp.path().join("task.md");
    let proposal = temp.path().join("proposal.json");
    fs::write(&question, "What changed?\n").context("question")?;
    fs::write(&issue, "Issue body\n").context("issue")?;
    fs::write(&summary, "{\"agents\": []}\n").context("summary")?;
    fs::write(&task, "Update README\n").context("task")?;
    fs::write(
        &proposal,
        "{\"summary\":\"noop\",\"commands\":[],\"patches\":[],\"notes\":[]}",
    )
    .context("proposal")?;
    let question_link = temp.path().join("question-link");
    let issue_link = temp.path().join("issue-link");
    let summary_link = temp.path().join("summary-link");
    let task_link = temp.path().join("task-link");
    let proposal_link = temp.path().join("proposal-link");
    symlink(&question, &question_link).context("question link")?;
    symlink(&issue, &issue_link).context("issue link")?;
    symlink(&summary, &summary_link).context("summary link")?;
    symlink(&task, &task_link).context("task link")?;
    symlink(&proposal, &proposal_link).context("proposal link")?;

    let repo = repo_path.to_str().context("repo path utf8")?;
    let cases = [
        vec![
            "consult",
            "ask",
            "--question-file",
            question_link.to_str().context("question link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "issue",
            "preview",
            "--title",
            "link",
            "--body-file",
            issue_link.to_str().context("issue link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "orchestrate",
            "collect",
            summary_link.to_str().context("summary link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task.to_str().context("task utf8")?,
            "--agent-id",
            "proposal-link-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal_link.to_str().context("proposal link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task_link.to_str().context("task link utf8")?,
            "--agent-id",
            "task-link-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal.to_str().context("proposal utf8")?,
            "--repo",
            repo,
            "--json",
        ],
    ];
    for args in cases {
        let output = Command::new(BIN)
            .args(args)
            .output()
            .context("run link input")?;
        assert!(!output.status.success());
    }

    let repo = Repository::open(&repo_path).context("open repo")?;
    for branch in ["maco/proposal-link-agent", "maco/task-link-agent"] {
        assert!(repo.find_branch(branch, git2::BranchType::Local).is_err());
    }
    assert!(!repo_path.join(".maco/consult").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cli_prompt_preview_refuses_symlinked_repository_excerpts() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    let secret_path = temp.path().join("symlink-secret.txt");
    fs::write(&task_path, "Inspect the requested path.\n").context("write task")?;
    fs::write(&secret_path, "PROMPT_PREVIEW_SYMLINK_SENTINEL\n").context("write secret")?;
    symlink(&secret_path, repo_path.join("secret-link.txt")).context("create leaf symlink")?;

    let output = Command::new(BIN)
        .args([
            "llm",
            "prompt-preview",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "secret-link.txt",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run prompt preview")?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PROMPT_PREVIEW_SYMLINK_SENTINEL"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PROMPT_PREVIEW_SYMLINK_SENTINEL"));

    Ok(())
}

fn run_success_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    run_success_json_args(&args)
}

#[test]
fn cli_orchestrate_run_refuses_dirty_primary_with_actionable_error() -> Result<()> {
    support::require_containment!(
        "cli_orchestrate_run_refuses_dirty_primary_with_actionable_error"
    );
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "true"}
          ]
        }"#,
    )
    .context("write plan")?;
    fs::write(repo_path.join("dirty.txt"), "pending\n").context("write dirty file")?;

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run dirty orchestration")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("capability-bound repository cleanliness input"),
        "expected capability-bound cleanliness context: {stderr}"
    );
    Ok(())
}

fn run_success_json_args(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_json_regardless<const N: usize>(args: [&str; N]) -> Result<(Value, bool)> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    let report = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse orchestration json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((report, output.status.success()))
}

fn assert_orchestration_failed_closed(summary: &Value) -> Result<()> {
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("orchestration error")?;
    assert!(
        error.contains("process-tree ownership")
            || error.contains("containment")
            || error.contains("command exited"),
        "unexpected fail-closed error: {error}"
    );
    assert_eq!(
        summary["agents"][0]["changed_paths"]
            .as_array()
            .context("changed paths")?
            .len(),
        0
    );
    Ok(())
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args([
            "init",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n").context("write readme")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .context("write lib")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
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
