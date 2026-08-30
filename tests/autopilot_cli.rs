use anyhow::{Context, Result};
use git2::Repository;
use serde_json::Value;
use std::{
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const RETIRED_MESSAGE: &str =
    "autopilot plan/run is retired; use literal instruction routing: maco <instruction>";

#[test]
fn autopilot_plan_and_run_retire_before_reads_launch_or_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).context("create repository fixture")?;
    fs::write(repo.join("existing"), "preserve me\n").context("write repository marker")?;

    let missing_task = temp.path().join("task-must-not-be-read");
    let missing_profile = temp.path().join("profile-must-not-be-read");
    let missing_config = temp.path().join("config-must-not-be-read");
    let codex_probe = temp.path().join("codex-must-not-launch");
    let launch_marker = temp.path().join("codex-was-launched");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            &codex_probe,
            "#!/bin/sh\n: > \"$MACO_RETIRE_TEST_LAUNCH_MARKER\"\n",
        )
        .context("write launch probe")?;
        fs::set_permissions(&codex_probe, fs::Permissions::from_mode(0o700))
            .context("make launch probe executable")?;
    }
    let before = direct_child_names(&repo)?;

    let plan = Command::new(BIN)
        .args([
            OsStr::new("autopilot"),
            OsStr::new("plan"),
            missing_task.as_os_str(),
            OsStr::new("--repo"),
            repo.as_os_str(),
            OsStr::new("--json"),
        ])
        .output()
        .context("run retired autopilot plan")?;
    assert_retired(plan);

    let run = Command::new(BIN)
        .env("MACO_RETIRE_TEST_LAUNCH_MARKER", &launch_marker)
        .args([
            OsStr::new("autopilot"),
            OsStr::new("run"),
            missing_task.as_os_str(),
            OsStr::new("--repo"),
            repo.as_os_str(),
            OsStr::new("--run-id"),
            OsStr::new("must-not-exist"),
            OsStr::new("--profile"),
            missing_profile.as_os_str(),
            OsStr::new("--codex-bin"),
            codex_probe.as_os_str(),
            OsStr::new("--machine-global-config"),
            missing_config.as_os_str(),
            OsStr::new("--machine-global-runtime-root-id"),
            OsStr::new("must-not-resolve"),
            OsStr::new("--json"),
        ])
        .output()
        .context("run retired autopilot execution")?;
    assert_retired(run);

    let empty_run = Command::new(BIN)
        .args(["autopilot", "run"])
        .output()
        .context("run retired autopilot execution without legacy arguments")?;
    assert_retired(empty_run);

    assert_eq!(direct_child_names(&repo)?, before);
    assert!(!repo.join(".maco").exists());
    assert!(!repo.join(".agents").exists());
    assert!(!missing_task.exists());
    assert!(!missing_profile.exists());
    assert!(!missing_config.exists());
    assert!(!launch_marker.exists());
    Ok(())
}

#[test]
fn retired_autopilot_verbs_are_hidden_while_read_only_commands_remain() -> Result<()> {
    let output = Command::new(BIN)
        .args(["autopilot", "--help"])
        .output()
        .context("show autopilot help")?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).context("decode autopilot help")?;

    assert!(!stdout.lines().any(|line| line.trim_start().starts_with("plan ")));
    assert!(!stdout.lines().any(|line| line.trim_start().starts_with("run ")));
    for command in ["status", "collect", "artifacts"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{command} "))),
            "missing {command} from autopilot help:\n{stdout}"
        );
    }
    Ok(())
}

#[test]
fn literal_instruction_routing_remains_available() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let output = Command::new(BIN)
        .current_dir(temp.path())
        .env_remove("MACO_MACHINE_GLOBAL_CONFIG")
        .env_remove("MACO_MACHINE_GLOBAL_RUNTIME_ROOT_ID")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .args([
            "replace the retired autopilot entrypoint",
            "--without-parsing-this-as-an-option",
        ])
        .output()
        .context("route a literal instruction")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to resolve default machine-global binding for routed literal instruction"),
        "{stderr}"
    );
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
    assert!(!stderr.contains("unexpected argument"), "{stderr}");
    assert!(!temp.path().join(".maco").exists());
    assert!(!temp.path().join(".agents").exists());
    Ok(())
}

#[test]
fn status_and_collect_remain_read_only_for_legacy_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("initialize repository")?;
    let run_dir = temp
        .path()
        .join(".maco/autopilot/runs/legacy-active");
    fs::create_dir_all(&run_dir).context("create legacy run artifacts")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
            .context("restrict legacy run directory")?;
    }
    let plan_path = run_dir.join("plan.json");
    fs::write(&plan_path, "{\"version\":1}\n").context("write legacy plan")?;

    let status = Command::new(BIN)
        .args([
            "autopilot",
            "status",
            "legacy-active",
            "--repo",
            path_str(temp.path())?,
            "--json",
        ])
        .output()
        .context("inspect legacy autopilot status")?;
    assert!(status.status.success(), "{}", output_stderr(&status));
    let report: Value = serde_json::from_slice(&status.stdout).context("decode status JSON")?;
    assert_eq!(report["run_id"], "legacy-active");
    assert_eq!(report["artifacts"]["plan"], true);
    assert!(report["final_report"].is_null());

    let collect = Command::new(BIN)
        .args([
            "autopilot",
            "collect",
            "legacy-active",
            "--repo",
            path_str(temp.path())?,
            "--json",
        ])
        .output()
        .context("collect legacy autopilot status")?;
    assert!(!collect.status.success());
    assert!(
        output_stderr(&collect).contains("active or unfinalized"),
        "{}",
        output_stderr(&collect)
    );
    assert_eq!(fs::read_to_string(&plan_path)?, "{\"version\":1}\n");
    Ok(())
}

fn assert_retired(output: Output) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(RETIRED_MESSAGE), "{stderr}");
    assert!(!stderr.contains("Usage:"), "{stderr}");
}

fn direct_child_names(path: &Path) -> Result<Vec<String>> {
    let mut names = fs::read_dir(path)
        .with_context(|| format!("read {}", path.display()))?
        .map(|entry| {
            entry.map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}

fn output_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
