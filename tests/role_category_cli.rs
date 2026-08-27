use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

mod support;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn supervise_and_autopilot_help_advertise_role_category_override() -> Result<()> {
    for command in ["supervise", "autopilot"] {
        let output = Command::new(BIN)
            .arg(command)
            .arg("run")
            .arg("--help")
            .output()
            .with_context(|| format!("render {command} run help"))?;
        assert!(
            output.status.success(),
            "{command} run --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("--role-category"),
            "{command} run help omitted --role-category: {stdout}"
        );
        assert!(
            stdout.contains("operator_override") || stdout.contains("operator role-category"),
            "{command} run help omitted operator-override recording: {stdout}"
        );
    }
    Ok(())
}

#[test]
fn supervise_and_autopilot_reject_unknown_role_category_before_launch() -> Result<()> {
    for command in ["supervise", "autopilot"] {
        let output = Command::new(BIN)
            .arg(command)
            .arg("run")
            .arg("plan.json")
            .arg("--role-category")
            .arg("weak_model")
            .arg("--machine-global-config")
            .arg("/tmp/maco-machine-global.json")
            .arg("--machine-global-runtime-root-id")
            .arg("runtime")
            .output()
            .with_context(|| format!("parse {command} unknown role category"))?;
        assert!(
            !output.status.success(),
            "{command} accepted an unknown role category"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("role category") || stderr.contains("role-category"),
            "{command} refusal omitted the flag name: {stderr}"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn role_category_cli_stamps_stores_and_refuses_weak_coordinator() -> Result<()> {
    support::require_containment!("role_category_cli_stamps_stores_and_refuses_weak_coordinator");
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;

    let automatic_plan = temp.path().join("automatic.json");
    write_plan(&automatic_plan, None)?;
    let automatic = run_json(&[
        "supervise",
        "run",
        path_str(&automatic_plan)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "role-category-automatic",
        "--runtime",
        "fake",
        "--allow-dirty-primary",
        "--json",
    ])?;
    let automatic_snapshot = read_plan_snapshot(&repo_path, "role-category-automatic")?;
    assert_eq!(
        automatic_snapshot["assignments"][0]["role_category"],
        "delegating_coordinator"
    );
    assert_ne!(
        automatic_snapshot["assignments"][0]["selection_source"],
        "operator_override"
    );
    let automatic_text = automatic.to_string();
    assert!(
        automatic_text.contains("delegating_coordinator")
            && (automatic_text.contains("refused at execution admission")
                || automatic_text.contains("unproven model")),
        "automatic coordinator default must be admitted as a stored category: {automatic_text}"
    );

    let override_plan = temp.path().join("override.json");
    write_plan(&override_plan, None)?;
    let overridden = run_success_json(&[
        "supervise",
        "run",
        path_str(&override_plan)?,
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "role-category-override",
        "--runtime",
        "fake",
        "--role-category",
        "non_delegating_terminal_worker",
        "--allow-dirty-primary",
        "--json",
    ])?;
    assert_eq!(overridden["success"], true);
    let override_snapshot = read_plan_snapshot(&repo_path, "role-category-override")?;
    assert_eq!(
        override_snapshot["assignments"][0]["role_category"],
        "non_delegating_terminal_worker"
    );
    assert_eq!(
        override_snapshot["assignments"][0]["selection_source"],
        "operator_override"
    );

    let marker = temp.path().join("codex-bin-ran");
    let fake_codex = temp.path().join("fake-codex");
    fs::write(
        &fake_codex,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&fake_codex)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_codex, permissions)?;
    }
    let weak_plan = temp.path().join("weak-coordinator.json");
    write_plan(&weak_plan, Some("gpt-5.6-luna"))?;
    let output = command_with_test_machine_global_binding(
        BIN,
        &[
            "supervise",
            "run",
            path_str(&weak_plan)?,
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            "role-category-weak-coordinator",
            "--runtime",
            "codex",
            "--codex-bin",
            path_str(&fake_codex)?,
            "--role-category",
            "delegating_coordinator",
            "--allow-dirty-primary",
            "--json",
        ],
    )
    .output()
    .context("run weak coordinator admission")?;
    assert!(
        !output.status.success(),
        "weak coordinator unexpectedly launched: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("ineligible")
            || combined.contains("cannot hold")
            || combined.contains("refused at execution admission")
            || combined.contains("weak model")
            || combined.contains("capability")
            || combined.contains("unproven model"),
        "admission refusal missing authority cause: {combined}"
    );
    assert!(
        !marker.exists(),
        "weak coordinator admission must fail before launching the Codex binary"
    );
    Ok(())
}

fn write_plan(path: &Path, model: Option<&str>) -> Result<()> {
    let mut plan = serde_json::json!({
        "version": 1,
        "task": "role-category composed path",
        "max_child_retries": 0,
        "max_gate_corrections": 0,
        "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["README.md"],
            "worker_assignments": []
        }]
    });
    if let Some(model) = model {
        plan["role_models"] = serde_json::json!({
            "child_orchestrator": {
                "model": model,
                "unavailable_model_fallback": "fail_closed"
            }
        });
    }
    fs::write(path, serde_json::to_vec_pretty(&plan)?).context("write role-category plan")?;
    Ok(())
}

fn read_plan_snapshot(repo: &Path, run_id: &str) -> Result<Value> {
    let path = repo
        .join(".maco/o2/runs")
        .join(run_id)
        .join("assignments/supervisor-plan.json");
    serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("read stored supervisor plan snapshot {}", path.display()))?,
    )
    .context("parse stored supervisor plan snapshot")
}

fn run_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(BIN, args)
        .output()
        .context("run maco")?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse supervise JSON: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = command_with_test_machine_global_binding(BIN, args)
        .output()
        .context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse success JSON")
}

fn command_with_test_machine_global_binding(bin: impl AsRef<Path>, args: &[&str]) -> Command {
    let mut command = Command::new(bin.as_ref());
    command.args(args);
    if args.first() == Some(&"supervise") && args.get(1) == Some(&"run") {
        let repo = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--repo").then_some(Path::new(pair[1])))
            .expect("supervise run test command must name --repo");
        let config = write_test_machine_global_config(repo)
            .expect("write supervise CLI machine-global config");
        command
            .arg("--machine-global-config")
            .arg(config)
            .args(["--machine-global-runtime-root-id", "runtime"]);
    }
    command
}

#[cfg(target_os = "linux")]
fn write_test_machine_global_config(repo: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture_root = repo.parent().context("test repository parent")?;
    let state_root = fixture_root.join("supervise-machine-global-state");
    fs::create_dir_all(&state_root)?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))?;
    let uid = fs::metadata("/proc/self")?.uid();
    let runtime_root = PathBuf::from(format!("/run/user/{uid}"));
    let config = fixture_root.join("supervise-machine-global.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))?,
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    Ok(config)
}

#[cfg(not(target_os = "linux"))]
fn write_test_machine_global_config(repo: &Path) -> Result<PathBuf> {
    Ok(repo.join("unsupported-machine-global-config"))
}

fn create_committed_repo(root: &Path) -> Result<PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    fs::create_dir_all(repo_path.join("src"))?;
    fs::write(repo_path.join(".gitignore"), ".maco/\n")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )?;
    let repo = Repository::open(&repo_path)?;
    commit_all(&repo, "initial")?;
    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let signature = Signature::now("maco test", "maco-test@example.invalid")?;
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
    .context("commit")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
