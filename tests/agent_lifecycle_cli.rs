use anyhow::{Context, Result};
use git2::Repository;
use multi_agent_coding_orchestrator::agent_lifecycle::{AgentLaunchMetadata, AgentRegistry};
use serde_json::Value;
use std::{
    path::Path,
    process::{Child, Command},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

struct SleepChild(Child);

impl SleepChild {
    fn spawn() -> Result<Self> {
        let program = [
            "/run/current-system/sw/bin/sleep",
            "/usr/bin/sleep",
            "/bin/sleep",
        ]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("sleep executable")?;
        Ok(Self(
            Command::new(program)
                .arg("60")
                .spawn()
                .context("spawn sleep")?,
        ))
    }
}

impl Drop for SleepChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn agents_list_and_stop_json_surface_registered_process() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let registry = AgentRegistry::open(temp.path())?;
    let mut child = SleepChild::spawn()?;
    let pid = child.0.id();
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "cli-run", "cli-task")?,
        pid,
        vec!["sleep".to_string(), "60".to_string()],
    )?;

    let list = Command::new(BIN)
        .args([
            "agents",
            "list",
            "--repo",
            temp.path().to_str().context("repo path utf8")?,
            "--run-id",
            "cli-run",
            "--json",
        ])
        .output()
        .context("run agents list")?;
    assert!(
        list.status.success(),
        "agents list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed: Value = serde_json::from_slice(&list.stdout).context("parse agents list JSON")?;
    assert_eq!(listed[0]["pid"], pid);
    assert_eq!(listed[0]["role"], "worker");
    assert_eq!(listed[0]["run_id"], "cli-run");
    assert_eq!(listed[0]["task_id"], "cli-task");
    assert!(listed[0].get("parent").is_none());

    let stop = Command::new(BIN)
        .args([
            "agents",
            "stop",
            &pid.to_string(),
            "--repo",
            temp.path().to_str().context("repo path utf8")?,
            "--wait-seconds",
            "1",
            "--json",
        ])
        .output()
        .context("run agents stop")?;
    assert!(
        stop.status.success(),
        "agents stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let stopped: Value = serde_json::from_slice(&stop.stdout).context("parse agents stop JSON")?;
    assert_eq!(stopped["stopped"][0]["process"]["pid"], pid);
    assert_eq!(stopped["stopped"][0]["outcome"], "terminated");
    assert!(!child.0.wait().context("wait stopped child")?.success());
    Ok(())
}

#[test]
fn agents_list_json_exposes_parent_linkage() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let registry = AgentRegistry::open(temp.path())?;
    let mut child = SleepChild::spawn()?;
    let pid = child.0.id();
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "cli-run", "cli-task")?
            .with_parent("cli-parent")?,
        pid,
        vec!["sleep".to_string(), "60".to_string()],
    )?;

    let list = Command::new(BIN)
        .args([
            "agents",
            "list",
            "--repo",
            temp.path().to_str().context("repo path utf8")?,
            "--run-id",
            "cli-run",
            "--json",
        ])
        .output()
        .context("run agents list")?;
    assert!(
        list.status.success(),
        "agents list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed: Value = serde_json::from_slice(&list.stdout).context("parse agents list JSON")?;
    assert_eq!(listed[0]["pid"], pid);
    assert_eq!(listed[0]["parent"], "cli-parent");
    let _ = child.0.kill();
    Ok(())
}
