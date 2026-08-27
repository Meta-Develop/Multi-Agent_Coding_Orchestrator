use anyhow::{Context, Result};
use git2::Repository;
use multi_agent_coding_orchestrator::agent_lifecycle::{
    AgentLaunchMetadata, AgentListFilter, AgentRegistry,
};
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

fn codex_argv(model: &str) -> Vec<String> {
    vec![
        "codex".to_string(),
        "exec".to_string(),
        "-m".to_string(),
        model.to_string(),
        "-".to_string(),
    ]
}

#[test]
fn agents_list_exposes_launch_time_authority_binding() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let registry = AgentRegistry::open(temp.path())?;
    let child = SleepChild::spawn()?;
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "auditor", "authority-run", "audit-task")?
            .with_parent("parent-o1")?,
        child.0.id(),
        codex_argv("gpt-5.6-sol"),
    )?;

    let output = Command::new(BIN)
        .args([
            "agents",
            "list",
            "--repo",
            temp.path().to_str().context("repo path utf8")?,
            "--run-id",
            "authority-run",
            "--json",
        ])
        .output()
        .context("run agents list")?;
    assert!(
        output.status.success(),
        "agents list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: Value = serde_json::from_slice(&output.stdout).context("parse agents list")?;
    let authority = &listed["agents"][0]["launch_authority"];
    assert_eq!(authority["category"], "read_only_review_auditor");
    assert_eq!(authority["requested_model"], "gpt-5.6-sol");
    assert_eq!(authority["model_capability"], "critical_judgment");
    assert_eq!(authority["may_delegate"], false);
    assert_eq!(authority["may_write"], false);
    assert_eq!(authority["may_judge_acceptance"], true);
    assert_eq!(authority["may_mutate_git_history"], false);
    assert_eq!(authority["probe_only"], false);
    Ok(())
}

#[test]
fn lifecycle_refuses_luna_for_coordinator_and_auditor_authority() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let registry = AgentRegistry::open(temp.path())?;

    for role in ["child_orchestrator", "auditor"] {
        let child = SleepChild::spawn()?;
        let error = registry
            .register(
                &AgentLaunchMetadata::new(temp.path(), role, "weak-run", role)?,
                child.0.id(),
                codex_argv("gpt-5.6-luna"),
            )
            .expect_err("weak model must not receive coordinator or audit authority");
        let message = format!("{error:#}");
        assert!(
            message.contains("ineligible by measured catalog/evidence")
                || message.contains("does not satisfy role"),
            "{message}"
        );
    }
    assert!(registry.list(&AgentListFilter::default())?.is_empty());
    Ok(())
}

#[test]
fn version_probe_carries_no_agent_authority() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let registry = AgentRegistry::open(temp.path())?;
    let child = SleepChild::spawn()?;
    let record = registry.register(
        &AgentLaunchMetadata::new(temp.path(), "child_orchestrator", "probe-run", "probe-task")?,
        child.0.id(),
        vec!["codex".to_string(), "--version".to_string()],
    )?;
    let encoded = serde_json::to_value(record)?;
    assert_eq!(encoded["launch_authority"]["probe_only"], true);
    assert_eq!(encoded["launch_authority"]["may_delegate"], false);
    assert_eq!(encoded["launch_authority"]["may_write"], false);
    assert_eq!(encoded["launch_authority"]["may_judge_acceptance"], false);
    assert_eq!(encoded["launch_authority"]["may_mutate_git_history"], false);
    Ok(())
}
