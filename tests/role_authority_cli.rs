use anyhow::{Context, Result};
use git2::{IndexAddOption, Repository, Signature};
use multi_agent_coding_orchestrator::agent_lifecycle::{
    AgentLaunchMetadata, AgentListFilter, AgentRegistry,
};
use multi_agent_coding_orchestrator::supervise::{admit_role_category, RoleCategory};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const RETIRED_AUTOPILOT_MESSAGE: &str =
    "autopilot plan/run is retired; use literal instruction routing: maco <instruction>";

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

#[test]
fn fake_goal_launch_returns_automatic_authority_and_derived_shape() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = create_committed_autopilot_repo(temp.path())?;
    let goal = temp.path().join("goal.md");
    fs::write(
        &goal,
        "Coordinate repository work.\n- Update README.md.\n- Update src/lib.rs.\n",
    )?;
    let output = Command::new(BIN)
        .args([
            "supervise",
            "plan",
            "--from-goal",
            path_text(&goal)?,
            "--repo",
            path_text(&repo)?,
            "--json",
        ])
        .output()
        .context("plan goal through active supervise entrypoint")?;
    assert!(
        output.status.success(),
        "goal planning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value =
        serde_json::from_slice(&output.stdout).context("parse supervise goal plan")?;
    let topology = &plan["coordination_topology"];
    assert_eq!(topology["caller_selected_coordination_depth"], false);
    assert_eq!(topology["planned_max_depth"], plan["max_depth"]);
    assert!(topology["planned_max_depth"]
        .as_u64()
        .is_some_and(|depth| depth >= 2));
    assert!(topology["derived_coordination_depth"]
        .as_u64()
        .is_some_and(|depth| depth >= 1));
    let assignments = plan["assignments"]
        .as_array()
        .context("supervise assignments")?;
    assert!(!assignments.is_empty());
    assert!(assignments
        .iter()
        .all(|entry| entry["role_category"] == "delegating_coordinator"));
    assert!(assignments
        .iter()
        .all(|entry| entry.get("selection_source").is_none()));
    assert!(assignments.iter().any(|entry| entry["phase"] == "planning"));
    assert!(assignments
        .iter()
        .any(|entry| entry["phase"] == "execution"));
    let workers = assignments
        .iter()
        .filter_map(|entry| entry["worker_assignments"].as_array())
        .flatten()
        .collect::<Vec<_>>();
    assert!(!workers.is_empty());
    assert!(workers
        .iter()
        .all(|worker| worker["role_category"] == "non_delegating_terminal_worker"));
    assert!(workers
        .iter()
        .all(|worker| worker.get("selection_source").is_none()));
    assert!(plan["review_lenses"]
        .as_array()
        .is_some_and(|lenses| !lenses.is_empty()));
    assert!(RoleCategory::ReadOnlyReviewAuditor.is_read_only());
    assert!(!RoleCategory::ReadOnlyReviewAuditor.may_delegate());
    assert!(!RoleCategory::ReadOnlyReviewAuditor.may_write());
    assert!(RoleCategory::ReadOnlyReviewAuditor.may_judge_acceptance());
    Ok(())
}

#[test]
fn fake_autopilot_refuses_luna_delegation_before_supervisor_dispatch() {
    let error = admit_role_category(RoleCategory::DelegatingCoordinator, Some("gpt-5.6-luna"))
        .expect_err("luna must not receive delegating coordinator authority");
    let message = format!("{error:#}");
    assert!(
        message.contains("delegating_coordinator")
            && (message.contains("ineligible by measured catalog/evidence")
                || message.contains("cannot hold")),
        "{message}"
    );
}

#[test]
fn fake_autopilot_refuses_luna_auditor_before_supervisor_dispatch() {
    let error = admit_role_category(RoleCategory::ReadOnlyReviewAuditor, Some("gpt-5.6-luna"))
        .expect_err("luna must not receive review auditor authority");
    let message = format!("{error:#}");
    assert!(
        message.contains("read_only_review_auditor")
            && (message.contains("ineligible by measured catalog/evidence")
                || message.contains("cannot hold")
                || message.contains("below floor")),
        "{message}"
    );
}

#[test]
fn fake_autopilot_git_forge_does_not_grant_history_authority() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = create_committed_autopilot_repo(temp.path())?;
    let repository = Repository::open(&repo)?;
    let head_before = repository.head()?.target().context("HEAD target")?;
    let index_before = fs::read(repository.path().join("index"))?;
    drop(repository);
    let plan = temp.path().join("authority-plan.json");
    fs::write(
        &plan,
        r#"{
          "version": 1,
          "task": {"title": "Git authority", "body": "Do not grant history mutation."},
          "forge_mode": "git",
          "assigned_paths": ["README.md"]
        }"#,
    )?;
    let output = Command::new(BIN)
        .args([
            "autopilot",
            "run",
            path_text(&plan)?,
            "--repo",
            path_text(&repo)?,
            "--run-id",
            "git-authority-binding",
            "--json",
        ])
        .output()
        .context("run retired autopilot git forge")?;
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "retirement must not emit a run report"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(RETIRED_AUTOPILOT_MESSAGE), "{stderr}");
    assert!(!stderr.contains("Usage:"), "{stderr}");

    let repository = Repository::open(&repo)?;
    assert_eq!(repository.head()?.target(), Some(head_before));
    assert_eq!(fs::read(repository.path().join("index"))?, index_before);
    assert!(repository.statuses(None)?.is_empty());
    assert!(!repo.join(".maco").exists());
    Ok(())
}

fn create_committed_autopilot_repo(root: &Path) -> Result<PathBuf> {
    let repo = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_text(&repo)?, "--json"])
        .output()
        .context("initialize fixture repository")?;
    if !output.status.success() {
        anyhow::bail!(
            "fixture init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::create_dir_all(repo.join("src"))?;
    fs::write(repo.join(".gitignore"), ".maco/\n")?;
    fs::write(repo.join("README.md"), "# Authority fixture\n")?;
    fs::write(repo.join("src/lib.rs"), "pub fn ok() -> bool { true }\n")?;
    let repository = Repository::open(&repo)?;
    let mut config = repository.config()?;
    config.set_str("user.name", "maco test")?;
    config.set_str("user.email", "maco-test@example.invalid")?;
    let mut index = repository.index()?;
    index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repository.find_tree(tree_id)?;
    let signature = Signature::now("maco test", "maco-test@example.invalid")?;
    repository.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
    drop(tree);
    drop(repository);
    Ok(repo)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
