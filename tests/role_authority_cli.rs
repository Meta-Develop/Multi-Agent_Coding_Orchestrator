use anyhow::{Context, Result};
use git2::{IndexAddOption, Repository, Signature};
use multi_agent_coding_orchestrator::agent_lifecycle::{
    AgentLaunchMetadata, AgentListFilter, AgentRegistry,
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output},
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

#[test]
fn fake_goal_launch_returns_automatic_authority_and_derived_shape() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = create_committed_autopilot_repo(temp.path())?;
    let goal = temp.path().join("goal.md");
    fs::write(
        &goal,
        "Coordinate repository work.\n- Update README.md.\n- Update src/lib.rs.\n",
    )?;
    let output = run_autopilot_cli(
        &repo,
        &[
            "autopilot",
            "run",
            "--from-goal",
            path_text(&goal)?,
            "--repo",
            path_text(&repo)?,
            "--run-id",
            "authority-goal-run",
            "--json",
        ],
    )?;
    assert!(
        output.status.success(),
        "goal launch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).context("parse goal report")?;
    let authority = &report["authority_plan"];
    assert_eq!(authority["selection_source"], "effective_planner_output");
    assert_eq!(authority["caller_selected_category"], false);
    assert_eq!(authority["caller_selected_coordination_depth"], false);
    assert!(authority["planned_max_depth"]
        .as_u64()
        .is_some_and(|depth| depth >= 2));
    assert!(authority["derived_coordination_depth"]
        .as_u64()
        .is_some_and(|depth| depth >= 1));
    let assignments = authority["assignments"]
        .as_array()
        .context("authority assignments")?;
    assert!(!assignments.is_empty());
    assert!(assignments
        .iter()
        .all(|entry| entry["category"].is_string()));
    assert!(assignments
        .iter()
        .all(|entry| entry["may_mutate_git_history"] == false));
    assert!(assignments.iter().any(|entry| {
        entry["category"] == "read_only_review_auditor"
            && entry["may_judge_acceptance"] == true
            && entry["may_write"] == false
    }));
    Ok(())
}

#[test]
fn fake_autopilot_refuses_luna_delegation_before_supervisor_dispatch() -> Result<()> {
    assert_fake_authority_refusal(
        "luna-delegation-refusal",
        None,
        Some(
            r#"{
              "version": 1,
              "role_models": {
                "child_orchestrator": {"model": "gpt-5.6-luna"}
              }
            }"#,
        ),
        "model_ineligible_for_delegating_coordinator",
    )
}

#[test]
fn fake_autopilot_refuses_luna_auditor_before_supervisor_dispatch() -> Result<()> {
    assert_fake_authority_refusal(
        "luna-auditor-refusal",
        None,
        Some(
            r#"{
              "version": 1,
              "review_lenses": [{
                "id": "weak-auditor",
                "backend": {
                  "kind": "model",
                  "backend_id": "openai",
                  "model": "gpt-5.6-luna",
                  "reasoning_effort": "xhigh"
                },
                "information_scope": "diff_only"
              }]
            }"#,
        ),
        "model_ineligible_for_review_auditor",
    )
}

#[test]
fn fake_autopilot_git_forge_does_not_grant_history_authority() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = create_committed_autopilot_repo(temp.path())?;
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
    let output = run_autopilot_cli(
        &repo,
        &[
            "autopilot",
            "run",
            path_text(&plan)?,
            "--repo",
            path_text(&repo)?,
            "--run-id",
            "git-authority-binding",
            "--json",
        ],
    )?;
    let report: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse git-authority report; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    let authority = &report["authority_plan"];
    assert_eq!(authority["forge_mode"], "git");
    assert_eq!(authority["git_history_mutation_granted"], false);
    assert_ne!(authority["refusal_reason"], "git_authority_unbound");
    let assignments = authority["assignments"]
        .as_array()
        .context("git-authority assignments")?;
    assert!(!assignments.is_empty());
    assert!(assignments
        .iter()
        .all(|entry| entry["may_mutate_git_history"] == false));
    Ok(())
}

fn assert_fake_authority_refusal(
    run_id: &str,
    extra_plan_field: Option<&str>,
    profile: Option<&str>,
    expected_reason: &str,
) -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = create_committed_autopilot_repo(temp.path())?;
    let plan = temp.path().join("authority-plan.json");
    fs::write(
        &plan,
        format!(
            r#"{{
              "version": 1,
              "task": {{"title": "Authority refusal", "body": "Refuse before dispatch."}},
              {} 
              "assigned_paths": ["README.md"]
            }}"#,
            extra_plan_field.unwrap_or("")
        ),
    )?;
    let profile_path = profile
        .map(|contents| {
            let path = temp.path().join("authority-profile.json");
            fs::write(&path, contents).map(|()| path)
        })
        .transpose()?;
    let mut args = vec![
        "autopilot",
        "run",
        path_text(&plan)?,
        "--repo",
        path_text(&repo)?,
    ];
    if let Some(profile_path) = &profile_path {
        args.extend(["--profile", path_text(profile_path)?]);
    }
    args.extend(["--run-id", run_id, "--json"]);
    let output = run_autopilot_cli(&repo, &args)?;
    assert!(
        !output.status.success(),
        "authority-unsafe Fake run unexpectedly succeeded"
    );
    let report: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse authority refusal; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    assert_eq!(report["status"], "refused");
    assert_eq!(report["attempt_count"], 0);
    assert_eq!(report["authority_plan"]["refusal_reason"], expected_reason);
    assert!(!repo
        .join(format!(".maco/o2/runs/{run_id}-supervise"))
        .exists());
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

fn run_autopilot_cli(repo: &Path, args: &[&str]) -> Result<Output> {
    let fixture_root = repo.parent().context("fixture root")?;
    let child_tmp = fixture_root.join("autopilot-child-tmp");
    fs::create_dir_all(&child_tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&child_tmp, fs::Permissions::from_mode(0o700))?;
    }
    let config = write_machine_global_fixture(repo)?;
    Command::new(BIN)
        .args(args)
        .args([
            "--machine-global-config",
            path_text(&config)?,
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .env("TMPDIR", child_tmp)
        .env_remove("MACO_BOUNDED_STATUS_RUNTIME_ROOT")
        .output()
        .context("run autopilot CLI")
}

#[cfg(target_os = "linux")]
fn write_machine_global_fixture(repo: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture_root = repo.parent().context("fixture root")?;
    let state_root = fixture_root.join("machine-global-state");
    fs::create_dir_all(&state_root)?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))?;
    let uid = fs::metadata("/proc/self")?.uid();
    let config = fixture_root.join("machine-global.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": format!("/run/user/{uid}"),
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))?,
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    Ok(config)
}

#[cfg(not(target_os = "linux"))]
fn write_machine_global_fixture(repo: &Path) -> Result<PathBuf> {
    Ok(repo.join("unsupported-machine-global.json"))
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
