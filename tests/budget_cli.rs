#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const RECORD_NAME: &str = "00000000000000000001.json";
const OUTER_CAUSE: &str = "Error: failed to initialize the supervise run budget ledger";
const ROLLING_CAUSE: &str =
    "workspace rolling budget ledger is unavailable or corrupt: workspace rolling budget journal is corrupt or unavailable";

#[test]
fn unreadable_authenticated_rolling_budget_record_fails_closed_with_named_cli_cause() -> Result<()>
{
    let fixture = BudgetCliFixture::seed("unreadable")?;
    let record = fixture.first_record()?;
    fs::set_permissions(&record, fs::Permissions::from_mode(0o000))
        .context("make authenticated rolling-budget record unreadable")?;

    let output = fixture.run("unreadable-reopen")?;
    assert_budget_ledger_refusal(
        output,
        "checkpoint state file is not a bounded private regular file",
    )
}

#[test]
fn authenticated_rolling_budget_record_tamper_fails_closed_with_named_cli_cause() -> Result<()> {
    let fixture = BudgetCliFixture::seed("tamper")?;
    let record = fixture.first_record()?;
    tamper_record_payload_without_resigning(&record)?;

    let output = fixture.run("tamper-reopen")?;
    assert_budget_ledger_refusal(output, "repository authentication tag verification failed")
}

struct BudgetCliFixture {
    _temp: TempDir,
    repo: PathBuf,
    plan: PathBuf,
    machine_global_config: PathBuf,
}

impl BudgetCliFixture {
    fn seed(case: &str) -> Result<Self> {
        let temp = TempDir::new().context("create budget CLI fixture tempdir")?;
        let repo = create_committed_repo(temp.path())?;
        let plan = temp.path().join(format!("{case}-plan.json"));
        write_fake_plan(&plan)?;
        let machine_global_config = write_machine_global_config(temp.path())?;
        let fixture = Self {
            _temp: temp,
            repo,
            plan,
            machine_global_config,
        };

        let output = fixture.run(&format!("{case}-seed"))?;
        if !output.status.success() {
            bail!(
                "failed to seed authenticated rolling-budget journal: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let report: Value = serde_json::from_slice(&output.stdout)
            .context("parse successful fake supervise report")?;
        assert_eq!(report["runtime"], "fake");
        assert_eq!(report["success"], true);
        assert!(fixture.first_record()?.is_file());
        Ok(fixture)
    }

    fn run(&self, run_id: &str) -> Result<Output> {
        Command::new(BIN)
            .args([
                "supervise",
                "run",
                path_str(&self.plan)?,
                "--repo",
                path_str(&self.repo)?,
                "--run-id",
                run_id,
                "--runtime",
                "fake",
                "--max-rolling-tokens",
                "100000",
                "--rolling-window-seconds",
                "3600",
                "--machine-global-config",
                path_str(&self.machine_global_config)?,
                "--machine-global-runtime-root-id",
                "runtime",
                "--json",
            ])
            .env_remove("RUST_LOG")
            .output()
            .context("run fake supervise CLI fixture")
    }

    fn first_record(&self) -> Result<PathBuf> {
        let repository = Repository::open(&self.repo).context("reopen fixture repository")?;
        Ok(repository
            .commondir()
            .join("maco/state/authenticated-budget-ledger-v1/workspace")
            .join(RECORD_NAME))
    }
}

fn assert_budget_ledger_refusal(output: Output, terminal_cause: &str) -> Result<()> {
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "budget-ledger refusal wrote stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr =
        String::from_utf8(output.stderr).context("budget-ledger refusal stderr is UTF-8")?;
    let lines = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            OUTER_CAUSE,
            "Caused by:",
            &format!("{ROLLING_CAUSE}: {terminal_cause}"),
        ]
    );
    Ok(())
}

fn tamper_record_payload_without_resigning(record: &Path) -> Result<()> {
    let original =
        fs::read_to_string(record).context("read authenticated rolling-budget record")?;
    let mut value: Value =
        serde_json::from_str(&original).context("parse rolling-budget record")?;
    let mac = value["mac"]
        .as_str()
        .context("rolling-budget record has a string mac")?
        .to_string();
    if mac.len() != 64
        || !mac
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("rolling-budget record mac is not canonical lowercase hex");
    }
    let original_tokens = value
        .pointer("/payload/tokens")
        .and_then(Value::as_u64)
        .context("rolling-budget record payload has numeric tokens")?;
    let tampered_tokens = original_tokens
        .checked_add(1)
        .context("rolling-budget record token tamper overflowed")?;
    value["payload"]["tokens"] = Value::from(tampered_tokens);
    assert_eq!(value["mac"], mac);

    fs::write(record, serde_json::to_vec(&value)?)
        .context("tamper rolling-budget payload without resigning")?;
    let rewritten = fs::read(record).context("reread tampered rolling-budget record")?;
    let reparsed: Value = serde_json::from_slice(&rewritten)
        .context("tampered rolling-budget record remains JSON")?;
    assert_eq!(reparsed["payload"]["tokens"], tampered_tokens);
    assert_eq!(reparsed["mac"], mac);
    assert_eq!(
        fs::metadata(record)?.permissions().mode() & 0o777,
        0o600,
        "tampered rolling-budget record must remain a bounded private regular file"
    );
    Ok(())
}

fn write_fake_plan(path: &Path) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "task": "seed authenticated rolling-budget journal",
            "max_child_assignments": 1,
            "assignments": [{
                "id": "deterministic-child",
                "phase": "execution",
                "assigned_paths": ["README.md"],
                "worker_assignments": []
            }]
        }))?,
    )
    .context("write deterministic fake supervise plan")
}

fn write_machine_global_config(root: &Path) -> Result<PathBuf> {
    let state_root = root.join("machine-global-state");
    fs::create_dir(&state_root).context("create machine-global state root")?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .context("secure machine-global state root")?;
    let uid = fs::metadata("/proc/self")?.uid();
    let config = root.join("machine-global.json");
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
    )
    .context("write machine-global config")?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .context("secure machine-global config")?;
    Ok(config)
}

fn create_committed_repo(root: &Path) -> Result<PathBuf> {
    let repo = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_str(&repo)?, "--json"])
        .env_remove("RUST_LOG")
        .output()
        .context("initialize budget CLI fixture repository")?;
    if !output.status.success() {
        bail!(
            "fixture repository init failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::create_dir(repo.join("src")).context("create fixture source directory")?;
    fs::write(repo.join(".gitignore"), ".maco/\n")?;
    fs::write(repo.join("README.md"), "# Budget CLI fixture\n")?;
    fs::write(repo.join("src/lib.rs"), "pub fn ok() -> bool { true }\n")?;
    commit_all(&Repository::open(&repo)?, "initial budget CLI fixture")?;
    Ok(repo)
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
    .context("commit budget CLI fixture")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}
