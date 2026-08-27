#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::{json, Value};
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

#[test]
fn json_plan_inventory_failure_emits_structured_error_envelope_on_stdout() -> Result<()> {
    let temp = TempDir::new().context("create inventory-failure CLI fixture tempdir")?;
    let repo = create_committed_repo(temp.path())?;
    let repository = Repository::open(&repo).context("open inventory-failure repository")?;
    let alternates = repository.path().join("objects/info/alternates");
    fs::create_dir_all(alternates.parent().context("alternates parent")?)
        .context("create objects/info for untrusted alternates")?;
    fs::write(&alternates, "/untrusted/object-store\n")
        .context("write untrusted Git object alternates")?;
    let task = temp.path().join("failed-inventory-task.md");
    fs::write(&task, "Update README.md.\n").context("write inventory-failure task")?;

    let output = Command::new(BIN)
        .args([
            "supervise",
            "plan",
            path_str(&task)?,
            "--repo",
            path_str(&repo)?,
            "--json",
        ])
        .env_remove("RUST_LOG")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
        .output()
        .context("run supervise plan --json inventory failure")?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).context("inventory-failure stderr is UTF-8")?;
    assert!(
        stderr.contains("repository inventory failed")
            && stderr.contains("bounded-status rejects Git object alternates"),
        "inventory failure must keep the full error chain on stderr: {stderr}"
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse inventory-failure JSON envelope: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    assert_eq!(envelope["success"], false);
    assert_eq!(envelope["status"], "error");
    let top = envelope["error"]
        .as_str()
        .context("envelope error string")?;
    let causes = envelope["causes"]
        .as_array()
        .context("envelope causes array")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let chain = std::iter::once(top)
        .chain(causes.iter().copied())
        .collect::<Vec<_>>();
    assert!(
        chain
            .iter()
            .any(|text| text.contains("repository inventory failed")),
        "envelope chain should name the inventory failure: {envelope}"
    );
    assert!(
        chain
            .iter()
            .any(|text| text.contains("bounded-status rejects Git object alternates")),
        "envelope chain should retain the Git alternates cause: {envelope}"
    );
    Ok(())
}

#[test]
fn fake_backed_multi_assignment_plan_run_completes_under_cli_token_ceiling() -> Result<()> {
    let temp = TempDir::new().context("create fake-backed ceiling CLI fixture tempdir")?;
    let repo = create_committed_repo(temp.path())?;
    let plan = temp.path().join("ceiling-plan.json");
    write_fake_ceiling_plan(&plan)?;
    let machine_global_config = write_machine_global_config(temp.path())?;

    let output = Command::new(BIN)
        .args([
            "supervise",
            "run",
            path_str(&plan)?,
            "--repo",
            path_str(&repo)?,
            "--run-id",
            "fake-ceiling-complete",
            "--runtime",
            "fake",
            "--max-tokens",
            "100000",
            "--max-concurrent-children",
            "1",
            "--machine-global-config",
            path_str(&machine_global_config)?,
            "--machine-global-runtime-root-id",
            "runtime",
            "--json",
        ])
        .env_remove("RUST_LOG")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
        .output()
        .context("run fake-backed plan under CLI token ceiling")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!("parse fake-backed ceiling run JSON: stdout={stdout} stderr={stderr}")
    })?;
    assert_eq!(report["runtime"], "fake");
    assert_eq!(
        report["success"], true,
        "fake-backed plan→run under a hard CLI ceiling must complete: {report} stderr={stderr}"
    );
    let started = report["role_economics_profile"]["execution"]["started_assignment_count"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        started >= 2,
        "both fake-backed assignments must start under the ceiling: {report}"
    );
    if let Some(reasons) = report["run_budget"]["reasons"].as_array() {
        assert!(
            !reasons
                .iter()
                .any(|reason| reason == "missing_provider_usage"),
            "fake-backed usage must not fail closed as missing_provider_usage: {report}"
        );
    }
    Ok(())
}

#[test]
fn sequential_fake_supervise_processes_exhaust_rolling_quota_then_refuse() -> Result<()> {
    let probe = BudgetCliFixture::new_unseeded("exhaust-probe")?;
    let first_probe = probe.run_with_rolling("probe-run", "100000")?;
    assert!(
        first_probe.status.success(),
        "probe fake-backed supervise process must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&first_probe.stdout),
        String::from_utf8_lossy(&first_probe.stderr)
    );
    let probe_report: Value =
        serde_json::from_slice(&first_probe.stdout).context("parse probe supervise report")?;
    let per_run = probe_report["run_budget"]["consumed"]["tokens"]
        .as_u64()
        .context("probe consumed tokens")?;
    assert!(
        per_run > 0,
        "probe fake-backed run must consume rolling tokens: {probe_report}"
    );

    let exact = per_run
        .checked_mul(2)
        .context("exact two-process rolling quota overflowed")?;
    let fixture = BudgetCliFixture::new_unseeded("exhaust")?;
    let first = fixture.run_with_rolling("exhaust-1", &exact.to_string())?;
    assert_successful_fake_supervise(first, "first exhaustion process")?;
    let second = fixture.run_with_rolling("exhaust-2", &exact.to_string())?;
    assert_successful_fake_supervise(second, "second exhaustion process")?;

    let refused = fixture.run_with_rolling("exhaust-3", &exact.to_string())?;
    assert_eq!(
        refused.status.code(),
        Some(1),
        "process after exact exhaustion must exit nonzero"
    );
    let refused_report: Value = serde_json::from_slice(&refused.stdout).with_context(|| {
        format!(
            "parse exhausted supervise JSON: stdout={} stderr={}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        )
    })?;
    assert_eq!(refused_report["success"], false);
    let reasons = refused_report["run_budget"]["reasons"]
        .as_array()
        .context("exhausted run_budget.reasons")?;
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "hard_token_ceiling_reached"),
        "next independent process must be refused with hard_token_ceiling_reached: {refused_report}"
    );
    Ok(())
}

struct BudgetCliFixture {
    _temp: TempDir,
    repo: PathBuf,
    plan: PathBuf,
    machine_global_config: PathBuf,
}

impl BudgetCliFixture {
    fn new_unseeded(case: &str) -> Result<Self> {
        let temp = TempDir::new().context("create budget CLI fixture tempdir")?;
        let repo = create_committed_repo(temp.path())?;
        let plan = temp.path().join(format!("{case}-plan.json"));
        write_fake_plan(&plan)?;
        let machine_global_config = write_machine_global_config(temp.path())?;
        Ok(Self {
            _temp: temp,
            repo,
            plan,
            machine_global_config,
        })
    }

    fn seed(case: &str) -> Result<Self> {
        let fixture = Self::new_unseeded(case)?;
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
        self.run_with_rolling(run_id, "100000")
    }

    fn run_with_rolling(&self, run_id: &str, max_rolling_tokens: &str) -> Result<Output> {
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
                max_rolling_tokens,
                "--rolling-window-seconds",
                "3600",
                "--machine-global-config",
                path_str(&self.machine_global_config)?,
                "--machine-global-runtime-root-id",
                "runtime",
                "--json",
            ])
            .env_remove("RUST_LOG")
            .env_remove("RUST_BACKTRACE")
            .env_remove("RUST_LIB_BACKTRACE")
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
        serde_json::to_vec_pretty(&json!({
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

fn write_fake_ceiling_plan(path: &Path) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "task": "complete fake-backed plan under a hard CLI ceiling",
            "max_child_assignments": 2,
            "run_budget": {
                "role_token_reservations": {
                    "child_orchestrator": 1024,
                    "auditor": 1024,
                    "worker": 1024
                }
            },
            "assignments": [
                {
                    "id": "ceiling-child-readme",
                    "phase": "execution",
                    "assigned_paths": ["README.md"],
                    "worker_assignments": []
                },
                {
                    "id": "ceiling-child-lib",
                    "phase": "execution",
                    "assigned_paths": ["src/lib.rs"],
                    "worker_assignments": []
                }
            ]
        }))?,
    )
    .context("write fake-backed CLI ceiling plan")
}

fn assert_successful_fake_supervise(output: Output, label: &str) -> Result<()> {
    if !output.status.success() {
        bail!(
            "{label} unexpectedly failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let report: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse {label} fake supervise report"))?;
    assert_eq!(report["runtime"], "fake");
    assert_eq!(
        report["success"], true,
        "{label} must succeed before exact rolling exhaustion: {report}"
    );
    Ok(())
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
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE")
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
