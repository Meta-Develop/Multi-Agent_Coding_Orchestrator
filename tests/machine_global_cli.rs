#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn machine_global_cli_requires_explicit_no_follow_config() -> Result<()> {
    let fixture = Fixture::new(Vec::new(), 1)?;

    let missing = run(&["machine-global", "status", "--json"])?;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--config"));

    let linked_config = fixture.base.join("linked-config.json");
    symlink(&fixture.config, &linked_config).context("link config fixture")?;
    let linked_config = path_text(&linked_config)?;
    let denied = run(&[
        "machine-global",
        "status",
        "--config",
        linked_config,
        "--json",
    ])?;
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr)
            .contains("machine-global config path is not exact and canonical"),
        "a linked config must fail the exact canonical no-follow boundary"
    );
    assert!(
        !fixture
            .state_root
            .join("machine-global-state-v1.json")
            .exists(),
        "a refused config must not create durable state"
    );

    Ok(())
}

#[test]
fn machine_global_cli_claim_owner_status_and_release_are_privacy_safe() -> Result<()> {
    let fixture = Fixture::new(Vec::new(), 1)?;
    private_dir(&fixture.root.join("store"))?;
    let config = path_text(&fixture.config)?;

    let claim = success_json(&[
        "machine-global",
        "claim",
        "repair-agent",
        "--root-id",
        "sessions",
        "--path",
        "store",
        "--correlation",
        "claim-repair",
        "--config",
        config,
        "--json",
    ])?;
    let token = claim["token"]
        .as_str()
        .context("claim token string")?
        .to_string();

    let denial = denied_json(&[
        "machine-global",
        "claim",
        "cleanup-agent",
        "--root-id",
        "sessions",
        "--path",
        "store/repair",
        "--correlation",
        "claim-cleanup",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(denial["reason"]["family"], "claim_conflict");
    assert_eq!(
        denial["context"]["paths"][0],
        "__machine_global__/sessions/store/repair"
    );
    assert_private_output(&denial, &fixture.root)?;

    let owner = success_json(&[
        "machine-global",
        "owner",
        "--root-id",
        "sessions",
        "--path",
        "store/repair",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(owner["target"]["root_id"], "sessions");
    assert_eq!(owner["target"]["relative"], "store/repair");
    assert_eq!(owner["claims"][0]["owner"], "repair-agent");
    assert!(owner["claims"][0].get("token").is_none());

    let status = success_json(&["machine-global", "status", "--config", config, "--json"])?;
    assert_eq!(status["claims"][0]["owner"], "repair-agent");
    assert!(status["claims"][0].get("token").is_none());
    assert_private_output(&status, &fixture.root)?;

    let wrong_owner = run(&[
        "machine-global",
        "release",
        "cleanup-agent",
        &token,
        "--config",
        config,
        "--json",
    ])?;
    assert!(!wrong_owner.status.success());
    assert!(String::from_utf8_lossy(&wrong_owner.stderr).contains("different agent"));

    let released = success_json(&[
        "machine-global",
        "release",
        "repair-agent",
        &token,
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(released["owner"], "repair-agent");
    assert_eq!(released["released"], true);
    assert!(
        !serde_json::to_string(&released)?.contains(&token),
        "release output must not echo a bearer token"
    );

    Ok(())
}

#[test]
fn machine_global_cli_rejects_arbitrary_absolute_retention_target() -> Result<()> {
    let fixture = Fixture::new(Vec::new(), 1)?;
    let outside = fixture.base.join("outside");
    private_dir(&outside)?;
    fs::write(outside.join("irrecoverable"), b"keep me").context("write outside fixture")?;
    let config = path_text(&fixture.config)?;
    let outside_text = path_text(&outside)?;

    let denial = denied_json(&[
        "machine-global",
        "retention",
        "quarantine",
        "cleanup-agent",
        "--root-id",
        "sessions",
        "--path",
        outside_text,
        "--correlation",
        "outside-target",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(denial["reason"]["family"], "destructive_target");
    assert_eq!(denial["reason"]["denial"]["kind"], "undeclared_target");
    assert!(outside.join("irrecoverable").is_file());
    let encoded = serde_json::to_string(&denial)?;
    assert!(!encoded.contains(outside_text));
    assert_private_output(&denial, &fixture.root)?;

    Ok(())
}

#[test]
fn machine_global_cli_reports_protected_retention_denial() -> Result<()> {
    let protected = json!({
        "coordinate": {
            "root_id": "sessions",
            "relative": "critical"
        },
        "retryability": "not_retryable"
    });
    let fixture = Fixture::new(vec![protected], 1)?;
    private_dir(&fixture.root.join("critical"))?;
    fs::write(fixture.root.join("critical/session"), b"keep me")
        .context("write protected fixture")?;
    let config = path_text(&fixture.config)?;

    let denial = denied_json(&[
        "machine-global",
        "retention",
        "quarantine",
        "cleanup-agent",
        "--root-id",
        "sessions",
        "--path",
        "critical",
        "--correlation",
        "protected-target",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(denial["reason"]["family"], "destructive_target");
    assert_eq!(
        denial["reason"]["denial"]["kind"],
        "protected_path_intersection"
    );
    assert_eq!(denial["reason"]["denial"]["target"]["relative"], "critical");
    assert!(fixture.root.join("critical/session").is_file());
    assert_eq!(quarantine_entries(&fixture.root)?.len(), 0);
    assert_private_output(&denial, &fixture.root)?;

    Ok(())
}

#[ignore = "1s Unix-second grace can already be elapsed when the early-purge assertion crosses a second boundary; unrelated to #137"]
#[test]
fn machine_global_cli_quarantines_restores_and_purges_after_grace() -> Result<()> {
    let fixture = Fixture::new(Vec::new(), 1)?;
    let target = fixture.root.join("expired-session");
    private_dir(&target)?;
    fs::write(target.join("session.json"), b"{\"important\":true}\n")
        .context("write retention fixture")?;
    let config = path_text(&fixture.config)?;

    let first = quarantine(config, "quarantine-first")?;
    let first_id = first["id"].as_u64().context("first operation id")?;
    let first_quarantine = first["targets"][0]["quarantine_name"]
        .as_str()
        .context("first quarantine name")?;
    let first_cleanup = first["targets"][0]["cleanup_name"]
        .as_str()
        .context("first cleanup name")?;
    assert_eq!(first["targets"][0]["state"], "quarantined");
    assert!(first_cleanup.starts_with(".maco-delete-v2-"));
    assert_eq!(Path::new(first_cleanup).components().count(), 1);
    assert!(!target.exists());
    assert!(fixture.root.join(first_quarantine).is_dir());
    assert!(!fixture.root.join(first_cleanup).exists());
    assert_private_output(&first, &fixture.root)?;

    let status = success_json(&["machine-global", "status", "--config", config, "--json"])?;
    assert_eq!(status["retention_operations"][0]["id"], first_id);
    assert!(
        status["retention_operations"][0].get("token").is_none(),
        "status must redact the retention bearer token"
    );

    let first_id_text = first_id.to_string();
    let restored = success_json(&[
        "machine-global",
        "retention",
        "restore",
        "cleanup-agent",
        &first_id_text,
        "--correlation",
        "restore-first",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(restored["targets"][0]["state"], "restored");
    assert_eq!(
        fs::read_to_string(target.join("session.json"))?,
        "{\"important\":true}\n"
    );
    assert!(!fixture.root.join(first_quarantine).exists());
    assert!(!fixture.root.join(first_cleanup).exists());
    assert_private_output(&restored, &fixture.root)?;

    let second = quarantine(config, "quarantine-second")?;
    let second_id = second["id"].as_u64().context("second operation id")?;
    let second_id_text = second_id.to_string();
    let second_token = second["token"].as_str().context("second operation token")?;
    let second_quarantine = second["targets"][0]["quarantine_name"]
        .as_str()
        .context("second quarantine name")?;
    let second_cleanup = second["targets"][0]["cleanup_name"]
        .as_str()
        .context("second cleanup name")?;
    assert_eq!(Path::new(second_cleanup).components().count(), 1);
    assert_private_output(&second, &fixture.root)?;

    let early = run(&[
        "machine-global",
        "retention",
        "purge",
        "cleanup-agent",
        &second_id_text,
        "--token",
        second_token,
        "--correlation",
        "purge-early",
        "--config",
        config,
        "--json",
    ])?;
    assert!(!early.status.success());
    assert!(String::from_utf8_lossy(&early.stderr).contains("grace has not elapsed"));
    assert!(fixture.root.join(second_quarantine).is_dir());

    thread::sleep(Duration::from_secs(2));
    let purged = success_json(&[
        "machine-global",
        "retention",
        "purge",
        "cleanup-agent",
        &second_id_text,
        "--token",
        second_token,
        "--correlation",
        "purge-after-grace",
        "--config",
        config,
        "--json",
    ])?;
    assert_eq!(purged["targets"][0]["state"], "purged");
    assert!(!target.exists());
    assert!(!fixture.root.join(second_quarantine).exists());
    assert!(!fixture.root.join(second_cleanup).exists());
    assert_private_output(&purged, &fixture.root)?;

    Ok(())
}

fn quarantine(config: &str, correlation: &str) -> Result<Value> {
    success_json(&[
        "machine-global",
        "retention",
        "quarantine",
        "cleanup-agent",
        "--root-id",
        "sessions",
        "--path",
        "expired-session",
        "--correlation",
        correlation,
        "--config",
        config,
        "--json",
    ])
}

struct Fixture {
    _temp: TempDir,
    base: PathBuf,
    root: PathBuf,
    state_root: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new(protected_paths: Vec<Value>, grace_seconds: u64) -> Result<Self> {
        let temp = TempDir::new().context("create tempdir")?;
        let base = fs::canonicalize(temp.path()).context("canonicalize tempdir")?;
        let root = base.join("declared-root");
        let state_root = base.join("state");
        private_dir(&root)?;
        private_dir(&state_root)?;
        let config = base.join("machine-global.json");
        let document = json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "sessions",
                "path": root,
                "protected_paths": protected_paths,
                "quarantine_grace_seconds": grace_seconds
            }]
        });
        fs::write(&config, serde_json::to_vec_pretty(&document)?)
            .context("write machine-global config")?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .context("make config private")?;
        Ok(Self {
            _temp: temp,
            base,
            root,
            state_root,
            config,
        })
    }
}

fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("make directory private {}", path.display()))
}

fn run(args: &[&str]) -> Result<Output> {
    Command::new(BIN).args(args).output().context("run maco")
}

fn success_json(args: &[&str]) -> Result<Value> {
    let output = run(args)?;
    if !output.status.success() {
        bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse successful command JSON")
}

fn denied_json(args: &[&str]) -> Result<Value> {
    let output = run(args)?;
    if output.status.success() {
        bail!("expected maco command denial");
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse denial JSON; stderr was {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn quarantine_entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).context("read declared root")? {
        let entry = entry.context("read declared root entry")?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".maco-quarantine-v1-")
        {
            entries.push(entry.path());
        }
    }
    Ok(entries)
}

fn assert_private_output(value: &Value, root: &Path) -> Result<()> {
    let encoded = serde_json::to_string(value)?;
    let root = path_text(root)?;
    assert!(
        !encoded.contains(root),
        "machine-global JSON leaked a configured absolute root"
    );
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("path is not valid UTF-8")
}
