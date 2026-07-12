use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn parses_old_format_existing_claim_files() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_claim(
        repo,
        "old-active",
        r#"# Claim: old-active

- Owner: `worker-a`
- Date: `2026-05-19`
- Status: `active`
- Owned files, regions, devices, or services:
  - `src/cli.rs`: old style claim
"#,
    )?;

    let status = run_success_json(&[
        "live",
        "status",
        "--repo",
        repo_str(repo)?,
        "--now",
        "2026-05-20T00:00:00Z",
        "--json",
    ])?;
    let claim = claim_by_id(&status, "old-active")?;

    assert_eq!(claim["owner"], "worker-a");
    assert_eq!(claim["status"], "active");
    assert_eq!(claim["is_lock"], true);
    assert_eq!(claim["created"], "2026-05-19");
    assert_eq!(claim["owned_files"][0], "src/cli.rs");
    assert_eq!(claim["liveness"]["reference_field"], "date");

    Ok(())
}

#[test]
fn status_output_includes_active_handoff_and_done_claims() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "active-claim", "active", "src/cli.rs")?;
    write_modern_claim(repo, "handoff-claim", "handoff", "README.md")?;
    write_modern_claim(repo, "done-claim", "done", "RELEASE_NOTES.md")?;

    let status = run_success_json(&[
        "live",
        "status",
        "--repo",
        repo_str(repo)?,
        "--now",
        "2026-05-20T00:30:00Z",
        "--json",
    ])?;

    assert_eq!(status["claim_count"], 3);
    assert_eq!(status["lock_count"], 1);
    assert_eq!(claim_by_id(&status, "active-claim")?["status"], "active");
    assert_eq!(claim_by_id(&status, "handoff-claim")?["status"], "handoff");
    assert_eq!(claim_by_id(&status, "done-claim")?["status"], "done");

    Ok(())
}

#[test]
fn stale_detection_uses_deterministic_now() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_claim(
        repo,
        "timed",
        r#"# Claim: timed

- Claim ID: `timed`
- Owner: `worker-a`
- Status: `active`
- Created: `2026-05-20T00:00:00Z`
- Updated: `2026-05-20T00:00:00Z`
- Heartbeat: `2026-05-20T00:00:00Z`
- Stale after minutes: `60`
- Owned files, regions, devices, or services:
  - `src/lib.rs`: test
"#,
    )?;

    let status = run_success_json(&[
        "live",
        "status",
        "--repo",
        repo_str(repo)?,
        "--now",
        "2026-05-20T02:00:00Z",
        "--json",
    ])?;
    let claim = claim_by_id(&status, "timed")?;

    assert_eq!(claim["liveness"]["state"], "stale");
    assert_eq!(claim["liveness"]["age_minutes"], 120);
    assert_eq!(claim["liveness"]["stale_after_minutes"], 60);

    Ok(())
}

#[test]
fn heartbeat_updates_timestamp_and_audit_log() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "heartbeat-me", "active", "src/live_claim.rs")?;

    let report = run_success_json(&[
        "live",
        "heartbeat",
        "heartbeat-me",
        "--repo",
        repo_str(repo)?,
        "--by",
        "heartbeat-me",
        "--json",
    ])?;

    assert_eq!(report["claim_id"], "heartbeat-me");
    assert_eq!(report["actor"], "heartbeat-me");
    assert_eq!(report["status"], "active");
    let updated = report["updated"].as_str().context("updated timestamp")?;
    assert_eq!(report["claim"]["heartbeat"], updated);
    assert_ne!(updated, "2026-05-20T00:00:00Z");
    let claim_text = fs::read_to_string(claim_path(repo, "heartbeat-me")).context("read claim")?;
    assert!(claim_text.contains(&format!("- Updated: `{updated}`")));
    assert!(claim_text.contains(&format!("- Heartbeat: `{updated}`")));
    assert!(claim_text.contains("`heartbeat-me` heartbeat"));

    Ok(())
}

#[test]
fn heartbeat_rejects_blank_actor_without_touching_claim() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "heartbeat-blank-actor", "active", "src/live_claim.rs")?;
    let claim_path = claim_path(repo, "heartbeat-blank-actor");
    let original_claim = fs::read_to_string(&claim_path).context("read original claim")?;

    let output = run_failure_output(&[
        "live",
        "heartbeat",
        "heartbeat-blank-actor",
        "--repo",
        repo_str(repo)?,
        "--by",
        "   ",
        "--json",
    ])?;

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("heartbeat requires --by"),
        "stderr was {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&claim_path).context("read unchanged claim")?,
        original_claim
    );

    Ok(())
}

#[test]
fn mutation_cli_rejects_public_now_override_without_touching_claim() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "real-clock-only", "active", "src/live_claim.rs")?;
    let path = claim_path(repo, "real-clock-only");
    let original = fs::read(&path)?;
    let draft = repo.join("real-clock-only-draft.md");
    fs::write(
        &draft,
        modern_claim_text("real-clock-only", "blocked", "src/live_claim.rs"),
    )?;

    for args in [
        vec![
            "live",
            "apply",
            path_str(&draft)?,
            "--repo",
            repo_str(repo)?,
            "--by",
            "real-clock-only",
            "--now",
            "2999-01-01T00:00:00Z",
            "--json",
        ],
        vec![
            "live",
            "heartbeat",
            "real-clock-only",
            "--repo",
            repo_str(repo)?,
            "--by",
            "real-clock-only",
            "--now",
            "2999-01-01T00:00:00Z",
            "--json",
        ],
        vec![
            "live",
            "override-release",
            "real-clock-only",
            "--repo",
            repo_str(repo)?,
            "--by",
            "project-owner",
            "--reason",
            "attempted clock override",
            "--now",
            "2999-01-01T00:00:00Z",
            "--json",
        ],
        vec![
            "live",
            "release",
            "real-clock-only",
            "--repo",
            repo_str(repo)?,
            "--by",
            "real-clock-only",
            "--reason",
            "attempted clock override",
            "--now",
            "2999-01-01T00:00:00Z",
            "--json",
        ],
    ] {
        let output = run_failure_output(&args)?;
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--now'"));
        assert_eq!(fs::read(&path)?, original);
    }
    Ok(())
}

#[test]
fn apply_and_owner_release_publish_through_the_locked_cli_path() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    fs::create_dir_all(repo.join(".agents/live/claims"))?;
    let draft = repo.join("draft-claim.md");
    fs::write(
        &draft,
        modern_claim_text("cli-applied", "active", "src/review.rs"),
    )?;

    let created = run_success_json(&[
        "live",
        "apply",
        path_str(&draft)?,
        "--repo",
        repo_str(repo)?,
        "--by",
        "cli-applied",
        "--json",
    ])?;
    assert_eq!(created["created"], true);
    assert_eq!(created["claim"]["status"], "active");

    fs::write(
        &draft,
        modern_claim_text("cli-applied", "blocked", "src/review.rs"),
    )?;
    let updated = run_success_json(&[
        "live",
        "apply",
        path_str(&draft)?,
        "--repo",
        repo_str(repo)?,
        "--by",
        "cli-applied",
        "--json",
    ])?;
    assert_eq!(updated["created"], false);
    assert_eq!(updated["claim"]["status"], "blocked");

    let before_wrong_owner = fs::read(claim_path(repo, "cli-applied"))?;
    let wrong_owner = run_failure_output(&[
        "live",
        "release",
        "cli-applied",
        "--repo",
        repo_str(repo)?,
        "--by",
        "other-owner",
        "--reason",
        "not the recorded owner",
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&wrong_owner.stderr).contains("exactly match"));
    assert_eq!(
        fs::read(claim_path(repo, "cli-applied"))?,
        before_wrong_owner
    );

    let released = run_success_json(&[
        "live",
        "release",
        "cli-applied",
        "--repo",
        repo_str(repo)?,
        "--by",
        "cli-applied",
        "--status",
        "done",
        "--reason",
        "owner completed the claim",
        "--json",
    ])?;
    assert_eq!(released["status"], "done");
    assert!(released["audit_entry"]
        .as_str()
        .unwrap_or_default()
        .contains("released claim as `done`"));
    Ok(())
}

#[test]
fn override_release_changes_active_to_handoff_and_records_reason() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "release-me", "active", "src/cli.rs")?;

    let report = run_success_json(&[
        "live",
        "override-release",
        "release-me",
        "--repo",
        repo_str(repo)?,
        "--by",
        "project-owner",
        "--reason",
        "stale claim blocked required files",
        "--json",
    ])?;

    assert_eq!(report["previous_status"], "active");
    assert_eq!(report["status"], "handoff");
    assert_eq!(report["claim"]["is_lock"], false);
    let claim_text = fs::read_to_string(claim_path(repo, "release-me")).context("read claim")?;
    assert!(claim_text.contains("- Status: `handoff`"));
    assert!(claim_text.contains("previous status `active`"));
    assert!(claim_text.contains("reason: stale claim blocked required files"));

    Ok(())
}

#[test]
fn validate_reports_missing_and_malformed_fields() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_claim(
        repo,
        "bad",
        r#"# Claim: bad

- Status: `waiting`
"#,
    )?;

    let validation = run_success_json(&[
        "live",
        "validate",
        "--repo",
        repo_str(repo)?,
        "--now",
        "2026-05-20T00:00:00Z",
        "--json",
    ])?;

    assert_eq!(validation["valid"], false);
    let issues = validation["claims"][0]["issues"]
        .as_array()
        .context("issues array")?;
    assert!(issues.iter().any(|issue| issue["field"] == "owner"));
    assert!(issues.iter().any(|issue| issue["field"] == "status"
        && issue["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unsupported")));
    assert!(issues.iter().any(|issue| issue["field"] == "owned_files"));

    Ok(())
}

#[test]
fn json_output_shape_is_stable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "shape", "blocked", "src/lib.rs")?;

    let status = run_success_json(&[
        "live",
        "status",
        "--repo",
        repo_str(repo)?,
        "--now",
        "2026-05-20T00:10:00Z",
        "--json",
    ])?;
    let claim = claim_by_id(&status, "shape")?;

    assert!(status.get("repo").is_some());
    assert!(status.get("claims_dir").is_some());
    assert!(status.get("now").is_some());
    assert!(status.get("claim_count").is_some());
    assert!(status.get("lock_count").is_some());
    assert!(claim.get("claim_id").is_some());
    assert_eq!(claim["file"], ".agents/live/claims/shape.md");
    assert!(claim.get("owner").is_some());
    assert!(claim.get("status").is_some());
    assert!(claim.get("is_lock").is_some());
    assert!(claim.get("owned_files").is_some());
    assert!(claim.get("liveness").is_some());
    assert!(claim["liveness"].get("state").is_some());
    assert!(claim["liveness"].get("age_minutes").is_some());

    Ok(())
}

#[test]
fn mutation_cli_refuses_wrong_owner_fresh_override_and_markdown_injection() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    write_modern_claim(repo, "owned-claim", "active", "src/live_claim.rs")?;
    let path = claim_path(repo, "owned-claim");
    let future = fs::read_to_string(&path)?.replace("2026-05-20T00:00:00Z", "2999-05-20T00:00:00Z");
    fs::write(&path, future)?;
    let original = fs::read(&path).context("read original claim")?;

    let wrong_owner = run_failure_output(&[
        "live",
        "heartbeat",
        "owned-claim",
        "--repo",
        repo_str(repo)?,
        "--by",
        "other-owner",
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&wrong_owner.stderr).contains("exactly match"));
    assert_eq!(fs::read(&path)?, original);

    let fresh = run_failure_output(&[
        "live",
        "override-release",
        "owned-claim",
        "--repo",
        repo_str(repo)?,
        "--by",
        "project-owner",
        "--reason",
        "fresh claim remains owned",
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&fresh.stderr).contains("provably stale"));
    assert_eq!(fs::read(&path)?, original);

    let injected = run_failure_output(&[
        "live",
        "override-release",
        "owned-claim",
        "--repo",
        repo_str(repo)?,
        "--by",
        "project-owner",
        "--reason",
        "unsafe\n## injected",
        "--json",
    ])?;
    assert!(String::from_utf8_lossy(&injected.stderr).contains("unsafe"));
    assert_eq!(fs::read(&path)?, original);
    Ok(())
}

#[test]
fn stale_publication_claim_override_release_does_not_touch_owned_files() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo = temp.path();
    fs::create_dir_all(repo.join("src")).context("create src")?;
    fs::write(repo.join("src/cli.rs"), "dirty cli").context("write cli")?;
    fs::write(repo.join("src/lib.rs"), "dirty lib").context("write lib")?;
    fs::write(repo.join("README.md"), "dirty readme").context("write readme")?;
    fs::write(repo.join("RELEASE_NOTES.md"), "dirty notes").context("write notes")?;
    write_claim(
        repo,
        "codex-pr-issue-publication",
        r#"# Claim: codex-pr-issue-publication

- Owner: `codex-pr-issue-publication`
- Date: `2026-05-19`
- Status: `active`
- Owned files, regions, devices, or services:
  - `src/cli.rs`: wire PR and issue CLI behavior
  - `src/lib.rs`: expose publication module if needed
  - `README.md`: update documented feature scope
  - `RELEASE_NOTES.md`: update documented feature scope
"#,
    )?;

    let report = run_success_json(&[
        "live",
        "override-release",
        "codex-pr-issue-publication",
        "--repo",
        repo_str(repo)?,
        "--by",
        "project-owner",
        "--reason",
        "original owner/session unavailable; stale active claim blocked required integration files; preserving all existing file changes",
        "--json",
    ])?;

    assert_eq!(report["status"], "handoff");
    assert_eq!(fs::read_to_string(repo.join("src/cli.rs"))?, "dirty cli");
    assert_eq!(fs::read_to_string(repo.join("src/lib.rs"))?, "dirty lib");
    assert_eq!(fs::read_to_string(repo.join("README.md"))?, "dirty readme");
    assert_eq!(
        fs::read_to_string(repo.join("RELEASE_NOTES.md"))?,
        "dirty notes"
    );

    Ok(())
}

fn write_modern_claim(repo: &Path, claim_id: &str, status: &str, path: &str) -> Result<()> {
    write_claim(repo, claim_id, &modern_claim_text(claim_id, status, path))
}

fn modern_claim_text(claim_id: &str, status: &str, path: &str) -> String {
    format!(
        r#"# Claim: {claim_id}

- Claim ID: `{claim_id}`
- Owner: `{claim_id}`
- Status: `{status}`
- Created: `2026-05-20T00:00:00Z`
- Updated: `2026-05-20T00:00:00Z`
- Heartbeat: `2026-05-20T00:00:00Z`
- Stale after minutes: `120`
- Owned files, regions, devices, or services:
  - `{path}`: test

## Audit log

- `2026-05-20T00:00:00Z` - `{claim_id}` created
"#
    )
}

fn write_claim(repo: &Path, claim_id: &str, content: &str) -> Result<()> {
    let dir = repo.join(".agents/live/claims");
    fs::create_dir_all(&dir).context("create claims dir")?;
    fs::write(dir.join(format!("{claim_id}.md")), content).context("write claim")
}

fn claim_path(repo: &Path, claim_id: &str) -> PathBuf {
    repo.join(".agents/live/claims")
        .join(format!("{claim_id}.md"))
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_failure_output(args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!("maco command succeeded unexpectedly");
    }
    Ok(output)
}

fn claim_by_id<'a>(status: &'a Value, claim_id: &str) -> Result<&'a Value> {
    status["claims"]
        .as_array()
        .context("claims array")?
        .iter()
        .find(|claim| claim["claim_id"] == claim_id)
        .with_context(|| format!("missing claim {claim_id}"))
}

fn repo_str(repo: &Path) -> Result<&str> {
    repo.to_str().context("repo path utf8")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("path utf8")
}
