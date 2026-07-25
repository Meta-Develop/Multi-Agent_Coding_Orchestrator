use anyhow::{Context, Result};
use git2::{Oid, Repository, Signature};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, File},
    path::Path,
    process::Command,
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");
const ISSUE33_CLAIMS_V1: &[u8] = include_bytes!("fixtures/issue33/agent-files-claims-v1.json");
const ISSUE33_CLAIMS_V1_SHA256: &str =
    "85ca48c7b658a3f28b4d3758268a41319b86f9b9bef78637bda7069cc2b83111";
const ISSUE33_PHYSICAL_JOURNAL_ID: &str =
    "6ce2913c16ab9fe3388b4d29719afd3b2549aa6d90975b2cf8ddc4173d0999f4";
const ISSUE33_PHYSICAL_JOURNAL_MANIFEST: &str =
    include_str!("fixtures/issue33/authenticated-claims-state-v1.sha256");

#[cfg(unix)]
#[test]
fn cli_issue33_quarantine_then_attested_migration_restores_claim_consumers() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repository = Repository::open(&repo_path).context("open repo")?;
    let state_root = repository.commondir().join("maco/state");
    fs::create_dir_all(&state_root).context("create temporary state root")?;
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .context("make temporary state root owner-private")?;
    write_private_test_state_file(
        &state_root.join("artifact_finalization_hmac_v1.key"),
        &[0x33; 32],
    )?;
    write_private_test_state_file(&state_root.join("repository_auth_epoch_v1"), &[0x34; 32])?;
    fs::write(state_root.join("claims.json"), ISSUE33_CLAIMS_V1)
        .context("write checksum-less claims-v1 fixture")?;
    fs::set_permissions(
        state_root.join("claims.json"),
        fs::Permissions::from_mode(0o600),
    )
    .context("make checksum-less claims-v1 fixture owner-private")?;

    let journal_root = state_root.join("authenticated-claims-state-v1");
    fs::create_dir(&journal_root).context("create temporary authenticated claims journal root")?;
    fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))
        .context("make temporary claims journal root owner-private")?;
    let physical_journal = journal_root.join(ISSUE33_PHYSICAL_JOURNAL_ID);
    let copied_files = copy_issue33_physical_journal_fixture(&physical_journal)?;
    assert_eq!(
        copied_files,
        ISSUE33_PHYSICAL_JOURNAL_MANIFEST.lines().count(),
        "the regression must install every captured physical-journal file"
    );

    let repo = repo_path.to_str().context("repo path utf8")?;
    let blocked = Command::new(BIN)
        .args(["sync", "status", "--repo", repo, "--json"])
        .output()
        .context("run sync status against unanchored physical journal")?;
    assert!(!blocked.status.success());
    assert_eq!(
        String::from_utf8_lossy(&blocked.stderr).trim(),
        format!(
            "Error: authenticated snapshot physical journal '{}' is not anchored by any signed logical state",
            ISSUE33_PHYSICAL_JOURNAL_ID
        )
    );

    let fixture_source = issue33_physical_journal_fixture();
    let quarantine_root = repository
        .commondir()
        .join("maco/issue33-option-2-quarantine");
    fs::create_dir(&quarantine_root).context("create test-local option-2 quarantine")?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))
        .context("make test-local quarantine owner-private")?;
    let quarantined_journal = quarantine_root.join(ISSUE33_PHYSICAL_JOURNAL_ID);
    fs::rename(&physical_journal, &quarantined_journal)
        .context("quarantine only the copied unanchored physical journal")?;
    assert!(!physical_journal.exists());
    assert!(quarantined_journal.is_dir());
    assert!(
        fixture_source.is_dir(),
        "the checked-in physical-journal fixture must remain untouched"
    );

    let migration = run_success_json([
        "state",
        "migrate",
        "--repo",
        repo,
        "--apply",
        "--acknowledge-unauthenticated-claims-v1",
        "--expected-claims-v1-sha256",
        ISSUE33_CLAIMS_V1_SHA256,
        "--json",
    ])?;
    assert_eq!(migration["mode"], "apply");
    assert_eq!(migration["status"], "applied");
    assert_eq!(migration["manifest_generation"], 1);
    let claims_entry = migration["entries"]
        .as_array()
        .context("migration entries")?
        .iter()
        .find(|entry| entry["store"] == "claims")
        .context("claims migration entry")?;
    assert_eq!(
        claims_entry["provenance"],
        "operator_attested_unauthenticated_import"
    );
    assert_eq!(claims_entry["sha256"], ISSUE33_CLAIMS_V1_SHA256);

    let status = run_success_json(["sync", "status", "--repo", repo, "--json"])?;
    let claims = status.as_array().context("status claims")?;
    assert_eq!(claims.len(), 3);
    assert_eq!(
        claims
            .iter()
            .map(|claim| claim["token"].as_u64())
            .collect::<Vec<_>>(),
        vec![Some(20), Some(44), Some(66)]
    );
    assert_eq!(claims[0]["agent_id"], "o1-worktree-cleanup");
    assert_eq!(claims[0]["paths"], serde_json::json!([".maco"]));
    assert_eq!(claims[1]["agent_id"], "o1-guard-fix");
    assert_eq!(
        claims[1]["paths"],
        serde_json::json!([
            "scripts/audit-codex-terminal-role-launches",
            "scripts/check-development-handoff-clean"
        ])
    );
    assert_eq!(claims[2]["agent_id"], "history-rewrite-otherproj-o1");
    assert_eq!(
        claims[2]["paths"],
        serde_json::json!(["machine-root/projects/example/other-repo"])
    );

    let gc = run_success_json(["worktree", "gc", "--repo", repo, "--dry-run", "--json"])?;
    assert_eq!(gc["dry_run"], true);
    assert_eq!(gc["considered_count"], 0);
    assert_eq!(gc["removed_count"], 0);
    assert_eq!(gc["orphan_removed_count"], 0);
    assert!(
        quarantined_journal.is_dir(),
        "successful consumers must not silently delete the quarantined evidence"
    );

    Ok(())
}

#[cfg(unix)]
fn write_private_test_state_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("make {} owner-private", path.display()))
}

#[cfg(unix)]
fn issue33_physical_journal_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/issue33/authenticated-claims-state-v1")
        .join(ISSUE33_PHYSICAL_JOURNAL_ID)
}

#[cfg(unix)]
fn copy_issue33_physical_journal_fixture(destination: &Path) -> Result<usize> {
    let source = issue33_physical_journal_fixture();
    fs::create_dir(destination)
        .with_context(|| format!("create copied journal {}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "make copied journal {} owner-private",
            destination.display()
        )
    })?;

    let mut copied_files = 0usize;
    for entry in fs::read_dir(&source)
        .with_context(|| format!("enumerate captured journal {}", source.display()))?
    {
        let entry = entry.context("inspect captured physical-journal entry")?;
        let metadata = entry
            .metadata()
            .context("inspect captured physical-journal metadata")?;
        if !metadata.is_file() {
            anyhow::bail!(
                "captured physical-journal entry is not a regular file: {}",
                entry.path().display()
            );
        }
        let copied = destination.join(entry.file_name());
        fs::copy(entry.path(), &copied)
            .with_context(|| format!("copy captured journal file {}", entry.path().display()))?;
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "make copied journal file {} owner-private",
                copied.display()
            )
        })?;
        copied_files = copied_files
            .checked_add(1)
            .context("captured journal file count overflowed")?;
    }
    Ok(copied_files)
}

#[test]
fn cli_repo_map_orchestrate_and_sync_status_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {
              "id": "agent-a",
              "paths": ["src"],
              "command": "git rev-parse --is-inside-work-tree"
            }
          ]
        }"#,
    )
    .context("write plan")?;

    let map = run_success_json([
        "repo",
        "map",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert!(map["entries"].as_array().context("entries array")?.len() >= 2);

    let validation = run_success_json([
        "orchestrate",
        "validate",
        plan_path.to_str().context("plan path utf8")?,
        "--json",
    ])?;
    assert_eq!(validation["agent_count"], 1);

    if assert_orchestrate_run_unsupported(&plan_path, &repo_path)? {
        return Ok(());
    }

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        assert_orchestration_failed_closed(&summary)?;
        let status = run_success_json([
            "sync",
            "status",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])?;
        assert_eq!(status.as_array().context("status array")?.len(), 0);
        return Ok(());
    }
    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["stdout"]["text"], "true\n");

    let status = run_success_json([
        "sync",
        "status",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_orchestrate_failure_still_emits_json_summary() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "false"}
          ]
        }"#,
    )
    .context("write plan")?;

    if assert_orchestrate_run_unsupported(&plan_path, &repo_path)? {
        return Ok(());
    }

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("error string")?;
    assert!(
        error.contains("command exited") || error.contains("process-tree ownership"),
        "unexpected orchestration failure: {error}"
    );

    Ok(())
}

#[test]
fn cli_orchestrate_reports_committed_agent_change_and_patch() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    let patch_dir = temp.path().join("patches");
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {
              "id": "agent-a",
              "paths": ["README.md"],
              "command": "printf '# Smoke\n\ncommitted\n' > README.md && git add README.md && git -c user.name='maco test' -c user.email='maco-test@example.invalid' commit -m agent-change"
            }
          ]
        }"#,
    )
    .context("write plan")?;

    if assert_orchestrate_run_unsupported(&plan_path, &repo_path)? {
        assert!(!patch_dir.exists());
        return Ok(());
    }

    let (summary, verified_backend_available) = run_json_regardless([
        "orchestrate",
        "run",
        plan_path.to_str().context("plan path utf8")?,
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--patch-dir",
        patch_dir.to_str().context("patch dir utf8")?,
        "--json",
    ])?;
    if !verified_backend_available {
        assert_orchestration_failed_closed(&summary)?;
        assert!(!patch_dir.join("agent-a.patch").exists());
        assert_eq!(
            fs::read_to_string(repo_path.join("README.md"))?,
            "# Smoke\n"
        );
        return Ok(());
    }

    assert_eq!(summary["success"], true);
    assert_eq!(summary["agents"][0]["status"], "succeeded");
    assert_eq!(summary["agents"][0]["changed_paths"][0], "README.md");
    assert_eq!(
        summary["agents"][0]["patch_path"],
        patch_dir.join("agent-a.patch").to_string_lossy().as_ref()
    );
    let patch = fs::read_to_string(patch_dir.join("agent-a.patch")).context("read patch")?;
    assert!(patch.contains("committed"));

    Ok(())
}

#[test]
fn cli_claim_conflict_still_emits_json_summary() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let plan_path = temp.path().join("plan.json");
    run_success_json([
        "sync",
        "claim",
        "other-agent",
        "README.md",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;
    fs::write(
        &plan_path,
        r#"{
          "agents": [
            {"id": "agent-a", "paths": ["README.md"], "command": "echo should-not-run"}
          ]
        }"#,
    )
    .context("write plan")?;

    if assert_orchestrate_run_unsupported(&plan_path, &repo_path)? {
        return Ok(());
    }

    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan_path.to_str().context("plan path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run maco")?;

    assert!(!output.status.success());
    let summary: Value = serde_json::from_slice(&output.stdout).context("parse summary json")?;
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    assert!(summary["agents"][0]["error"]
        .as_str()
        .context("error string")?
        .contains("failed to claim paths"));

    Ok(())
}

#[test]
fn cli_worktree_diff_uses_active_claims_for_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;
    run_success_json([
        "sync",
        "claim",
        "agent-a",
        "README.md",
        "--repo",
        repo,
        "--json",
    ])?;

    let diff = run_success_json(["worktree", "diff", "agent-a", "--repo", repo, "--json"])?;

    assert_eq!(diff["metadata"]["agent_id"], "agent-a");
    assert_eq!(diff["claimed_paths"][0], "README.md");
    assert_eq!(diff["changed_paths"][0], "README.md");
    assert_eq!(
        diff["unclaimed_changed_paths"]
            .as_array()
            .context("unclaimed array")?
            .len(),
        0
    );
    assert!(diff["diff"]["summary"]["text"]
        .as_str()
        .context("diff summary")?
        .contains("changed"));

    Ok(())
}

#[test]
fn cli_worktree_pending_on_fresh_repo_creates_no_maco_state() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let maco_root = repo_path.join(".git").join("maco");
    assert!(!maco_root.exists());

    let pending = run_success_json(["worktree", "pending", "--repo", repo, "--json"])?;

    assert_eq!(pending.as_array().context("pending array")?.len(), 0);
    assert!(!maco_root.exists());
    let remove = Command::new(BIN)
        .args([
            "worktree",
            "remove",
            "agent-a",
            "--repo",
            repo,
            "--delete-branch",
            "--json",
        ])
        .output()
        .context("run unsupported non-force removal")?;
    assert!(!remove.status.success());
    assert!(String::from_utf8_lossy(&remove.stderr)
        .contains("non-force managed worktree removal is unsupported"));
    assert!(!maco_root.exists());
    Ok(())
}

#[test]
fn cli_semantic_map_and_queries_emit_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Worker;\nimpl Worker { pub fn new() -> Self { Worker } }\n",
    )
    .context("write semantic lib")?;

    let map = run_success_json(["repo", "map", "--semantic", "--repo", repo, "--json"])?;
    assert!(map["symbols"]
        .as_array()
        .context("symbols array")?
        .iter()
        .any(|symbol| symbol["name"] == "Worker"));

    let symbol = run_success_json([
        "repo", "query", "symbol", "Worker", "--repo", repo, "--json",
    ])?;
    assert_eq!(symbol["matches"][0]["name"], "Worker");

    let path = run_success_json([
        "repo",
        "query",
        "path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(path["files"][0]["path"], "src/lib.rs");
    assert!(path["symbols"]
        .as_array()
        .context("path symbols")?
        .iter()
        .any(|symbol| symbol["name"] == "new"));

    Ok(())
}

#[test]
fn cli_semantic_coord_preview_claim_conflict_status_and_release_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(repo_path.join("src/lib.rs"), "pub struct Worker;\n")
        .context("write semantic lib")?;

    let preview = run_success_json([
        "coord",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(preview["persisted"], false);
    assert_eq!(preview["has_blocking_conflicts"], false);
    assert_eq!(preview["intent"]["symbols"][0]["name"], "Worker");

    let claim = run_success_json([
        "coord",
        "claim",
        "agent-a",
        "--repo",
        repo,
        "--path",
        "src/lib.rs",
        "--symbol",
        "Worker",
        "--json",
    ])?;
    assert_eq!(claim["persisted"], true);
    let token = claim["intent"]["token"].as_u64().context("claim token")?;

    let output = Command::new(BIN)
        .args([
            "coord", "claim", "agent-b", "--repo", repo, "--symbol", "Worker", "--json",
        ])
        .output()
        .context("run conflicting claim")?;
    assert!(!output.status.success());
    let conflict: Value = serde_json::from_slice(&output.stdout).context("parse conflict json")?;
    assert_eq!(conflict["persisted"], false);
    assert_eq!(conflict["has_blocking_conflicts"], true);
    assert!(conflict["conflicts"]
        .as_array()
        .context("conflicts array")?
        .iter()
        .any(|conflict| conflict["kind"] == "symbol_overlap"));

    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 1);

    let token_arg = token.to_string();
    let released =
        run_success_json_args(&["coord", "release", &token_arg, "--repo", repo, "--json"])?;
    assert_eq!(released["agent_id"], "agent-a");
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_semantic_coord_release_agent_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\n",
    )
    .context("write semantic lib")?;

    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Alpha", "--json",
    ])?;
    run_success_json([
        "coord", "claim", "agent-a", "--repo", repo, "--symbol", "Beta", "--json",
    ])?;

    let released = run_success_json([
        "coord",
        "release-agent",
        "agent-a",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(released.as_array().context("released array")?.len(), 2);
    let status = run_success_json(["coord", "status", "--repo", repo, "--json"])?;
    assert_eq!(status.as_array().context("status array")?.len(), 0);

    Ok(())
}

#[test]
fn cli_merge_preview_blocks_unclaimed_edits_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    if assert_worktree_creation_unsupported(repo)? {
        return Ok(());
    }
    let worktree = run_success_json(["worktree", "create", "agent-a", "--repo", repo, "--json"])?;
    let worktree_path = Path::new(worktree["path"].as_str().context("worktree path string")?);
    fs::write(worktree_path.join("README.md"), "# Smoke\n\nchanged\n").context("edit worktree")?;

    let preview = run_success_json([
        "merge",
        "preview",
        "agent-a",
        "--repo",
        repo,
        "--claim",
        "src/lib.rs",
        "--json",
    ])?;

    assert_eq!(preview["safety"]["readiness"]["status"], "blocked");
    assert!(preview["safety"]["readiness"]["blockers"]
        .as_array()
        .context("blockers array")?
        .iter()
        .any(|blocker| blocker == "unclaimed_edits"));
    assert_eq!(
        preview["candidate"]["unclaimed_changed_paths"][0],
        "README.md"
    );

    Ok(())
}

#[test]
fn cli_llm_providers_and_prompt_preview_are_network_free_json() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let repo = repo_path.to_str().context("repo path utf8")?;
    let task_path = temp.path().join("task.md");
    fs::write(
        &task_path,
        "Implement local-only prompt preview.\nAPI_TOKEN=secret\n",
    )
    .context("write task")?;

    let providers = run_success_json(["llm", "providers", "--json"])?;
    assert_eq!(providers["network_providers_required"], false);
    assert_eq!(providers["providers"][0]["id"], "fake");
    assert_eq!(providers["providers"][0]["network_required"], false);

    let preview = run_success_json([
        "llm",
        "prompt-preview",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "src/lib.rs",
        "--repo",
        repo,
        "--json",
    ])?;
    assert_eq!(preview["agent_id"], "agent-a");
    assert_eq!(preview["provider"]["network_required"], false);
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("<redacted:secret>"));
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("src/lib.rs"));

    Ok(())
}

#[test]
fn cli_prompt_preview_refuses_paths_outside_the_repository() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    let secret_path = temp.path().join("outside-secret.txt");
    fs::write(&task_path, "Inspect the requested path.\n").context("write task")?;
    fs::write(&secret_path, "PROMPT_PREVIEW_OUTSIDE_SENTINEL\n").context("write secret")?;

    for candidate in [
        "../outside-secret.txt".to_string(),
        secret_path.to_string_lossy().into_owned(),
    ] {
        let output = Command::new(BIN)
            .args([
                "llm",
                "prompt-preview",
                task_path.to_str().context("task path utf8")?,
                "--agent-id",
                "agent-a",
                "--path",
                &candidate,
                "--repo",
                repo_path.to_str().context("repo path utf8")?,
                "--json",
            ])
            .output()
            .context("run prompt preview")?;
        assert!(!output.status.success());
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("PROMPT_PREVIEW_OUTSIDE_SENTINEL")
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("PROMPT_PREVIEW_OUTSIDE_SENTINEL")
        );
    }

    Ok(())
}

#[test]
fn cli_prompt_preview_preserves_directory_and_planned_file_scopes() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    fs::write(&task_path, "新しいファイルを追加します。\n").context("write task")?;

    let preview = run_success_json([
        "llm",
        "prompt-preview",
        task_path.to_str().context("task path utf8")?,
        "--agent-id",
        "agent-a",
        "--path",
        "src",
        "--path",
        "src/planned.rs",
        "--repo",
        repo_path.to_str().context("repo path utf8")?,
        "--json",
    ])?;

    let claimed_paths = preview["claimed_paths"]
        .as_array()
        .context("claimed paths")?;
    assert!(claimed_paths.iter().any(|path| path == "src"));
    assert!(claimed_paths.iter().any(|path| path == "src/planned.rs"));
    assert!(preview["rendered"]
        .as_str()
        .context("rendered prompt")?
        .contains("新しいファイルを追加します"));

    Ok(())
}

#[test]
fn bounded_external_cli_inputs_fail_before_creating_work() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let oversized = temp.path().join("oversized-input");
    File::create(&oversized)
        .context("create oversized input")?
        .set_len(64 * 1024 * 1024 + 1)
        .context("size oversized input")?;
    let task = temp.path().join("task.md");
    fs::write(&task, "Update README\n").context("task")?;

    for args in [
        vec![
            "consult",
            "ask",
            "--question-file",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "issue",
            "preview",
            "--title",
            "bounded input",
            "--body-file",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "orchestrate",
            "collect",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task.to_str().context("task path utf8")?,
            "--agent-id",
            "bounded-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            oversized.to_str().context("oversized path utf8")?,
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ],
    ] {
        let output = Command::new(BIN)
            .args(args)
            .output()
            .context("run bounded input")?;
        assert!(!output.status.success());
    }

    let repo = Repository::open(&repo_path).context("open repo")?;
    assert!(repo
        .find_branch("maco/bounded-agent", git2::BranchType::Local)
        .is_err());
    assert!(!repo_path.join(".maco/consult").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn external_cli_file_inputs_refuse_symlink_leafs_before_work() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let question = temp.path().join("question.md");
    let issue = temp.path().join("issue.md");
    let summary = temp.path().join("summary.json");
    let task = temp.path().join("task.md");
    let proposal = temp.path().join("proposal.json");
    fs::write(&question, "What changed?\n").context("question")?;
    fs::write(&issue, "Issue body\n").context("issue")?;
    fs::write(&summary, "{\"agents\": []}\n").context("summary")?;
    fs::write(&task, "Update README\n").context("task")?;
    fs::write(
        &proposal,
        "{\"summary\":\"noop\",\"commands\":[],\"patches\":[],\"notes\":[]}",
    )
    .context("proposal")?;
    let question_link = temp.path().join("question-link");
    let issue_link = temp.path().join("issue-link");
    let summary_link = temp.path().join("summary-link");
    let task_link = temp.path().join("task-link");
    let proposal_link = temp.path().join("proposal-link");
    symlink(&question, &question_link).context("question link")?;
    symlink(&issue, &issue_link).context("issue link")?;
    symlink(&summary, &summary_link).context("summary link")?;
    symlink(&task, &task_link).context("task link")?;
    symlink(&proposal, &proposal_link).context("proposal link")?;

    let repo = repo_path.to_str().context("repo path utf8")?;
    let cases = [
        vec![
            "consult",
            "ask",
            "--question-file",
            question_link.to_str().context("question link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "issue",
            "preview",
            "--title",
            "link",
            "--body-file",
            issue_link.to_str().context("issue link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "orchestrate",
            "collect",
            summary_link.to_str().context("summary link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task.to_str().context("task utf8")?,
            "--agent-id",
            "proposal-link-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal_link.to_str().context("proposal link utf8")?,
            "--repo",
            repo,
            "--json",
        ],
        vec![
            "agent",
            "run",
            task_link.to_str().context("task link utf8")?,
            "--agent-id",
            "task-link-agent",
            "--path",
            "README.md",
            "--fake-proposal",
            proposal.to_str().context("proposal utf8")?,
            "--repo",
            repo,
            "--json",
        ],
    ];
    for args in cases {
        let output = Command::new(BIN)
            .args(args)
            .output()
            .context("run link input")?;
        assert!(!output.status.success());
    }

    let repo = Repository::open(&repo_path).context("open repo")?;
    for branch in ["maco/proposal-link-agent", "maco/task-link-agent"] {
        assert!(repo.find_branch(branch, git2::BranchType::Local).is_err());
    }
    assert!(!repo_path.join(".maco/consult").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cli_prompt_preview_refuses_symlinked_repository_excerpts() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let task_path = temp.path().join("task.md");
    let secret_path = temp.path().join("symlink-secret.txt");
    fs::write(&task_path, "Inspect the requested path.\n").context("write task")?;
    fs::write(&secret_path, "PROMPT_PREVIEW_SYMLINK_SENTINEL\n").context("write secret")?;
    symlink(&secret_path, repo_path.join("secret-link.txt")).context("create leaf symlink")?;

    let output = Command::new(BIN)
        .args([
            "llm",
            "prompt-preview",
            task_path.to_str().context("task path utf8")?,
            "--agent-id",
            "agent-a",
            "--path",
            "secret-link.txt",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run prompt preview")?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PROMPT_PREVIEW_SYMLINK_SENTINEL"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PROMPT_PREVIEW_SYMLINK_SENTINEL"));

    Ok(())
}

fn run_success_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    run_success_json_args(&args)
}

fn assert_worktree_creation_unsupported(repo: &str) -> Result<bool> {
    let output = Command::new(BIN)
        .args(["worktree", "create", "agent-a", "--repo", repo, "--json"])
        .output()
        .context("run unsupported worktree create")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("managed worktree creation is unsupported")
            && stderr.contains("capability-bound"),
        "unexpected worktree-create refusal: {stderr}"
    );
    Ok(true)
}

fn assert_orchestrate_run_unsupported(plan: &Path, repo: &Path) -> Result<bool> {
    let output = Command::new(BIN)
        .args([
            "orchestrate",
            "run",
            plan.to_str().context("plan path utf8")?,
            "--repo",
            repo.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("run unsupported orchestration")?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("orchestration assignment creation is temporarily unsupported"),
        "unexpected orchestration refusal: {stderr}"
    );
    Ok(true)
}

fn run_success_json_args(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_json_regardless<const N: usize>(args: [&str; N]) -> Result<(Value, bool)> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    let report = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse orchestration json from stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((report, output.status.success()))
}

fn assert_orchestration_failed_closed(summary: &Value) -> Result<()> {
    assert_eq!(summary["success"], false);
    assert_eq!(summary["agents"][0]["status"], "failed");
    let error = summary["agents"][0]["error"]
        .as_str()
        .context("orchestration error")?;
    assert!(
        error.contains("process-tree ownership") || error.contains("containment"),
        "unexpected fail-closed error: {error}"
    );
    assert_eq!(
        summary["agents"][0]["changed_paths"]
            .as_array()
            .context("changed paths")?
            .len(),
        0
    );
    Ok(())
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args([
            "init",
            "--repo",
            repo_path.to_str().context("repo path utf8")?,
            "--json",
        ])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fs::create_dir_all(repo_path.join("src")).context("create src")?;
    fs::write(repo_path.join("README.md"), "# Smoke\n").context("write readme")?;
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub fn ok() -> bool { true }\n",
    )
    .context("write lib")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "initial commit")?;

    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index().context("open index")?;
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .context("add all")?;
    index.write().context("write index")?;
    let tree_id = index.write_tree().context("write tree")?;
    let tree = repo.find_tree(tree_id).context("find tree")?;
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
    repo.commit(Some("HEAD"), &signature, &signature, message, &tree, &[])
        .context("commit")
}
