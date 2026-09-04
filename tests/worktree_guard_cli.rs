#![cfg(unix)]

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_maco");
const WORKTREE_GUARD_ASSET: &[u8] = include_bytes!("../assets/maco-worktree-guard.sh");
const WORKTREE_GUARD_ASSET_V3_LEGACY: &[u8] = include_bytes!("../assets/maco-worktree-guard-v3.sh");
const HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5: &str = r#"#!/usr/bin/env bash
# human-authorship-guard dispatcher v5
set -euo pipefail
self="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
previous="$self.human-authorship-previous"
input="$(mktemp)"
trap 'rm -f "$input"' EXIT
cat > "$input"
if [[ -x "$previous" ]]; then
  "$previous" "$@" < "$input"
fi

resolve_guard() {
  local name="$1"
  local repo_root
  local primary
  local common_dir
  local fallback

  repo_root="$(git rev-parse --show-toplevel)"
  primary="$repo_root/.agents/scripts/$name"
  if [[ -x "$primary" ]]; then
    printf '%s\n' "$primary"
    return 0
  fi

  if ! common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    printf 'human-authorship-guard dispatcher: cannot resolve Git common directory for %s\n' \
      "$name" >&2
    return 1
  fi
  fallback="$(dirname "$common_dir")/.agents/scripts/$name"
  if [[ -x "$fallback" ]]; then
    printf '%s\n' "$fallback"
    return 0
  fi

  printf 'human-authorship-guard dispatcher: missing executable guard %s; checked %s and %s\n' \
    "$name" "$primary" "$fallback" >&2
  return 1
}

authorship_guard="$(resolve_guard check-human-authorship)"
"$authorship_guard" approved-current
"$authorship_guard" pre-push-approved "${1:-}" < "$input"
private_guard="$(resolve_guard check-private-agent-paths)"
"$private_guard" pre-push "${1:-}" < "$input"
github_actor_guard="$(resolve_guard check-approved-github-actor)"
"$github_actor_guard"
"#;
const USER_PRE_PUSH: &str = "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'user-pre-push:%s\\n' \"${1:-}\" >> \"$common/user-hooks.log\"\ncat >> \"$common/user-pre-push.stdin\"\n";

#[test]
fn canonical_v5_then_primary_guard_preserves_both_enforcement_paths() -> Result<()> {
    let fixture = GuardFixture::new("v5-then-primary")?;
    let pre_commit = fixture.hooks.join("pre-commit");
    let pre_push = fixture.hooks.join("pre-push");
    let v5_previous = fixture.hooks.join("pre-push.human-authorship-previous");
    write_executable(
        &pre_commit,
        "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'user-pre-commit\\n' >> \"$common/user-hooks.log\"\n",
    )?;
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    let original_pre_commit = fs::read(&pre_commit)?;
    let original_pre_push = fs::read(&pre_push)?;
    let original_v5_previous = fs::read(&v5_previous)?;

    let installed = run_guard_json("install", &fixture.primary)?;
    assert_eq!(installed["status"], "installed");
    assert_eq!(installed["mode"], "primary");
    assert!(installed["pre_push_target"]
        .as_str()
        .context("missing pre-push target")?
        .ends_with("pre-push.human-authorship-previous"));
    assert_eq!(fs::read(&pre_push)?, original_pre_push);
    assert_eq!(
        fs::read(
            fixture
                .hooks
                .join("pre-push.human-authorship-previous.maco-worktree-guard-previous")
        )?,
        original_v5_previous
    );
    assert_eq!(
        fs::read(
            fixture
                .hooks
                .join("pre-commit.maco-worktree-guard-previous")
        )?,
        original_pre_commit
    );
    assert_eq!(
        run_guard_json("verify", &fixture.primary)?["status"],
        "verified"
    );
    assert_eq!(
        run_guard_json("install", &fixture.primary)?["status"],
        "already_installed"
    );
    install_canonical_v5_dispatcher(&fixture)?;
    assert_eq!(
        run_guard_json("verify", &fixture.primary)?["status"],
        "verified"
    );

    exercise_allowed_primary_push(&fixture, "v5-first")?;
    let user_log = fs::read_to_string(fixture.common.join("user-hooks.log"))?;
    assert!(user_log.contains("user-pre-commit"));
    assert!(user_log.contains("user-pre-push:origin"));
    assert!(user_log.contains("authorship:approved-current"));
    assert!(user_log.contains("authorship:pre-push-approved origin"));
    assert!(user_log.contains("private:pre-push origin"));
    assert!(user_log.contains("actor:"));
    assert!(
        fs::read_to_string(fixture.common.join("user-pre-push.stdin"))?.contains("refs/heads/main")
    );

    git_success(&fixture.primary, &["switch", "-q", "-c", "maco/blocked"])?;
    stage_file(&fixture.primary, "blocked.txt", "blocked\n")?;
    let blocked_commit = git(&fixture.primary, &["commit", "-m", "blocked commit"])?;
    assert_refusal(&blocked_commit, "commit", "maco/blocked");
    assert_success(
        git(
            &fixture.primary,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-q",
                "-m",
                "prepare blocked push",
            ],
        )?,
        "prepare blocked push",
    );
    let blocked_push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/maco/blocked"],
    )?;
    assert_refusal(&blocked_push, "push", "maco/blocked");

    let removed = run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(removed["status"], "removed");
    assert_eq!(fs::read(&pre_commit)?, original_pre_commit);
    assert_eq!(fs::read(&pre_push)?, original_pre_push);
    assert_eq!(fs::read(&v5_previous)?, original_v5_previous);
    assert!(!fixture.hooks.join(".maco-worktree-guard").exists());
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "already_absent"
    );
    Ok(())
}

#[test]
fn v5_first_order_keeps_the_user_hook_live_between_install_steps() -> Result<()> {
    let fixture = GuardFixture::new("v5-first-order")?;
    let pre_push = fixture.hooks.join("pre-push");
    let v5_previous = fixture.hooks.join("pre-push.human-authorship-previous");
    let guard_previous = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    let original_user_hook = fs::read(&pre_push)?;

    let guard_first = run_guard("install", &fixture.primary)?;
    assert!(!guard_first.status.success());
    assert!(String::from_utf8_lossy(&guard_first.stderr)
        .contains("human-authorship dispatcher v5 is missing or modified"));
    assert_eq!(fs::read(&pre_push)?, original_user_hook);
    assert!(!fixture.hooks.join(".maco-worktree-guard").exists());

    install_canonical_v5_dispatcher(&fixture)?;
    let interrupted_verify = run_guard("verify", &fixture.primary)?;
    assert!(!interrupted_verify.status.success());
    assert!(String::from_utf8_lossy(&interrupted_verify.stderr)
        .contains("worktree guard state is missing"));
    exercise_allowed_primary_push(&fixture, "between-installers")?;
    let before_guard_log = fs::read_to_string(fixture.common.join("user-hooks.log"))?;
    assert!(before_guard_log.contains("user-pre-push:origin"));
    assert!(before_guard_log.contains("authorship:pre-push-approved origin"));

    assert_eq!(
        run_guard_json("install", &fixture.primary)?["status"],
        "installed"
    );
    assert_eq!(
        fs::read(&pre_push)?,
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes()
    );
    assert_eq!(fs::read(&v5_previous)?, WORKTREE_GUARD_ASSET);
    assert_eq!(fs::read(&guard_previous)?, original_user_hook);
    assert_eq!(
        fs::read_to_string(fixture.hooks.join(".maco-worktree-guard/pre-push-target"))?,
        "pre-push.human-authorship-previous\n"
    );
    assert_eq!(
        run_guard_json("verify", &fixture.primary)?["status"],
        "verified"
    );
    assert_eq!(
        run_guard_json("install", &fixture.primary)?["status"],
        "already_installed"
    );
    exercise_allowed_primary_push(&fixture, "after-worktree-guard")?;
    let user_log = fs::read_to_string(fixture.common.join("user-hooks.log"))?;
    assert!(user_log.contains("user-pre-push:origin"));
    assert!(user_log.contains("authorship:pre-push-approved origin"));
    assert!(user_log.contains("private:pre-push origin"));
    assert!(user_log.contains("actor:"));

    git_success(&fixture.primary, &["switch", "-q", "-c", "maco/v5-first"])?;
    stage_file(&fixture.primary, "blocked.txt", "blocked\n")?;
    let blocked_commit = git(&fixture.primary, &["commit", "-m", "blocked commit"])?;
    assert_refusal(&blocked_commit, "commit", "maco/v5-first");
    assert_success(
        git(
            &fixture.primary,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-q",
                "-m",
                "prepare v5-first blocked push",
            ],
        )?,
        "prepare v5-first blocked push",
    );
    let blocked_push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/maco/v5-first"],
    )?;
    assert_refusal(&blocked_push, "push", "maco/v5-first");

    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(
        fs::read(&pre_push)?,
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes()
    );
    assert_eq!(fs::read(&v5_previous)?, original_user_hook);
    assert!(!guard_previous.exists());
    exercise_allowed_primary_push(&fixture, "after-uninstall")?;
    Ok(())
}

#[test]
fn tampered_v5_dispatcher_fails_closed_before_and_after_installation() -> Result<()> {
    let fixture = GuardFixture::new("tampered-v5")?;
    let pre_push = fixture.hooks.join("pre-push");
    let v5_previous = fixture.hooks.join("pre-push.human-authorship-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    let original_previous = fs::read(&v5_previous)?;
    let tampered =
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.replace("\"$github_actor_guard\"\n", ":\n");
    write_executable(&pre_push, &tampered)?;

    let install = run_guard("install", &fixture.primary)?;
    assert!(!install.status.success());
    assert!(String::from_utf8_lossy(&install.stderr)
        .contains("human-authorship dispatcher v5 is missing or modified"));
    assert_eq!(fs::read(&pre_push)?, tampered.as_bytes());
    assert_eq!(fs::read(&v5_previous)?, original_previous);
    assert!(!fixture.hooks.join(".maco-worktree-guard").exists());

    write_executable(&pre_push, HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5)?;
    run_guard_json("install", &fixture.primary)?;
    write_executable(&pre_push, &tampered)?;
    for operation in ["verify", "uninstall"] {
        let output = run_guard(operation, &fixture.primary)?;
        assert!(!output.status.success(), "{operation} accepted tampered v5");
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("human-authorship dispatcher v5 is missing or modified"));
    }
    assert_eq!(fs::read(&pre_push)?, tampered.as_bytes());
    assert_eq!(fs::read(&v5_previous)?, WORKTREE_GUARD_ASSET);
    assert!(fixture.hooks.join(".maco-worktree-guard").is_dir());
    Ok(())
}

#[test]
fn tampered_outer_dispatcher_refuses_an_ordinary_push_before_the_user_hook() -> Result<()> {
    let fixture = GuardFixture::new("tampered-outer-runtime")?;
    let pre_push = fixture.hooks.join("pre-push");
    let chained = fixture.hooks.join("pre-push.human-authorship-previous");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    stage_file(&fixture.primary, "tampered-outer.txt", "tampered\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare tampered outer push"],
    )?;

    let tampered = format!(
        "{}# retained nested invocation, modified outer bytes\n",
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5
    );
    assert!(tampered.contains("\"$previous\" \"$@\" < \"$input\""));
    write_executable(&pre_push, &tampered)?;
    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert!(
        !push.status.success(),
        "tampered outer dispatcher allowed push"
    );
    assert!(String::from_utf8_lossy(&push.stderr).contains("installation state is invalid"));
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);
    assert_eq!(fs::read(&user_backup)?, USER_PRE_PUSH.as_bytes());
    assert!(
        !fixture.common.join("user-hooks.log").exists(),
        "a preserved or outer guard hook ran before the outer-integrity refusal"
    );
    Ok(())
}

#[test]
fn executable_outer_without_nested_guard_is_cli_detected_but_ordinary_push_succeeds() -> Result<()>
{
    let fixture = GuardFixture::new("outer-omits-nested-guard")?;
    let pre_push = fixture.hooks.join("pre-push");
    let chained = fixture.hooks.join("pre-push.human-authorship-previous");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    let replacement_log = fixture.common.join("outer-replacement.log");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    stage_file(&fixture.primary, "outer-omits-guard.txt", "replacement\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare omitted nested guard push"],
    )?;

    let replacement = r#"#!/bin/sh
common=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1
printf 'replacement-only\n' >> "$common/outer-replacement.log"
"#;
    assert!(!replacement.contains("human-authorship-previous"));
    write_executable(&pre_push, replacement)?;

    let verify = run_guard("verify", &fixture.primary)?;
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr)
        .contains("human-authorship dispatcher v5 is missing or modified"));
    assert!(!replacement_log.exists());

    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert_success(push, "push with outer dispatcher replacement");
    assert_eq!(fs::read_to_string(&replacement_log)?, "replacement-only\n");
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);
    assert_eq!(fs::read(&user_backup)?, USER_PRE_PUSH.as_bytes());
    assert!(
        !fixture.common.join("user-hooks.log").exists(),
        "the preserved user hook ran despite the omitted nested invocation"
    );
    Ok(())
}

#[test]
fn executable_outer_mode_drift_refuses_commit_merge_and_push_before_prior_hooks() -> Result<()> {
    let commit_fixture = GuardFixture::new("outer-mode-commit")?;
    write_executable(
        &commit_fixture.hooks.join("pre-commit"),
        "#!/bin/sh\nprintf 'user-pre-commit\\n' >> \"$(git rev-parse --git-common-dir)/user-hooks.log\"\n",
    )?;
    install_v5_guard_bundle(&commit_fixture)?;
    install_canonical_v5_dispatcher(&commit_fixture)?;
    run_guard_json("install", &commit_fixture.primary)?;
    fs::set_permissions(
        commit_fixture.hooks.join("pre-push"),
        fs::Permissions::from_mode(0o775),
    )?;
    stage_file(&commit_fixture.primary, "mode-commit.txt", "mode\n")?;
    let commit = git(
        &commit_fixture.primary,
        &["commit", "-m", "outer mode commit"],
    )?;
    assert!(
        !commit.status.success(),
        "mode-drifted outer allowed commit"
    );
    assert!(String::from_utf8_lossy(&commit.stderr).contains("installation state is invalid"));
    assert!(!commit_fixture.common.join("user-hooks.log").exists());

    let push_fixture = GuardFixture::new("outer-mode-push")?;
    write_executable(&push_fixture.hooks.join("pre-push"), USER_PRE_PUSH)?;
    install_v5_guard_bundle(&push_fixture)?;
    install_canonical_v5_dispatcher(&push_fixture)?;
    run_guard_json("install", &push_fixture.primary)?;
    stage_file(&push_fixture.primary, "mode-push.txt", "mode\n")?;
    git_success(
        &push_fixture.primary,
        &["commit", "-q", "-m", "prepare outer mode push"],
    )?;
    fs::set_permissions(
        push_fixture.hooks.join("pre-push"),
        fs::Permissions::from_mode(0o775),
    )?;
    let push = git(
        &push_fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert!(!push.status.success(), "mode-drifted outer allowed push");
    assert!(String::from_utf8_lossy(&push.stderr).contains("installation state is invalid"));
    assert!(!push_fixture.common.join("user-hooks.log").exists());
    for operation in ["install", "verify", "uninstall"] {
        let output = run_guard(operation, &push_fixture.primary)?;
        assert!(
            !output.status.success(),
            "{operation} accepted a mode-drifted outer dispatcher"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("exact mode 0755"));
    }

    let merge_fixture = GuardFixture::new("outer-mode-merge")?;
    write_executable(
        &merge_fixture.hooks.join("pre-merge-commit"),
        "#!/bin/sh\nprintf 'user-pre-merge\\n' >> \"$(git rev-parse --git-common-dir)/user-hooks.log\"\n",
    )?;
    install_v5_guard_bundle(&merge_fixture)?;
    install_canonical_v5_dispatcher(&merge_fixture)?;
    run_guard_json("install", &merge_fixture.primary)?;
    git_success(&merge_fixture.primary, &["switch", "-q", "-c", "topic"])?;
    stage_file(&merge_fixture.primary, "topic-mode.txt", "topic\n")?;
    git_success(
        &merge_fixture.primary,
        &["commit", "-q", "-m", "topic mode commit"],
    )?;
    git_success(&merge_fixture.primary, &["switch", "-q", "main"])?;
    stage_file(&merge_fixture.primary, "main-mode.txt", "main\n")?;
    git_success(
        &merge_fixture.primary,
        &["commit", "-q", "-m", "main mode commit"],
    )?;
    fs::set_permissions(
        merge_fixture.hooks.join("pre-push"),
        fs::Permissions::from_mode(0o775),
    )?;
    let merge = git(
        &merge_fixture.primary,
        &["merge", "--no-ff", "topic", "-m", "outer mode merge"],
    )?;
    assert!(!merge.status.success(), "mode-drifted outer allowed merge");
    assert!(String::from_utf8_lossy(&merge.stderr).contains("installation state is invalid"));
    assert!(!merge_fixture.common.join("user-hooks.log").exists());
    Ok(())
}

#[test]
fn non_executable_outer_is_cli_detected_but_git_skips_the_push_hook() -> Result<()> {
    let fixture = GuardFixture::new("outer-mode-non-executable")?;
    let pre_push = fixture.hooks.join("pre-push");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    stage_file(&fixture.primary, "non-executable-outer.txt", "mode\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare skipped push hook"],
    )?;
    fs::set_permissions(&pre_push, fs::Permissions::from_mode(0o644))?;

    let verify = run_guard("verify", &fixture.primary)?;
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("exact mode 0755"));
    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert_success(push, "push with Git-skipped non-executable outer hook");
    assert!(!fixture.common.join("user-hooks.log").exists());
    Ok(())
}

#[test]
fn exact_legacy_install_upgrades_in_place_without_changing_backups() -> Result<()> {
    let fixture = GuardFixture::new("legacy-upgrade")?;
    let pre_commit = fixture.hooks.join("pre-commit");
    let pre_merge = fixture.hooks.join("pre-merge-commit");
    let pre_push = fixture.hooks.join("pre-push");
    write_executable(&pre_commit, "#!/bin/sh\nexit 0\n")?;
    write_executable(&pre_merge, "#!/bin/sh\nexit 0\n")?;
    write_executable(&pre_push, USER_PRE_PUSH)?;
    let originals = [
        fs::read(&pre_commit)?,
        fs::read(&pre_merge)?,
        fs::read(&pre_push)?,
    ];
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let targets = active_guard_targets(&fixture);
    let backups = targets.each_ref().map(|target| guard_backup_path(target));
    let backup_snapshots = backups
        .each_ref()
        .map(|backup| (fs::read(backup), fs::symlink_metadata(backup)))
        .map(|(bytes, metadata)| {
            Ok::<_, anyhow::Error>((bytes?, metadata?.permissions().mode() & 0o7777))
        });
    let backup_snapshots = backup_snapshots.into_iter().collect::<Result<Vec<_>>>()?;
    for target in &targets {
        fs::write(target, WORKTREE_GUARD_ASSET_V3_LEGACY)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    }

    let verify = run_guard("verify", &fixture.primary)?;
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("requires an in-place upgrade"));
    assert_eq!(
        run_guard_json("install", &fixture.primary)?["status"],
        "installed"
    );
    for (target, (backup, snapshot)) in targets
        .iter()
        .zip(backups.iter().zip(backup_snapshots.iter()))
    {
        assert_eq!(fs::read(target)?, WORKTREE_GUARD_ASSET);
        assert_eq!(fs::read(backup)?, snapshot.0);
        assert_eq!(
            fs::symlink_metadata(backup)?.permissions().mode() & 0o7777,
            snapshot.1
        );
    }
    assert_eq!(
        run_guard_json("install", &fixture.primary)?["status"],
        "already_installed"
    );
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(fs::read(&pre_commit)?, originals[0]);
    assert_eq!(fs::read(&pre_merge)?, originals[1]);
    assert_eq!(
        fs::read(fixture.hooks.join("pre-push.human-authorship-previous"))?,
        originals[2]
    );
    assert_eq!(
        fs::read(&pre_push)?,
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes()
    );
    Ok(())
}

#[test]
fn interrupted_legacy_upgrade_is_recovered_before_uninstall() -> Result<()> {
    let fixture = GuardFixture::new("legacy-upgrade-interrupted")?;
    let pre_push = fixture.hooks.join("pre-push");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let targets = active_guard_targets(&fixture);
    let nested = &targets[0];
    let pre_commit = &targets[1];
    let pre_merge = &targets[2];
    fs::write(pre_commit, WORKTREE_GUARD_ASSET_V3_LEGACY)?;
    fs::set_permissions(pre_commit, fs::Permissions::from_mode(0o755))?;
    fs::write(pre_merge, WORKTREE_GUARD_ASSET_V3_LEGACY)?;
    fs::set_permissions(pre_merge, fs::Permissions::from_mode(0o755))?;
    assert_eq!(fs::read(nested)?, WORKTREE_GUARD_ASSET);

    let staged_commit = guard_staged_path(pre_commit);
    write_executable_bytes(&staged_commit, WORKTREE_GUARD_ASSET)?;
    let staged_merge = guard_staged_path(pre_merge);
    write_executable(&staged_merge, "#!/bin/sh\nexit 9\n")?;
    let refused = run_guard("install", &fixture.primary)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("staged upgrade changed"));
    assert_eq!(fs::read(pre_commit)?, WORKTREE_GUARD_ASSET_V3_LEGACY);
    assert_eq!(fs::read(pre_merge)?, WORKTREE_GUARD_ASSET_V3_LEGACY);

    fs::remove_file(&staged_merge)?;
    let interrupted_verify = run_guard("verify", &fixture.primary)?;
    assert!(!interrupted_verify.status.success());
    assert!(String::from_utf8_lossy(&interrupted_verify.stderr)
        .contains("requires an in-place upgrade"));
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert!(!staged_commit.exists());
    assert!(!fixture.hooks.join(".maco-worktree-guard").exists());
    assert_eq!(
        fs::read(fixture.hooks.join("pre-push.human-authorship-previous"))?,
        USER_PRE_PUSH.as_bytes()
    );
    assert_eq!(
        fs::read(&pre_push)?,
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes()
    );
    Ok(())
}

#[test]
fn pre_push_target_tamper_cannot_redirect_or_strand_the_user_hook() -> Result<()> {
    let fixture = GuardFixture::new("target-tamper")?;
    let pre_push = fixture.hooks.join("pre-push");
    let chained = fixture.hooks.join("pre-push.human-authorship-previous");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    let target_state = fixture.hooks.join(".maco-worktree-guard/pre-push-target");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    let original_user_hook = fs::read(&chained)?;
    run_guard_json("install", &fixture.primary)?;

    fs::write(&target_state, b"pre-push\n")?;
    let verify = run_guard("verify", &fixture.primary)?;
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr)
        .contains("worktree guard pre-push composition state is invalid"));

    stage_file(&fixture.primary, "tampered-target.txt", "tampered\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare tampered target push"],
    )?;
    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert!(!push.status.success());
    assert!(String::from_utf8_lossy(&push.stderr).contains("installation state is invalid"));
    assert_eq!(
        fs::read(&pre_push)?,
        HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes()
    );
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);
    assert_eq!(fs::read(&user_backup)?, original_user_hook);
    assert!(!fixture.common.join("user-hooks.log").exists());

    let uninstall = run_guard("uninstall", &fixture.primary)?;
    assert!(!uninstall.status.success());
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);
    assert_eq!(fs::read(&user_backup)?, original_user_hook);

    fs::write(&target_state, b"pre-push.human-authorship-previous\n")?;
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(fs::read(&chained)?, original_user_hook);
    assert!(!user_backup.exists());
    exercise_allowed_primary_push(&fixture, "target-repaired-uninstall")?;
    assert!(
        fs::read_to_string(fixture.common.join("user-hooks.log"))?.contains("user-pre-push:origin")
    );
    Ok(())
}

#[test]
fn mode_suffix_state_tamper_blocks_runtime_verify_and_uninstall() -> Result<()> {
    let fixture = GuardFixture::new("mode-state-tamper")?;
    let pre_push = fixture.hooks.join("pre-push");
    let chained = fixture.hooks.join("pre-push.human-authorship-previous");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    let state_path = fixture.hooks.join(".maco-worktree-guard/pre-push-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let original_user_hook = fs::read(&user_backup)?;
    let original_mode = fs::symlink_metadata(&user_backup)?.permissions().mode() & 0o7777;
    let original_state = fs::read_to_string(&state_path)?;
    let state_line = original_state
        .strip_suffix('\n')
        .context("preserved-hook state is not newline terminated")?;
    let (binding_prefix, recorded_mode) = state_line
        .rsplit_once(':')
        .context("preserved-hook state has no mode suffix")?;
    assert_eq!(recorded_mode, "755");

    fs::write(&state_path, format!("{binding_prefix}:644\n"))?;
    stage_file(&fixture.primary, "mode-state-tamper.txt", "tampered\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare mode state tamper push"],
    )?;
    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert!(!push.status.success());
    assert!(String::from_utf8_lossy(&push.stderr).contains("installation state is invalid"));
    assert!(!fixture.common.join("user-hooks.log").exists());

    for operation in ["verify", "uninstall"] {
        let output = run_guard(operation, &fixture.primary)?;
        assert!(
            !output.status.success(),
            "{operation} accepted a tampered mode suffix"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("preserved-hook binding changed"));
    }
    assert_eq!(fs::read(&user_backup)?, original_user_hook);
    assert_eq!(
        fs::symlink_metadata(&user_backup)?.permissions().mode() & 0o7777,
        original_mode
    );
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);

    fs::write(&state_path, original_state)?;
    assert_eq!(
        run_guard_json("verify", &fixture.primary)?["status"],
        "verified"
    );
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(fs::read(&chained)?, original_user_hook);
    assert_eq!(
        fs::symlink_metadata(&chained)?.permissions().mode() & 0o7777,
        original_mode
    );
    assert!(!user_backup.exists());
    exercise_allowed_primary_push(&fixture, "mode-state-repaired")?;
    assert!(
        fs::read_to_string(fixture.common.join("user-hooks.log"))?.contains("user-pre-push:origin")
    );
    Ok(())
}

#[test]
fn chmod_only_executable_backup_drift_blocks_runtime_verify_and_uninstall() -> Result<()> {
    let fixture = GuardFixture::new("chmod-backup-tamper")?;
    let pre_push = fixture.hooks.join("pre-push");
    let chained = fixture.hooks.join("pre-push.human-authorship-previous");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let original_user_hook = fs::read(&user_backup)?;
    let original_mode = fs::symlink_metadata(&user_backup)?.permissions().mode() & 0o7777;
    assert_eq!(original_mode, 0o755);

    fs::set_permissions(&user_backup, fs::Permissions::from_mode(0o644))?;
    assert_eq!(fs::read(&user_backup)?, original_user_hook);
    stage_file(&fixture.primary, "chmod-backup-tamper.txt", "tampered\n")?;
    git_success(
        &fixture.primary,
        &["commit", "-q", "-m", "prepare chmod backup tamper push"],
    )?;
    let push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/main"],
    )?;
    assert!(!push.status.success());
    assert!(String::from_utf8_lossy(&push.stderr).contains("installation state is invalid"));
    assert!(!fixture.common.join("user-hooks.log").exists());

    for operation in ["verify", "uninstall"] {
        let output = run_guard(operation, &fixture.primary)?;
        assert!(
            !output.status.success(),
            "{operation} accepted chmod-only backup drift"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("preserved-hook binding changed"));
    }
    assert_eq!(fs::read(&user_backup)?, original_user_hook);
    assert_eq!(
        fs::symlink_metadata(&user_backup)?.permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(fs::read(&chained)?, WORKTREE_GUARD_ASSET);

    fs::set_permissions(&user_backup, fs::Permissions::from_mode(original_mode))?;
    assert_eq!(
        run_guard_json("verify", &fixture.primary)?["status"],
        "verified"
    );
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(fs::read(&chained)?, original_user_hook);
    assert_eq!(
        fs::symlink_metadata(&chained)?.permissions().mode() & 0o7777,
        original_mode
    );
    assert!(!user_backup.exists());
    exercise_allowed_primary_push(&fixture, "chmod-backup-repaired")?;
    assert!(
        fs::read_to_string(fixture.common.join("user-hooks.log"))?.contains("user-pre-push:origin")
    );
    Ok(())
}

#[test]
fn missing_or_replaced_user_backup_blocks_verify_and_uninstall() -> Result<()> {
    let fixture = GuardFixture::new("backup-binding")?;
    let pre_push = fixture.hooks.join("pre-push");
    let user_backup = fixture
        .hooks
        .join("pre-push.human-authorship-previous.maco-worktree-guard-previous");
    write_executable(&pre_push, USER_PRE_PUSH)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let original_user_hook = fs::read(&user_backup)?;

    fs::remove_file(&user_backup)?;
    for operation in ["verify", "uninstall"] {
        let output = run_guard(operation, &fixture.primary)?;
        assert!(
            !output.status.success(),
            "{operation} accepted a missing backup"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("preserved-hook binding changed"));
    }
    assert!(fixture.hooks.join(".maco-worktree-guard").is_dir());

    write_executable(&user_backup, "#!/bin/sh\nexit 0\n")?;
    for operation in ["verify", "uninstall"] {
        let output = run_guard(operation, &fixture.primary)?;
        assert!(
            !output.status.success(),
            "{operation} accepted a replaced backup"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("preserved-hook binding changed"));
    }

    fs::write(&user_backup, &original_user_hook)?;
    fs::set_permissions(&user_backup, fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        run_guard_json("uninstall", &fixture.primary)?["status"],
        "removed"
    );
    assert_eq!(
        fs::read(fixture.hooks.join("pre-push.human-authorship-previous"))?,
        original_user_hook
    );
    Ok(())
}

#[test]
fn already_absent_uninstall_refuses_an_orphaned_backup() -> Result<()> {
    let fixture = GuardFixture::new("orphaned-backup")?;
    let orphan = fixture
        .hooks
        .join("pre-commit.maco-worktree-guard-previous");
    write_executable(&orphan, "#!/bin/sh\nexit 0\n")?;

    let uninstall = run_guard("uninstall", &fixture.primary)?;
    assert!(!uninstall.status.success());
    assert!(String::from_utf8_lossy(&uninstall.stderr)
        .contains("preserved or staged hook exists without owned state"));
    assert!(orphan.exists());
    Ok(())
}

#[test]
fn shared_default_hook_allows_linked_lane_and_blocks_its_branch_from_primary() -> Result<()> {
    let fixture = GuardFixture::new("linked-noop")?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    let linked = fixture.temp.path().join("linked");
    git_success(
        &fixture.primary,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "maco/linked-lane",
            linked.to_str().context("linked path is not UTF-8")?,
        ],
    )?;

    stage_file(&linked, "linked.txt", "linked\n")?;
    assert_success(
        git(&linked, &["commit", "-q", "-m", "linked lane commit"])?,
        "linked lane commit",
    );
    let hooks_path = git(
        &fixture.primary,
        &["config", "--local", "--get", "core.hooksPath"],
    )?;
    assert!(
        !hooks_path.status.success(),
        "guard installation must not create repository-local core.hooksPath"
    );

    git_success(
        &fixture.primary,
        &[
            "switch",
            "-q",
            "--ignore-other-worktrees",
            "maco/linked-lane",
        ],
    )?;
    stage_file(&fixture.primary, "primary.txt", "wrong worktree\n")?;
    let blocked = git(&fixture.primary, &["commit", "-m", "wrong worktree commit"])?;
    assert_refusal(&blocked, "commit", "maco/linked-lane");
    Ok(())
}

#[test]
fn primary_guard_blocks_a_merge_commit_on_an_agent_branch() -> Result<()> {
    let fixture = GuardFixture::new("merge-commit")?;
    let pre_merge_commit = fixture.hooks.join("pre-merge-commit");
    write_executable(&pre_merge_commit, "#!/bin/sh\nexit 0\n")?;
    let original_pre_merge_commit = fs::read(&pre_merge_commit)?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;

    git_success(&fixture.primary, &["switch", "-q", "-c", "topic"])?;
    stage_file(&fixture.primary, "topic.txt", "topic\n")?;
    git_success(&fixture.primary, &["commit", "-q", "-m", "topic commit"])?;
    git_success(&fixture.primary, &["switch", "-q", "main"])?;
    stage_file(&fixture.primary, "main.txt", "main\n")?;
    git_success(&fixture.primary, &["commit", "-q", "-m", "main commit"])?;
    git_success(
        &fixture.primary,
        &["switch", "-q", "-c", "maco/merge-blocked"],
    )?;

    let blocked = git(
        &fixture.primary,
        &["merge", "--no-ff", "topic", "-m", "blocked merge commit"],
    )?;
    assert_refusal(&blocked, "commit", "maco/merge-blocked");
    run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(fs::read(&pre_merge_commit)?, original_pre_merge_commit);
    Ok(())
}

#[test]
fn verify_and_uninstall_fail_closed_after_guard_hook_changes() -> Result<()> {
    let fixture = GuardFixture::new("changed-hook")?;
    install_v5_guard_bundle(&fixture)?;
    install_canonical_v5_dispatcher(&fixture)?;
    run_guard_json("install", &fixture.primary)?;
    fs::write(fixture.hooks.join("pre-commit"), b"#!/bin/sh\nexit 0\n")?;

    let verify = run_guard("verify", &fixture.primary)?;
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("worktree guard hook changed"));
    let uninstall = run_guard("uninstall", &fixture.primary)?;
    assert!(!uninstall.status.success());
    assert!(fixture.hooks.join(".maco-worktree-guard").is_dir());
    assert_eq!(
        fs::read(fixture.hooks.join("pre-commit"))?,
        b"#!/bin/sh\nexit 0\n"
    );
    Ok(())
}

#[test]
fn install_refuses_a_custom_hooks_path_without_changing_it() -> Result<()> {
    let fixture = GuardFixture::new("custom-hooks-path")?;
    git_success(
        &fixture.primary,
        &["config", "core.hooksPath", ".git/custom-hooks"],
    )?;

    let install = run_guard("install", &fixture.primary)?;
    assert!(!install.status.success());
    assert!(String::from_utf8_lossy(&install.stderr).contains("remove core.hooksPath"));
    assert_eq!(
        git_stdout(&fixture.primary, &["config", "--get", "core.hooksPath"])?,
        ".git/custom-hooks"
    );
    assert!(!fixture.hooks.join(".maco-worktree-guard").exists());
    Ok(())
}

struct GuardFixture {
    temp: TempDir,
    primary: PathBuf,
    common: PathBuf,
    hooks: PathBuf,
}

impl GuardFixture {
    fn new(name: &str) -> Result<Self> {
        let temp = tempfile::Builder::new().prefix(name).tempdir()?;
        let primary = temp.path().join("primary");
        let origin = temp.path().join("origin.git");
        command_success(
            Command::new("git")
                .args(["init", "-q", "--initial-branch=main"])
                .arg(&primary),
            "initialize primary repository",
        )?;
        command_success(
            Command::new("git")
                .args(["init", "-q", "--bare"])
                .arg(&origin),
            "initialize bare origin",
        )?;
        git_success(&primary, &["config", "user.name", "Guard Test"])?;
        git_success(
            &primary,
            &["config", "user.email", "guard-test@example.invalid"],
        )?;
        git_success(
            &primary,
            &[
                "remote",
                "add",
                "origin",
                origin.to_str().context("origin path is not UTF-8")?,
            ],
        )?;
        stage_file(&primary, "README.md", "# Test\n")?;
        git_success(&primary, &["commit", "-q", "-m", "initial"])?;
        let common = PathBuf::from(git_stdout(
            &primary,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?);
        let hooks = common.join("hooks");
        Ok(Self {
            temp,
            primary,
            common,
            hooks,
        })
    }
}

fn install_v5_guard_bundle(fixture: &GuardFixture) -> Result<()> {
    let scripts = fixture.primary.join(".agents/scripts");
    fs::create_dir_all(&scripts)?;
    for (name, label) in [
        ("check-human-authorship", "authorship"),
        ("check-private-agent-paths", "private"),
        ("check-approved-github-actor", "actor"),
    ] {
        write_executable(
            &scripts.join(name),
            &format!(
                "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf '{label}:%s\\n' \"$*\" >> \"$common/user-hooks.log\"\n"
            ),
        )?;
    }
    Ok(())
}

fn install_canonical_v5_dispatcher(fixture: &GuardFixture) -> Result<()> {
    let pre_push = fixture.hooks.join("pre-push");
    let previous = fixture.hooks.join("pre-push.human-authorship-previous");
    if fs::read(&pre_push).ok().as_deref()
        == Some(HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5.as_bytes())
    {
        return Ok(());
    }
    if pre_push.exists() {
        if previous.exists() {
            bail!(
                "test v5 installer refused existing previous hook {}",
                previous.display()
            );
        }
        fs::rename(&pre_push, &previous)?;
    }
    write_executable(&pre_push, HUMAN_AUTHORSHIP_PRE_PUSH_DISPATCHER_V5)
}

fn exercise_allowed_primary_push(fixture: &GuardFixture, label: &str) -> Result<()> {
    let path = format!("allowed-{label}.txt");
    stage_file(&fixture.primary, &path, "allowed\n")?;
    assert_success(
        git(
            &fixture.primary,
            &["commit", "-q", "-m", &format!("allowed {label} commit")],
        )?,
        "allowed primary commit",
    );
    assert_success(
        git(
            &fixture.primary,
            &["push", "-q", "origin", "HEAD:refs/heads/main"],
        )?,
        "allowed primary push",
    );
    Ok(())
}

fn run_guard_json(operation: &str, repo: &Path) -> Result<Value> {
    let output = run_guard(operation, repo)?;
    assert_success(output.clone(), operation);
    serde_json::from_slice(&output.stdout).context("parse worktree guard JSON")
}

fn run_guard(operation: &str, repo: &Path) -> Result<Output> {
    Command::new(BIN)
        .args(["worktree", "guard", operation, "--repo"])
        .arg(repo)
        .arg("--json")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .context("run worktree guard command")
}

fn stage_file(repo: &Path, relative: &str, contents: &str) -> Result<()> {
    fs::write(repo.join(relative), contents)?;
    git_success(repo, &["add", relative])
}

fn write_executable(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn write_executable_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn active_guard_targets(fixture: &GuardFixture) -> [PathBuf; 3] {
    [
        fixture.hooks.join("pre-push.human-authorship-previous"),
        fixture.hooks.join("pre-commit"),
        fixture.hooks.join("pre-merge-commit"),
    ]
}

fn guard_backup_path(target: &Path) -> PathBuf {
    let name = target.file_name().expect("test hook path has a filename");
    let mut backup = name.to_os_string();
    backup.push(".maco-worktree-guard-previous");
    target.with_file_name(backup)
}

fn guard_staged_path(target: &Path) -> PathBuf {
    let name = target.file_name().expect("test hook path has a filename");
    let mut staged = name.to_os_string();
    staged.push(".maco-worktree-guard-installing");
    target.with_file_name(staged)
}

fn git(repo: &Path, args: &[&str]) -> Result<Output> {
    Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .context("run Git command")
}

fn git_success(repo: &Path, args: &[&str]) -> Result<()> {
    assert_success(git(repo, args)?, &format!("git {}", args.join(" ")));
    Ok(())
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = git(repo, args)?;
    assert_success(output.clone(), &format!("git {}", args.join(" ")));
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn command_success(command: &mut Command, label: &str) -> Result<()> {
    let output = command
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .with_context(|| format!("run {label}"))?;
    assert_success(output, label);
    Ok(())
}

fn assert_success(output: Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_refusal(output: &Output, action: &str, branch: &str) {
    assert!(!output.status.success(), "{action} unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("refusing {action}")), "{stderr}");
    assert!(stderr.contains(branch), "{stderr}");
}
