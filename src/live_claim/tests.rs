use super::*;
use std::sync::Arc;

#[cfg(target_os = "linux")]
struct ClaimAtomicTestFaultGuard {
    previous_errno: Option<i32>,
    previous_crash: Option<ClaimFallbackCrashPoint>,
}

#[cfg(target_os = "linux")]
impl ClaimAtomicTestFaultGuard {
    fn install(
        errno: Option<i32>,
        crash: Option<ClaimFallbackCrashPoint>,
    ) -> ClaimAtomicTestFaultGuard {
        let previous_errno = CLAIM_TEST_EXCHANGE_ERRNO.with(|value| value.replace(errno));
        let previous_crash = CLAIM_TEST_FALLBACK_CRASH.with(|value| value.replace(crash));
        ClaimAtomicTestFaultGuard {
            previous_errno,
            previous_crash,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ClaimAtomicTestFaultGuard {
    fn drop(&mut self) {
        CLAIM_TEST_EXCHANGE_ERRNO.with(|value| value.set(self.previous_errno));
        CLAIM_TEST_FALLBACK_CRASH.with(|value| value.set(self.previous_crash));
    }
}

#[cfg(target_os = "linux")]
fn fallback_residue_paths(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = std::fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(CLAIM_FALLBACK_RESIDUE_PREFIX))
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn claim_text(
    claim_id: &str,
    owner: &str,
    status: &str,
    timestamp: &str,
    owned_surface: &str,
) -> String {
    format!(
            "# Claim: {claim_id}\n\n- Claim ID: {claim_id}\n- Owner: {owner}\n- Status: {status}\n- Created: {timestamp}\n- Updated: {timestamp}\n- Heartbeat: {timestamp}\n- Stale after minutes: 60\n- Owned files, regions, devices, or services:\n  - {owned_surface}: bounded test surface\n\n## Audit log\n\n- {timestamp} - {owner} created\n"
        )
}

fn initial_draft_text(
    claim_id: &str,
    owner: &str,
    status: &str,
    timestamp: &str,
    owned_surface: &str,
) -> String {
    format!(
            "# Claim: {claim_id}\n\n- Claim ID: {claim_id}\n- Owner: {owner}\n- Status: {status}\n- Created: {timestamp}\n- Updated: {timestamp}\n- Heartbeat: {timestamp}\n- Stale after minutes: 60\n- Owned files, regions, devices, or services:\n  - {owned_surface}: bounded test surface\n"
        )
}

fn write_claim(
    repo: &Path,
    claim_id: &str,
    owner: &str,
    status: &str,
    timestamp: &str,
) -> Result<PathBuf> {
    let directory = repo.join(CLAIMS_DIR);
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{claim_id}.md"));
    std::fs::write(
        &path,
        claim_text(
            claim_id,
            owner,
            status,
            timestamp,
            "Host-global transient service and runtime coordination",
        ),
    )?;
    Ok(path)
}

#[test]
fn parser_accepts_legacy_and_nonfilesystem_surfaces_but_rejects_strict_grammar_errors() {
    let legacy = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("legacy.md"),
            "# Claim: legacy\n\n- Owner: worker-a\n- Date: 2026-05-19\n- Status: active\n- Owned files, regions, devices, or services:\n  - Host-global transient service coordination: test\n",
        );
    assert!(legacy.issues.is_empty(), "{:?}", legacy.issues);
    assert_eq!(
        legacy.owned_files,
        vec![PathBuf::from("Host-global transient service coordination")]
    );

    let completed = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("completed.md"),
        &claim_text(
            "completed",
            "worker-a",
            "completed",
            "2026-05-19T00:00:00Z",
            "src/live_claim.rs",
        ),
    );
    assert!(completed.issues.iter().any(|issue| issue.field == "status"));

    let duplicate_owner = claim_text(
        "duplicate",
        "worker-a",
        "active",
        "2026-05-19T00:00:00Z",
        "src/live_claim.rs",
    )
    .replace("- Status:", "- Owner: worker-b\n- Status:");
    let duplicate = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("duplicate.md"),
        &duplicate_owner,
    );
    assert!(duplicate
        .issues
        .iter()
        .any(|issue| issue.message.contains("duplicate recognized field")));

    let mismatch = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("mismatch.md"),
        &claim_text(
            "different",
            "worker-a",
            "active",
            "2026-05-19T00:00:00Z",
            "src/live_claim.rs",
        ),
    );
    assert!(mismatch
        .issues
        .iter()
        .any(|issue| issue.message.contains("file name")));
}

#[test]
fn future_timestamps_are_unknown_and_cannot_be_override_released() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_claim(
        temp.path(),
        "future-claim",
        "future-claim",
        "active",
        "2026-05-21T00:00:00Z",
    )?;
    let now = LiveClock::parse("2026-05-20T00:00:00Z")?;
    let report = status(temp.path(), &now)?;
    assert_eq!(report.claims[0].liveness.state, "unknown");
    assert!(report.claims[0]
        .warnings
        .iter()
        .any(|warning| warning.contains("future")));
    let error = override_release_with_clock(
        temp.path(),
        "future-claim",
        "project-owner",
        "owner unavailable and bounded files are blocked",
        &now,
    )
    .expect_err("future claim must not be adopted as stale");
    assert!(error.to_string().contains("provably stale"));
    let heartbeat_error = heartbeat_with_clock(temp.path(), "future-claim", "future-claim", &now)
        .expect_err("future heartbeat generations must not be rolled back");
    assert!(heartbeat_error.to_string().contains("future or rollback"));
    Ok(())
}

#[test]
fn heartbeat_requires_exact_owner_and_override_requires_stale_safe_input() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = write_claim(
        temp.path(),
        "owner-claim",
        "owner-claim",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let original = std::fs::read(&path)?;
    let fresh = LiveClock::parse("2026-05-20T00:30:00Z")?;
    assert!(heartbeat_with_clock(temp.path(), "owner-claim", "other-owner", &fresh).is_err());
    assert_eq!(std::fs::read(&path)?, original);
    assert!(override_release_with_clock(
        temp.path(),
        "owner-claim",
        "project-owner",
        "fresh claim must remain owned",
        &fresh,
    )
    .is_err());
    assert_eq!(std::fs::read(&path)?, original);

    let stale = LiveClock::parse("2026-05-20T02:00:00Z")?;
    assert!(override_release_with_clock(
        temp.path(),
        "owner-claim",
        "project-owner",
        "line one\nline two",
        &stale,
    )
    .is_err());
    assert!(override_release_with_clock(
        temp.path(),
        "owner-claim",
        "project-owner",
        &format!("unsafe {} inline", char::from(96)),
        &stale,
    )
    .is_err());
    let report = heartbeat_with_clock(temp.path(), "owner-claim", "owner-claim", &fresh)?;
    assert_eq!(report.actor, "owner-claim");
    assert_eq!(
        report.file,
        PathBuf::from(CLAIMS_DIR).join("owner-claim.md")
    );
    let rollback = LiveClock::parse("2026-05-20T00:29:59Z")?;
    assert!(
        heartbeat_with_clock(temp.path(), "owner-claim", "owner-claim", &rollback)
            .expect_err("heartbeat rollback must fail")
            .to_string()
            .contains("future or rollback")
    );
    Ok(())
}

#[test]
fn atomic_mutation_cas_rejects_same_inode_and_replacement_races_for_every_mutator() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = write_claim(
        temp.path(),
        "content-race",
        "content-race",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let changed = claim_text(
        "content-race",
        "content-race",
        "active",
        "2026-05-20T00:01:00Z",
        "src/live_claim.rs",
    );
    let error = mutate_claim(
        temp.path(),
        "content-race",
        "content-race",
        &now,
        ClaimMutation::Heartbeat,
        |claim_path| {
            std::fs::write(claim_path, &changed)?;
            Ok(())
        },
    )
    .expect_err("same-inode content race must fail");
    assert!(error.to_string().contains("atomic mutation was refused"));
    assert_eq!(std::fs::read_to_string(&path)?, changed);

    for (claim_id, actor, mutation, mutation_now) in [
        (
            "heartbeat-race",
            "heartbeat-race",
            ClaimMutation::Heartbeat,
            "2026-05-20T00:30:00Z",
        ),
        (
            "release-race",
            "release-race",
            ClaimMutation::OwnerRelease {
                status: "done",
                reason: "bounded release race",
            },
            "2026-05-20T00:30:00Z",
        ),
        (
            "override-race",
            "project-owner",
            ClaimMutation::OverrideRelease {
                reason: "bounded override race",
            },
            "2026-05-20T02:00:00Z",
        ),
    ] {
        let second = tempfile::tempdir()?;
        let path = write_claim(
            second.path(),
            claim_id,
            claim_id,
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let replacement = claim_text(
            claim_id,
            claim_id,
            "active",
            "2026-05-20T00:02:00Z",
            "src/live_claim.rs",
        );
        let error = mutate_claim(
            second.path(),
            claim_id,
            actor,
            &LiveClock::parse(mutation_now)?,
            mutation,
            |claim_path| {
                std::fs::remove_file(claim_path)?;
                std::fs::write(claim_path, &replacement)?;
                Ok(())
            },
        )
        .expect_err("pathname replacement race must fail");
        assert!(error.to_string().contains("atomic mutation was refused"));
        assert_eq!(std::fs::read_to_string(&path)?, replacement);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_exchange_uses_noreplace_fallback_for_every_existing_claim_mutator() -> Result<()> {
    for (claim_id, actor, mutation, now, expected_status, expected_audit) in [
        (
            "fallback-heartbeat",
            "fallback-heartbeat",
            ClaimMutation::Heartbeat,
            "2026-05-20T00:30:00Z",
            "active",
            " heartbeat",
        ),
        (
            "fallback-release",
            "fallback-release",
            ClaimMutation::OwnerRelease {
                status: "done",
                reason: "bounded fallback release",
            },
            "2026-05-20T00:30:00Z",
            "done",
            "released claim as `done`",
        ),
        (
            "fallback-override",
            "project-owner",
            ClaimMutation::OverrideRelease {
                reason: "bounded stale fallback override",
            },
            "2026-05-20T02:00:00Z",
            "handoff",
            "override-release",
        ),
    ] {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            claim_id,
            claim_id,
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let report = {
            let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EINVAL), None);
            mutate_claim(
                temp.path(),
                claim_id,
                actor,
                &LiveClock::parse(now)?,
                mutation,
                |_| Ok(()),
            )?
        };
        assert_eq!(report.status.as_deref(), Some(expected_status));
        assert!(report.audit_entry.contains(expected_audit));
        assert!(std::fs::read_to_string(path)?.contains(expected_audit));
        assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn non_capability_exchange_error_preserves_cause_and_never_falls_back() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = write_claim(
        temp.path(),
        "exchange-eio",
        "exchange-eio",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let original = std::fs::read(&path)?;
    let error = {
        let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EIO), None);
        heartbeat_with_clock(
            temp.path(),
            "exchange-eio",
            "exchange-eio",
            &LiveClock::parse("2026-05-20T00:30:00Z")?,
        )
        .expect_err("non-capability exchange errors must not enter the fallback")
    };
    let chain = format!("{error:#}");
    assert!(chain.contains("claim compare-and-swap exchange failed"));
    assert!(chain.contains("Input/output error"), "{chain}");
    assert_eq!(std::fs::read(&path)?, original);
    assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn noreplace_fallback_rejects_target_and_other_board_generation_races() -> Result<()> {
    let target_race = tempfile::tempdir()?;
    let target_path = write_claim(
        target_race.path(),
        "fallback-target-race",
        "fallback-target-race",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let root = open_claims_root(&claims_dir(target_race.path()))?.context("target race root")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let (_, initial_board) = load_stable_claim_board(&root, &lock)?;
    let target_name = OsStr::new("fallback-target-race.md");
    let initial_target = initial_board
        .entries
        .get(target_name)
        .context("target race initial generation")?
        .clone();
    let directory = open_claim_board_directory(&root)?;
    let staged = stage_claim_file(&directory, target_name, b"bounded replacement")?;
    std::fs::remove_file(&target_path)?;
    std::fs::write(&target_path, b"racing direct replacement")?;
    let target_error = publish_existing_claim_noreplace_fallback(
        &root,
        &directory,
        &initial_board,
        target_name,
        &staged.generation.bytes,
        &initial_target,
        &staged,
    )
    .expect_err("fallback target CAS race must fail closed");
    assert!(format!("{target_error:#}").contains("old-generation residue was changed"));
    assert!(!target_path.exists());
    assert_eq!(
        fallback_residue_paths(&claims_dir(target_race.path()))?.len(),
        1
    );

    let board_race = tempfile::tempdir()?;
    let first_path = write_claim(
        board_race.path(),
        "fallback-board-first",
        "fallback-board-first",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let second_path = write_claim(
        board_race.path(),
        "fallback-board-second",
        "fallback-board-second",
        "done",
        "2026-05-20T00:00:00Z",
    )?;
    let original_first = std::fs::read(&first_path)?;
    let root = open_claims_root(&claims_dir(board_race.path()))?.context("board race root")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let (_, initial_board) = load_stable_claim_board(&root, &lock)?;
    let target_name = OsStr::new("fallback-board-first.md");
    let initial_target = initial_board
        .entries
        .get(target_name)
        .context("board race initial generation")?
        .clone();
    let directory = open_claim_board_directory(&root)?;
    let staged = stage_claim_file(&directory, target_name, b"bounded replacement")?;
    std::fs::write(
        &second_path,
        claim_text(
            "fallback-board-second",
            "fallback-board-second",
            "done",
            "2026-05-20T00:01:00Z",
            "src/changed.rs",
        ),
    )?;
    let board_error = publish_existing_claim_noreplace_fallback(
        &root,
        &directory,
        &initial_board,
        target_name,
        &staged.generation.bytes,
        &initial_target,
        &staged,
    )
    .expect_err("fallback whole-board CAS race must fail closed");
    assert!(format!("{board_error:#}").contains("another claim board entry changed"));
    assert_eq!(std::fs::read(&first_path)?, original_first);
    assert!(fallback_residue_paths(&claims_dir(board_race.path()))?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn noreplace_fallback_recovers_crashes_before_and_after_new_publication() -> Result<()> {
    for (claim_id, crash, expected_heartbeats) in [
        (
            "fallback-crash-old",
            ClaimFallbackCrashPoint::AfterOldDisplacement,
            0,
        ),
        (
            "fallback-crash-new",
            ClaimFallbackCrashPoint::AfterNewPublication,
            1,
        ),
    ] {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            claim_id,
            claim_id,
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let error = {
            let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EINVAL), Some(crash));
            heartbeat_with_clock(
                temp.path(),
                claim_id,
                claim_id,
                &LiveClock::parse("2026-05-20T00:30:00Z")?,
            )
            .expect_err("injected fallback crash must interrupt publication")
        };
        assert!(format!("{error:#}").contains("injected claim fallback crash"));
        assert_eq!(fallback_residue_paths(&claims_dir(temp.path()))?.len(), 1);
        assert_eq!(
            status(temp.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)?.claim_count,
            1
        );
        let recovered = std::fs::read_to_string(&path)?;
        assert_eq!(recovered.matches(" heartbeat").count(), expected_heartbeats);
        assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn fallback_recovery_preserves_tampered_duplicate_and_unsafe_residue() -> Result<()> {
    fn leave_old_displacement(repo: &Path, claim_id: &str) -> Result<PathBuf> {
        write_claim(repo, claim_id, claim_id, "active", "2026-05-20T00:00:00Z")?;
        {
            let _fault = ClaimAtomicTestFaultGuard::install(
                Some(libc::EINVAL),
                Some(ClaimFallbackCrashPoint::AfterOldDisplacement),
            );
            heartbeat_with_clock(
                repo,
                claim_id,
                claim_id,
                &LiveClock::parse("2026-05-20T00:30:00Z")?,
            )
            .expect_err("old displacement crash must leave transaction residue");
        }
        fallback_residue_paths(&claims_dir(repo))?
            .pop()
            .context("missing fallback residue")
    }

    let tampered = tempfile::tempdir()?;
    let tampered_residue = leave_old_displacement(tampered.path(), "tampered-residue")?;
    std::fs::write(&tampered_residue, b"tampered old generation")?;
    let tampered_error = status(tampered.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)
        .expect_err("tampered fallback residue must fail closed");
    assert!(format!("{tampered_error:#}").contains("old-generation residue was changed"));
    assert!(tampered_residue.exists());

    let duplicate = tempfile::tempdir()?;
    let first_residue = leave_old_displacement(duplicate.path(), "duplicate-residue")?;
    let directory = claims_dir(duplicate.path());
    let first_name = first_residue.file_name().context("fallback residue name")?;
    let transaction =
        ClaimFallbackTransaction::parse(first_name)?.context("parse fallback transaction")?;
    let duplicate_path = directory.join("duplicate-old-copy");
    std::fs::copy(&first_residue, &duplicate_path)?;
    let copied = read_entry_generation(
        &open_claims_root(&directory)?.context("duplicate residue root")?,
        OsStr::new("duplicate-old-copy"),
        MAX_CLAIM_BYTES,
    )?;
    let duplicate_name = OsString::from(format!(
            "{CLAIM_FALLBACK_RESIDUE_PREFIX}{}.{}.{}.{}.{:016x}.{:016x}.{:016x}.{:016x}{CLAIM_FALLBACK_RESIDUE_SUFFIX}",
            transaction.target_checksum,
            transaction.old_checksum,
            transaction.new_checksum,
            transaction.other_board_checksum,
            copied.identity.device,
            copied.identity.file,
            transaction.new_identity.device,
            transaction.new_identity.file,
        ));
    std::fs::rename(&duplicate_path, directory.join(&duplicate_name))?;
    let duplicate_error = status(duplicate.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)
        .expect_err("duplicate fallback residue must fail closed");
    assert!(format!("{duplicate_error:#}").contains("duplicate or ambiguous"));
    assert!(first_residue.exists());
    assert!(directory.join(duplicate_name).exists());

    let unsafe_residue = tempfile::tempdir()?;
    let residue = leave_old_displacement(unsafe_residue.path(), "unsafe-residue")?;
    let external = unsafe_residue.path().join("external-old-generation");
    std::fs::write(&external, b"unsafe replacement")?;
    std::fs::remove_file(&residue)?;
    std::os::unix::fs::symlink(&external, &residue)?;
    let unsafe_error = status(
        unsafe_residue.path(),
        &LiveClock::parse("2026-05-20T00:31:00Z")?,
    )
    .expect_err("unsafe fallback residue must fail closed");
    assert!(format!("{unsafe_error:#}").contains("transaction residue is unsafe"));
    assert!(std::fs::symlink_metadata(&residue)?
        .file_type()
        .is_symlink());
    Ok(())
}

#[test]
fn concurrent_heartbeats_preserve_both_audit_entries_under_board_lock() -> Result<()> {
    let temp = Arc::new(tempfile::tempdir()?);
    let path = write_claim(
        temp.path(),
        "locked-claim",
        "locked-claim",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let mut threads = Vec::new();
    for timestamp in ["2026-05-20T00:11:00Z", "2026-05-20T00:11:00Z"] {
        let temp = Arc::clone(&temp);
        threads.push(std::thread::spawn(move || -> Result<()> {
            heartbeat_with_clock(
                temp.path(),
                "locked-claim",
                "locked-claim",
                &LiveClock::parse(timestamp)?,
            )?;
            Ok(())
        }));
    }
    for thread in threads {
        thread
            .join()
            .map_err(|_| anyhow::anyhow!("heartbeat thread panicked"))??;
    }
    let content = std::fs::read_to_string(path)?;
    assert_eq!(content.matches(" heartbeat").count(), 2);
    Ok(())
}

#[test]
fn stable_board_read_and_mutation_fence_cover_names_and_other_claim_generations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_claim(
        temp.path(),
        "first-claim",
        "first-claim",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let second_path = write_claim(
        temp.path(),
        "second-claim",
        "second-claim",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let second_content = claim_text(
        "second-claim",
        "second-claim",
        "active",
        "2026-05-20T00:01:00Z",
        "tests/live_cli.rs",
    );
    let root = open_claims_root(&claims_dir(temp.path()))?.context("claim root")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let read_error = load_stable_claim_board_with_hook(&root, &lock, || {
        std::fs::write(&second_path, &second_content)?;
        Ok(())
    })
    .expect_err("stable board reads must reject generation changes");
    assert!(read_error.to_string().contains("generation changed"));
    drop(lock);

    std::fs::write(
        &second_path,
        claim_text(
            "second-claim",
            "second-claim",
            "active",
            "2026-05-20T00:00:00Z",
            "tests/live_cli.rs",
        ),
    )?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let mutation_error = mutate_claim(
        temp.path(),
        "first-claim",
        "first-claim",
        &now,
        ClaimMutation::Heartbeat,
        |_| {
            std::fs::write(&second_path, &second_content)?;
            Ok(())
        },
    )
    .expect_err("mutation fence must cover every board entry");
    assert!(mutation_error
        .to_string()
        .contains("atomic mutation was refused"));
    Ok(())
}

#[test]
fn active_owned_paths_are_component_aware_and_fail_board_validation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join("parent-claim.md"),
        claim_text(
            "parent-claim",
            "parent-claim",
            "active",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs",
        ),
    )?;
    let child = claim_text(
        "child-claim",
        "child-claim",
        "blocked",
        "2026-05-20T00:00:00Z",
        "src/live_claim.rs/tests",
    );
    std::fs::write(directory.join("child-claim.md"), child)?;
    let report = validate(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?;
    assert!(!report.valid);
    assert_eq!(
        report
            .claims
            .iter()
            .filter(|claim| claim
                .issues
                .iter()
                .any(|issue| issue.message.contains("overlaps")))
            .count(),
        2
    );
    let status_error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
        .expect_err("overlapping live claims must fail board validation");
    let status_message = status_error.to_string();
    assert!(status_message.contains("parent-claim.md"));
    assert!(status_message.contains("child-claim.md"));
    assert!(status_message.contains("overlapping"));
    assert!(status_message.contains("`owned_files`"));
    assert!(!status_message.contains("src/live_claim.rs"));
    assert!(!status_message.contains("src/live_claim.rs/tests"));

    std::fs::write(
        directory.join("child-claim.md"),
        claim_text(
            "child-claim",
            "child-claim",
            "handoff",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs/tests",
        ),
    )?;
    assert_eq!(
        status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
        2
    );
    Ok(())
}

#[test]
fn apply_admission_ignores_duplicate_ids_only_when_every_claim_is_non_conflicting() -> Result<()> {
    let timestamp = "2026-05-20T00:00:00Z";
    let duplicate_id = "raw-duplicate-id-value";
    let mut done = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("done.md"),
        &claim_text("done", "done", "done", timestamp, "src/done.rs"),
    );
    done.claim_id = Some(duplicate_id.to_string());
    let mut handoff = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("handoff.md"),
        &claim_text("handoff", "handoff", "handoff", timestamp, "src/handoff.rs"),
    );
    handoff.claim_id = Some(duplicate_id.to_string());

    ensure_claim_board_allows_apply(&[done.clone(), handoff.clone()])?;

    let strict_error = ensure_claim_board_valid(&[done.clone(), handoff.clone()])
        .expect_err("strict board validation must keep reporting terminal duplicates");
    let strict_message = strict_error.to_string();
    assert!(strict_message.contains("done.md"));
    assert!(strict_message.contains("handoff.md"));
    assert!(strict_message.contains("duplicate"));
    assert!(strict_message.contains("`claim_id`"));
    assert!(!strict_message.contains(duplicate_id));

    for status in ["active", "blocked", "completed"] {
        let mut conflicting = handoff.clone();
        conflicting.status = Some(status.to_string());
        let error = ensure_claim_board_allows_apply(&[done.clone(), conflicting])
            .expect_err("a duplicate id involving a classified or unclassified claim must block");
        let message = error.to_string();
        assert!(message.contains("done.md"));
        assert!(message.contains("handoff.md"));
        assert!(message.contains("duplicate"));
        assert!(message.contains("`claim_id`"));
        assert!(!message.contains(duplicate_id));
    }
    Ok(())
}

#[test]
fn apply_is_create_only_and_scope_changes_require_a_new_claim_id() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    let draft = temp.path().join("claim-draft.md");
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    std::fs::write(
        &draft,
        initial_draft_text(
            "applied-claim",
            "applied-owner",
            "active",
            now.raw(),
            "src/live_claim.rs",
        ),
    )?;
    let created = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
    assert!(created.created);
    let claim_path = directory.join("applied-claim.md");
    let created_content = std::fs::read_to_string(&claim_path)?;
    assert!(created_content.contains("created claim from bounded draft"));

    std::fs::write(
        &draft,
        initial_draft_text(
            "applied-claim",
            "applied-owner",
            "active",
            now.raw(),
            "src/changed-scope.rs",
        ),
    )?;
    let existing = apply_with_clock(temp.path(), &draft, "applied-owner", &now)
        .expect_err("existing claim updates must be refused even for the exact owner");
    assert!(existing.to_string().contains("create-only"));
    assert_eq!(std::fs::read_to_string(&claim_path)?, created_content);

    mutate_claim(
        temp.path(),
        "applied-claim",
        "applied-owner",
        &LiveClock::parse("2026-05-20T00:31:00Z")?,
        ClaimMutation::OwnerRelease {
            status: "handoff",
            reason: "scope change requires a new claim id",
        },
        |_| Ok(()),
    )?;
    let terminal_replay = apply_with_clock(temp.path(), &draft, "applied-owner", &now)
        .expect_err("released ids must not be replayed");
    assert!(terminal_replay.to_string().contains("create-only"));

    std::fs::write(
        &draft,
        initial_draft_text(
            "applied-claim-v2",
            "applied-owner",
            "active",
            now.raw(),
            "src/changed-scope.rs",
        ),
    )?;
    let replacement = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
    assert_eq!(replacement.claim_id, "applied-claim-v2");
    assert!(replacement.created);
    Ok(())
}

#[test]
fn apply_ignores_malformed_terminal_claims_while_validation_reports_them() -> Result<()> {
    for status in ["done", "handoff"] {
        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        let terminal_id = format!("malformed-{status}");
        let terminal_path = write_claim(
            temp.path(),
            &terminal_id,
            "terminal-owner",
            status,
            "2026-05-20T00:00:00Z",
        )?;
        let raw_owner = format!("TerminalOwnerSecret{status}");
        let malformed = std::fs::read_to_string(&terminal_path)?
            .replace("- Owner: terminal-owner", &format!("- Owner: {raw_owner}"));
        std::fs::write(&terminal_path, malformed)?;

        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let draft = temp.path().join("claim-draft.md");
        let created_id = format!("created-after-{status}");
        std::fs::write(
            &draft,
            initial_draft_text(
                &created_id,
                "new-owner",
                "active",
                now.raw(),
                "src/new_scope.rs",
            ),
        )?;

        let created = apply_with_clock(temp.path(), &draft, "new-owner", &now)?;
        assert_eq!(created.claim_id, created_id);
        let validation = validate(temp.path(), &now)?;
        assert!(!validation.valid);
        let terminal = validation
            .claims
            .iter()
            .find(|claim| {
                claim.file
                    == PathBuf::from(CLAIMS_DIR)
                        .join(&terminal_id)
                        .with_extension("md")
            })
            .context("terminal claim validation")?;
        assert!(terminal
            .issues
            .iter()
            .any(|issue| issue.severity == "error" && issue.field == "owner"));
        assert!(!serde_json::to_string(&validation)?.contains(&raw_owner));
    }
    Ok(())
}

#[test]
fn apply_rejects_malformed_live_claims_with_file_and_field_only() -> Result<()> {
    for status in ["active", "blocked"] {
        let temp = tempfile::tempdir()?;
        let malformed_id = format!("malformed-{status}");
        let raw_owner = format!("LiveOwnerSecret{status}");
        write_claim(
            temp.path(),
            &malformed_id,
            &raw_owner,
            status,
            "2026-05-20T00:00:00Z",
        )?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let draft = temp.path().join("claim-draft.md");
        let created_id = format!("blocked-by-{status}");
        std::fs::write(
            &draft,
            initial_draft_text(
                &created_id,
                "new-owner",
                "active",
                now.raw(),
                "src/new_scope.rs",
            ),
        )?;

        let error = apply_with_clock(temp.path(), &draft, "new-owner", &now)
            .expect_err("a malformed live claim must block creation");
        let message = error.to_string();
        assert!(message.contains(&format!("{malformed_id}.md")));
        assert!(message.contains("`owner`"));
        assert!(!message.contains(&raw_owner));
        assert!(!claims_dir(temp.path())
            .join(format!("{created_id}.md"))
            .exists());
    }
    Ok(())
}

#[test]
fn apply_does_not_trust_a_duplicate_terminal_status_when_diagnostics_are_full() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    let mut malformed = "\u{1}\n".repeat(MAX_CLAIM_ISSUES);
    malformed.push_str(&claim_text(
        "ambiguous-terminal",
        "terminal-owner",
        "done",
        "2026-05-20T00:00:00Z",
        "src/terminal.rs",
    ));
    malformed = malformed.replace("- Status: done", "- Status: done\n- Status: active");
    let malformed_file = PathBuf::from(CLAIMS_DIR).join("ambiguous-terminal.md");
    let parsed = parse_claim_file(malformed_file.clone(), &malformed);
    assert_eq!(parsed.issues.len(), MAX_CLAIM_ISSUES);
    assert!(parsed.issues.iter().all(|issue| issue.field == "line"));
    assert_eq!(parsed.status.as_deref(), Some("done"));
    assert!(!parsed.status_is_trustworthy);
    std::fs::write(directory.join("ambiguous-terminal.md"), malformed)?;

    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let draft = temp.path().join("claim-draft.md");
    std::fs::write(
        &draft,
        initial_draft_text(
            "blocked-by-ambiguous-terminal",
            "new-owner",
            "active",
            now.raw(),
            "src/new_scope.rs",
        ),
    )?;
    let error = apply_with_clock(temp.path(), &draft, "new-owner", &now)
        .expect_err("a structurally ambiguous status must block apply admission");
    let message = error.to_string();
    assert!(message.contains("ambiguous-terminal.md"));
    assert!(message.contains("`status`"));
    assert!(!message.contains("done"));
    assert!(!message.contains("active"));
    assert!(!directory.join("blocked-by-ambiguous-terminal.md").exists());
    Ok(())
}

#[test]
fn apply_does_not_trust_a_duplicate_terminal_status_after_the_line_limit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    let mut malformed = claim_text(
        "line-limited-terminal",
        "terminal-owner",
        "done",
        "2026-05-20T00:00:00Z",
        "src/terminal.rs",
    );
    malformed.push_str(&"\n".repeat(MAX_CLAIM_LINES));
    malformed.push_str("- Status: active\n");
    let malformed_file = PathBuf::from(CLAIMS_DIR).join("line-limited-terminal.md");
    let parsed = parse_claim_file(malformed_file, &malformed);
    assert_eq!(parsed.status.as_deref(), Some("done"));
    assert!(!parsed.status_is_trustworthy);
    assert!(parsed.issues.iter().any(|issue| issue.field == "lines"));
    assert!(!parsed.issues.iter().any(|issue| issue.field == "status"));
    std::fs::write(directory.join("line-limited-terminal.md"), malformed)?;

    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let draft = temp.path().join("claim-draft.md");
    std::fs::write(
        &draft,
        initial_draft_text(
            "blocked-by-line-limited-terminal",
            "new-owner",
            "active",
            now.raw(),
            "src/new_scope.rs",
        ),
    )?;
    let error = apply_with_clock(temp.path(), &draft, "new-owner", &now)
        .expect_err("a status hidden after the parser line limit must block admission");
    let message = error.to_string();
    assert!(message.contains("line-limited-terminal.md"));
    assert!(message.contains("`status`"));
    assert!(!message.contains("done"));
    assert!(!message.contains("active"));
    assert!(!directory
        .join("blocked-by-line-limited-terminal.md")
        .exists());
    Ok(())
}

#[test]
fn apply_rejects_a_malformed_draft_with_file_and_field_only() -> Result<()> {
    let temp = tempfile::tempdir()?;
    std::fs::create_dir_all(claims_dir(temp.path()))?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let draft = temp.path().join("claim-draft.md");
    let raw_owner = "MalformedDraftOwnerSecret";
    std::fs::write(
        &draft,
        initial_draft_text(
            "malformed-draft",
            raw_owner,
            "active",
            now.raw(),
            "src/live_claim.rs",
        ),
    )?;

    let error = apply_with_clock(temp.path(), &draft, "draft-owner", &now)
        .expect_err("the supported write path must reject a malformed draft");
    let message = error.to_string();
    assert!(message.contains("malformed-draft.md"));
    assert!(message.contains("`owner`"));
    assert!(!message.contains(raw_owner));
    assert!(!claims_dir(temp.path()).join("malformed-draft.md").exists());
    Ok(())
}

#[test]
fn apply_rejects_old_future_terminal_and_audit_replay_drafts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    std::fs::create_dir_all(claims_dir(temp.path()))?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let cases = [
        (
            "old-draft",
            "active",
            "2026-05-20T00:20:00Z",
            false,
            "too old",
        ),
        (
            "future-draft",
            "active",
            "2026-05-20T00:31:00Z",
            false,
            "future",
        ),
        (
            "terminal-draft",
            "done",
            "2026-05-20T00:30:00Z",
            false,
            "initial status active",
        ),
        (
            "audit-draft",
            "active",
            "2026-05-20T00:30:00Z",
            true,
            "audit history",
        ),
    ];
    for (claim_id, status, timestamp, with_audit, expected) in cases {
        let draft = temp.path().join(format!("{claim_id}.draft"));
        let mut content =
            initial_draft_text(claim_id, claim_id, status, timestamp, "src/live_claim.rs");
        if with_audit {
            content.push_str("\n## Audit log\n\n- forged prior history\n");
        }
        std::fs::write(&draft, content)?;
        let error = apply_with_clock(temp.path(), &draft, claim_id, &now)
            .expect_err("unsafe initial draft generation must be refused");
        assert!(error.to_string().contains(expected), "{error:#}");
        assert!(!claims_dir(temp.path())
            .join(format!("{claim_id}.md"))
            .exists());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn apply_binds_draft_parent_leaf_and_board_aliases_without_following_links() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let board_claim = write_claim(
        temp.path(),
        "board-source",
        "board-source",
        "done",
        now.raw(),
    )?;

    let inside = apply_with_clock(temp.path(), &board_claim, "board-source", &now)
        .expect_err("board-internal drafts must be refused");
    assert!(inside.to_string().contains("outside"));

    let hardlink = temp.path().join("hardlinked-draft.md");
    std::fs::hard_link(&board_claim, &hardlink)?;
    let hardlink_error = apply_with_clock(temp.path(), &hardlink, "board-source", &now)
        .expect_err("board hard links must be refused");
    assert!(hardlink_error.to_string().contains("bounded no-follow"));
    std::fs::remove_file(&hardlink)?;

    let alias = temp.path().join("claim-board-alias");
    symlink(&directory, &alias)?;
    let alias_error = apply_with_clock(
        temp.path(),
        &alias.join("board-source.md"),
        "board-source",
        &now,
    )
    .expect_err("board symlink aliases must be refused");
    assert!(alias_error.to_string().contains("parent"));

    let draft_parent = temp.path().join("draft-parent");
    let replacement_parent = temp.path().join("replacement-parent");
    std::fs::create_dir(&draft_parent)?;
    std::fs::create_dir(&replacement_parent)?;
    let draft = draft_parent.join("ancestor-race.md");
    std::fs::write(
        &draft,
        initial_draft_text(
            "ancestor-race",
            "ancestor-race",
            "active",
            now.raw(),
            "src/live_claim.rs",
        ),
    )?;
    let moved_parent = temp.path().join("draft-parent-original");
    let race = apply_with_clock_and_hooks(
        temp.path(),
        &draft,
        "ancestor-race",
        &now,
        |_| {
            std::fs::rename(&draft_parent, &moved_parent)?;
            symlink(&replacement_parent, &draft_parent)?;
            Ok(())
        },
        |_| Ok(()),
    )
    .expect_err("ancestor symlink replacement must invalidate the bound draft");
    assert!(race.to_string().contains("parent binding changed"));
    Ok(())
}

#[test]
fn apply_create_race_never_replaces_a_concurrently_created_target() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = claims_dir(temp.path());
    std::fs::create_dir_all(&directory)?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    let draft = temp.path().join("create-race.draft");
    std::fs::write(
        &draft,
        initial_draft_text(
            "create-race",
            "create-race",
            "active",
            now.raw(),
            "src/live_claim.rs",
        ),
    )?;
    let raced_content = claim_text(
        "create-race",
        "racing-owner",
        "done",
        now.raw(),
        "src/raced.rs",
    );
    let target = directory.join("create-race.md");
    let error = apply_with_clock_and_hooks(
        temp.path(),
        &draft,
        "create-race",
        &now,
        |_| Ok(()),
        |_| {
            std::fs::write(&target, &raced_content)?;
            Ok(())
        },
    )
    .expect_err("create-only rename must refuse a concurrently appearing target");
    assert!(error.to_string().contains("atomic mutation was refused"));
    assert_eq!(std::fs::read_to_string(&target)?, raced_content);
    Ok(())
}

#[cfg(unix)]
#[test]
fn claim_writer_residue_is_canonically_scavenged_and_unknown_residue_is_refused() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    write_claim(
        temp.path(),
        "residue-claim",
        "residue-claim",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let directory = claims_dir(temp.path());
    let known = directory.join(".residue-claim.md.1-2.tmp");
    std::fs::write(&known, b"bounded residue")?;
    std::fs::set_permissions(&known, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
        1
    );
    assert!(!known.exists());

    let interrupted_create = directory.join(".new-residue-claim.md.3-4.tmp");
    std::fs::write(&interrupted_create, b"bounded interrupted create residue")?;
    std::fs::set_permissions(&interrupted_create, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
        1
    );
    assert!(!interrupted_create.exists());

    let unknown = directory.join(".residue-claim.md.bad.tmp");
    std::fs::write(&unknown, b"unknown residue")?;
    std::fs::set_permissions(&unknown, std::fs::Permissions::from_mode(0o600))?;
    let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
        .expect_err("unknown writer residue must fail closed");
    assert!(error.to_string().contains("unknown writer residue"));
    assert!(unknown.exists());
    Ok(())
}

#[test]
fn stale_release_compacts_audit_growth_instead_of_becoming_unreleasable() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = write_claim(
        temp.path(),
        "audit-growth",
        "audit-growth",
        "active",
        "2026-05-20T00:00:00Z",
    )?;
    let mut content = std::fs::read_to_string(&path)?;
    while content.len() < MAX_CLAIM_BYTES as usize - 16 {
        content.push_str("- old bounded audit entry 0123456789012345678901234567890123456789\n");
    }
    content.truncate(MAX_CLAIM_BYTES as usize - 16);
    while !content.ends_with('\n') {
        content.pop();
    }
    std::fs::write(&path, content)?;

    let report = override_release_with_clock(
        temp.path(),
        "audit-growth",
        "project-owner",
        "stale owner unavailable",
        &LiveClock::parse("2026-05-20T02:00:00Z")?,
    )?;
    assert_eq!(report.status.as_deref(), Some("handoff"));
    let released = std::fs::read_to_string(path)?;
    assert!(released.contains("prior audit history compacted"));
    assert!(released.contains("override-release"));
    assert!(released.len() <= MAX_CLAIM_BYTES as usize);
    Ok(())
}

#[cfg(unix)]
#[test]
fn board_loader_rejects_links_special_files_unsafe_extras_and_bounds_without_path_leaks(
) -> Result<()> {
    use std::os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::symlink,
    };

    let temp = tempfile::tempdir()?;
    let directory = temp.path().join(CLAIMS_DIR);
    std::fs::create_dir_all(&directory)?;
    let external = temp.path().join("external-secret");
    std::fs::write(
        &external,
        claim_text(
            "linked",
            "linked",
            "active",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs",
        ),
    )?;
    symlink(&external, directory.join("linked.md"))?;
    let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
        .expect_err("claim symlink must fail closed");
    assert!(!error.to_string().contains(&external.display().to_string()));
    std::fs::remove_file(directory.join("linked.md"))?;

    std::fs::hard_link(&external, directory.join("hardlinked.md"))?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join("hardlinked.md"))?;

    let fifo_path = directory.join("fifo.md");
    let fifo = std::ffi::CString::new(fifo_path.as_os_str().as_bytes())?;
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(&fifo_path)?;

    std::fs::create_dir(directory.join("directory.md"))?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_dir(directory.join("directory.md"))?;

    std::fs::write(
        directory.join("oversized.md"),
        vec![b'x'; MAX_CLAIM_BYTES as usize + 1],
    )?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join("oversized.md"))?;

    std::fs::write(directory.join("nonutf.md"), [0xff, 0xfe])?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join("nonutf.md"))?;

    let non_utf_name = OsString::from_vec(b"nonutf-\xff.md".to_vec());
    std::fs::write(directory.join(&non_utf_name), b"bounded")?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join(&non_utf_name))?;

    std::fs::write(directory.join("unexpected.bin"), b"unexpected")?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join("unexpected.bin"))?;

    symlink(&external, directory.join(TEMPLATE_FILE))?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
    std::fs::remove_file(directory.join(TEMPLATE_FILE))?;

    std::fs::remove_file(directory.join(BOARD_LOCK_FILE))?;
    symlink(&external, directory.join(BOARD_LOCK_FILE))?;
    assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());

    let linked_root = tempfile::tempdir()?;
    std::fs::create_dir_all(linked_root.path().join(".agents/live"))?;
    symlink(&directory, linked_root.path().join(CLAIMS_DIR))?;
    assert!(status(
        linked_root.path(),
        &LiveClock::parse("2026-05-20T00:30:00Z")?
    )
    .is_err());
    Ok(())
}

#[test]
fn board_entry_count_is_bounded_before_claim_contents_are_parsed() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join(CLAIMS_DIR);
    std::fs::create_dir_all(&directory)?;
    for index in 0..=MAX_CLAIM_ENTRIES {
        std::fs::write(directory.join(format!("claim-{index}.md")), b"")?;
    }
    let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
        .expect_err("entry count must be bounded");
    assert!(error.to_string().contains("entry limit"));
    Ok(())
}

#[test]
fn real_board_style_surfaces_load_until_legacy_completed_status_fails_closed() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join(CLAIMS_DIR);
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join("global-validation.md"),
        claim_text(
            "global-validation",
            "global-validation",
            "active",
            "2026-05-20T00:00:00Z",
            "Host-global transient service units, cgroups, and runtime directories",
        ),
    )?;
    let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
    assert_eq!(status(temp.path(), &now)?.claim_count, 1);
    std::fs::write(
        directory.join("legacy-status.md"),
        claim_text(
            "legacy-status",
            "legacy-status",
            "completed",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs",
        ),
    )?;
    let draft = temp.path().join("claim-draft.md");
    std::fs::write(
        &draft,
        initial_draft_text(
            "new-real-board-claim",
            "new-owner",
            "active",
            now.raw(),
            "src/new_scope.rs",
        ),
    )?;
    let error = apply_with_clock(temp.path(), &draft, "new-owner", &now)
        .expect_err("an unsupported status cannot be classified as non-conflicting");
    let message = error.to_string();
    assert!(message.contains("legacy-status.md"));
    assert!(message.contains("`status`"));
    assert!(!message.contains("completed"));
    assert!(!directory.join("new-real-board-claim.md").exists());
    let validation = validate(temp.path(), &now)?;
    assert!(!validation.valid);
    let legacy = validation
        .claims
        .iter()
        .find(|claim| claim.file.ends_with("legacy-status.md"))
        .context("legacy completed validation")?;
    assert!(legacy
        .issues
        .iter()
        .any(|issue| issue.severity == "error" && issue.field == "status"));
    Ok(())
}

#[test]
fn validation_includes_parser_errors_and_duplicate_claim_ids_without_raw_values() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join(CLAIMS_DIR);
    std::fs::create_dir_all(&directory)?;
    let first = claim_text(
        "first",
        "first",
        "waiting-secret-value",
        "malformed-secret-timestamp",
        "src/live_claim.rs",
    )
    .replace("- Owner: first", "- Owner: first\n- Owner: duplicate-owner");
    std::fs::write(directory.join("first.md"), first)?;
    let second = claim_text(
        "first",
        "second",
        "active",
        "2026-05-20T00:00:00Z",
        "src/live_claim.rs",
    );
    std::fs::write(directory.join("second.md"), second)?;

    let report = validate(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?;
    assert!(!report.valid);
    let serialized = serde_json::to_string(&report)?;
    assert!(serialized.contains("duplicate recognized field"));
    assert!(serialized.contains("duplicated across claim files"));
    assert!(!serialized.contains("waiting-secret-value"));
    assert!(!serialized.contains("malformed-secret-timestamp"));
    Ok(())
}
