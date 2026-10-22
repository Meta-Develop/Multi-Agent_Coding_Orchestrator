use super::*;
use crate::safe_state::FileIdentity;
use std::os::unix::{
    fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

use crate::safe_state::LinuxOpenat2Error as Openat2Error;

fn journal(path: &Path) -> FileIdentity {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let metadata = file.metadata().unwrap();
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

fn entry() -> WorkerExecutionJournalEntry {
    WorkerExecutionJournalEntry {
        command: vec!["apply_patch".into(), "patch with \"quotes\"\n\\path".into()],
        cwd: PathBuf::from("/worktree"),
        start_timestamp: "2026-10-15T00:00:00Z".into(),
        end_timestamp: "2026-10-15T00:00:01Z".into(),
        changed_paths: vec![PathBuf::from("p")],
        observation: None,
    }
}

#[test]
fn worker_journal_enosys_fallback_appends_without_replacing_file() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    let original = b"existing immutable record\n";
    fs::write(&path, original).unwrap();

    for append in [true, false] {
        let file = open_worker_journal_no_follow(&path, append).unwrap();
        // SAFETY: fcntl reads flags from a live descriptor without pointers.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        assert_eq!(flags & libc::O_APPEND != 0, append);
        assert_eq!(
            flags & libc::O_ACCMODE,
            if append {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            }
        );
        // SAFETY: fcntl reads descriptor flags without pointers.
        let fd_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(fd_flags >= 0);
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
    }

    let record = entry();
    let mut encoded = Vec::new();
    append_worker_execution_journal_record(&mut encoded, &record).unwrap();
    // The injection remains active for the append open and both reopens.
    append_precreated_worker_execution_journal(&path, &expected, &record).unwrap();
    append_precreated_worker_execution_journal(&path, &expected, &record).unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        [original.as_slice(), &encoded, &encoded].concat()
    );
    verify_worker_journal_identity(&fs::metadata(&path).unwrap(), &expected).unwrap();
}

#[test]
fn worker_journal_enosys_fallback_refuses_symlink_leaf_and_ancestor() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    let alias = root.join("alias.jsonl");
    symlink(&path, &alias).unwrap();
    let ancestor = root.join("alias-dir");
    symlink(&root, &ancestor).unwrap();

    for alias in [alias, ancestor.join("worker.jsonl")] {
        for append in [true, false] {
            assert!(open_worker_journal_no_follow(&alias, append).is_err());
        }
        assert!(append_precreated_worker_execution_journal(&alias, &expected, &entry()).is_err());
    }
    assert!(fs::read(path).unwrap().is_empty());
}

#[test]
fn worker_journal_enosys_fallback_refuses_wrong_device_and_inode() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("worker.jsonl");
    let expected = journal(&path);
    for wrong in [
        FileIdentity {
            device: expected.device.wrapping_add(1),
            file: expected.file,
        },
        FileIdentity {
            device: expected.device,
            file: expected.file.wrapping_add(1),
        },
    ] {
        let error =
            append_precreated_worker_execution_journal(&path, &wrong, &entry()).unwrap_err();
        assert!(error
            .to_string()
            .contains("expected current-user-owned single-link 0600 regular file"));
        assert!(fs::read(&path).unwrap().is_empty());
    }
}

#[test]
fn worker_journal_enosys_fallback_preserves_file_policy_and_existing_only_open() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, root.join("hardlink.jsonl")).unwrap();
    assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
    let missing = root.join("missing.jsonl");
    assert!(append_precreated_worker_execution_journal(&missing, &expected, &entry()).is_err());
    assert!(!missing.exists());
    assert!(append_precreated_worker_execution_journal(&root, &expected, &entry()).is_err());
    let fifo = root.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: name is NUL-terminated and this test owns its temporary directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(open_worker_journal_no_follow(&fifo, false).is_err());
    assert!(append_precreated_worker_execution_journal(&fifo, &expected, &entry()).is_err());
    assert!(fs::read(path).unwrap().is_empty());
}

#[test]
fn worker_journal_fallback_does_not_retry_other_openat2_errors() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("worker.jsonl");
    let expected = journal(&path);
    for errno in [
        libc::EPERM,
        libc::EACCES,
        libc::EINVAL,
        libc::ELOOP,
        libc::EXDEV,
    ] {
        let _error = Openat2Error::force(errno);
        for append in [true, false] {
            let error = open_worker_journal_no_follow(&path, append).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
        }
        assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
        assert!(fs::read(&path).unwrap().is_empty());
    }
}

fn observed_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, FileIdentity) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let worktree = root.join("worktree");
    let repo = Repository::init(&worktree).unwrap();
    fs::write(worktree.join("README.md"), "original\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("README.md")).unwrap();
    index.write().unwrap();
    let tree_oid = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();
    let signature = git2::Signature::now("Fixture", "fixture@example.invalid").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .unwrap();
    let path = root.join("worker.jsonl");
    let identity = journal(&path);
    (temp, worktree, path, identity)
}

fn observed_entry(worktree: &Path, command: &[&str]) -> WorkerExecutionJournalEntry {
    WorkerExecutionJournalEntry {
        command: command.iter().map(|arg| (*arg).to_string()).collect(),
        cwd: worktree.to_path_buf(),
        changed_paths: Vec::new(),
        ..entry()
    }
}

#[test]
fn worker_journal_wrapped_edit_observes_paths_without_declaration() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let record = observed_entry(
        &worktree,
        &["/bin/sh", "-c", "printf 'edited\\n' >> README.md"],
    );
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    let records = parse_worker_execution_journal(&fs::read(&path).unwrap(), &path).unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[0].changed_paths.is_empty());
    assert_eq!(records[1].changed_paths, vec![PathBuf::from("README.md")]);
    assert_eq!(
        fs::read_to_string(worktree.join("README.md")).unwrap(),
        "original\nedited\n"
    );
    verify_worker_journal_identity(&fs::metadata(path).unwrap(), &identity).unwrap();
}

#[test]
fn worker_journal_declared_mismatch_is_preserved_and_rejected() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let mut record = observed_entry(&worktree, &["/bin/sh", "-c", "printf edited >> README.md"]);
    record.changed_paths = vec![PathBuf::from("unmodified.txt")];
    let error = run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
    assert!(error.to_string().contains("do not match observed"));
    let bytes = fs::read(&path).unwrap();
    assert!(parse_worker_execution_journal(&bytes, &path).is_err());
    let completed: WorkerExecutionJournalEntry =
        serde_json::from_slice(bytes.split(|b| *b == b'\n').nth(1).unwrap()).unwrap();
    assert_eq!(completed.changed_paths, vec![PathBuf::from("README.md")]);
    assert_eq!(
        completed.observation.unwrap().declared_paths,
        vec![PathBuf::from("unmodified.txt")]
    );
    assert!(run_worker_execution_journal_command(&path, &identity, &record, true).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn worker_journal_native_edit_observes_repeated_edits_and_never_executes_argv() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let baseline = observed_entry(&worktree, &["true"]);
    run_worker_execution_journal_command(&path, &identity, &baseline, true).unwrap();
    let native = observed_entry(
        &worktree,
        &[
            "apply_patch",
            "full native patch payload\nwith quotes: \"\\",
        ],
    );
    for contents in ["first\n", "second\n"] {
        fs::write(worktree.join("README.md"), contents).unwrap();
        // A normal shell wrapper must refuse to launder an earlier native edit.
        assert!(run_worker_execution_journal_command(&path, &identity, &baseline, false).is_err());
        run_worker_execution_journal_command(&path, &identity, &native, true).unwrap();
    }
    let records =
        parse_worker_execution_journal(&fs::read(path).unwrap(), Path::new("journal")).unwrap();
    assert_eq!(records.len(), 3);
    for record in &records[1..] {
        assert_eq!(record.command, native.command);
        assert_eq!(record.changed_paths, vec![PathBuf::from("README.md")]);
    }
    assert_ne!(
        records[1].observation.as_ref().unwrap().after,
        records[2].observation.as_ref().unwrap().after
    );
}

#[test]
fn worker_journal_native_observation_recovers_after_proven_no_launch() {
    let _fallback = Openat2Error::force(libc::ENOSYS).with_statx_enosys();
    for tool_startup_failure in [true, false] {
        let (_temp, worktree, path, identity) = observed_fixture();
        let observation = observed_entry(&worktree, &["true"]);
        run_worker_execution_journal_command(&path, &identity, &observation, true).unwrap();
        let baseline = fs::read(&path).unwrap();
        // Native edit runs exactly once; the only next successful action is its
        // observation, even when the execution tool itself rejects its cwd.
        fs::write(worktree.join("README.md"), "original\nHello from MACO\n").unwrap();
        let missing = worktree.join("nonexistent-tool-cwd");
        if tool_startup_failure {
            let error = std::process::Command::new("/bin/sh")
                .args(["-c", "touch should-not-run"])
                .current_dir(&missing)
                .status()
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        } else {
            let mut rejected = observation.clone();
            rejected.cwd = missing;
            let error = run_worker_execution_journal_command(&path, &identity, &rejected, true)
                .unwrap_err();
            assert!(error.to_string().contains("WorkerJournalPrelaunchRejected"));
            assert!(error
                .to_string()
                .contains("both --cwd and the execution tool workdir"));
        }
        assert_eq!(fs::read(&path).unwrap(), baseline);
        assert!(!worktree.join("should-not-run").exists());
        run_worker_execution_journal_command(&path, &identity, &observation, true).unwrap();
        let entries = parse_worker_execution_journal(&fs::read(&path).unwrap(), &path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].changed_paths, [PathBuf::from("README.md")]);
        let before = entries[0].observation.as_ref().unwrap();
        let after = entries[1].observation.as_ref().unwrap();
        assert_eq!(before.after, after.before);
        assert_eq!(after.phase, WorkerJournalObservationPhase::NativeEdit);
        assert_eq!(after.after[Path::new("README.md")].len(), 64);
        assert_eq!(before.worktree_identity, after.worktree_identity);
        assert_eq!(before.head_oid, after.head_oid);
        verify_worker_journal_identity(&fs::metadata(&path).unwrap(), &identity).unwrap();
        assert_eq!(
            fs::read_to_string(worktree.join("README.md")).unwrap(),
            "original\nHello from MACO\n"
        );
    }
}

#[test]
fn worker_journal_lock_release_survives_an_inherited_open_description() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let lock =
        WorkerJournalAppendLock::acquire(open_worker_journal_no_follow(&path, true).unwrap())
            .unwrap();
    // A fork in another thread retains the same open description until exec.
    // A duplicate deterministically models that lifetime without a fork race.
    let inherited = lock.file.try_clone().unwrap();
    let record = observed_entry(&worktree, &["true"]);
    let error = WorkerJournalAppendLock::acquire_with_timeout(
        open_worker_journal_no_follow(&path, true).unwrap(),
        std::time::Duration::from_millis(20),
    )
    .err()
    .expect("the active holder must not be bypassed");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(error
        .to_string()
        .contains("exclusive worker journal append lock"));
    assert!(fs::read(&path).unwrap().is_empty());
    drop(lock);
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    let records = parse_worker_execution_journal(&fs::read(&path).unwrap(), &path).unwrap();
    assert_eq!(records.len(), 2);
    verify_worker_journal_identity(&inherited.metadata().unwrap(), &identity).unwrap();
}

#[test]
fn worker_journal_concurrent_cli_appends_wait_and_preserve_ordered_observations() {
    use clap::Parser;
    use std::sync::{mpsc, Barrier};
    use std::time::Duration;

    let (_temp, worktree, path, identity) = observed_fixture();
    let holder =
        WorkerJournalAppendLock::acquire(open_worker_journal_no_follow(&path, true).unwrap())
            .unwrap();
    let barrier = Barrier::new(3);
    let (finished, received) = mpsc::channel();
    std::thread::scope(|scope| {
        let handles: Vec<_> = [
            "printf 'first\\n' >> README.md",
            "printf 'second\\n' >> README.md",
        ]
        .into_iter()
        .map(|command| {
            let finished = finished.clone();
            let barrier = &barrier;
            let path = &path;
            let identity = &identity;
            let worktree = &worktree;
            scope.spawn(move || {
                let args = vec![
                    "maco".to_string(),
                    "supervise".into(),
                    "journal-append".into(),
                    "--journal".into(),
                    path.to_str().unwrap().into(),
                    "--device".into(),
                    identity.device.to_string(),
                    "--inode".into(),
                    identity.file.to_string(),
                    "--cwd".into(),
                    worktree.to_str().unwrap().into(),
                    "--auto-timestamps".into(),
                    "--".into(),
                    "/bin/sh".into(),
                    "-c".into(),
                    command.into(),
                ];
                let cli = crate::cli::Cli::try_parse_from(args).unwrap();
                barrier.wait();
                let result = cli.run();
                finished.send(()).unwrap();
                result
            })
        })
        .collect();
        barrier.wait();
        // Both invocations overlap a held lock. Neither may fail immediately,
        // append an intent record, or execute its source mutation while waiting.
        let early = received.recv_timeout(Duration::from_millis(150));
        let waiting_bytes = fs::read(&path).unwrap();
        let waiting_source = fs::read_to_string(worktree.join("README.md")).unwrap();
        drop(holder);
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(early, Err(mpsc::RecvTimeoutError::Timeout));
        assert!(waiting_bytes.is_empty());
        assert_eq!(waiting_source, "original\n");
    });
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    // Two invocations each produce an adjacent started/completed pair; parsing
    // also checks digest continuity and rejects interleaved command records.
    let records = parse_worker_execution_journal(&bytes, &path).unwrap();
    assert_eq!(records.len(), 4);
    assert_ne!(records[0].command, records[2].command);
    for pair in records.chunks_exact(2) {
        assert_eq!(pair[0].command, pair[1].command);
        assert_eq!(pair[0].cwd, worktree);
        assert_eq!(pair[1].changed_paths, [PathBuf::from("README.md")]);
        assert_eq!(
            pair[0].observation.as_ref().unwrap().phase,
            WorkerJournalObservationPhase::Started
        );
        assert_eq!(
            pair[1].observation.as_ref().unwrap().phase,
            WorkerJournalObservationPhase::Completed
        );
    }
    let expected = if records[0].command[2].contains("first") {
        "original\nfirst\nsecond\n"
    } else {
        "original\nsecond\nfirst\n"
    };
    assert_eq!(
        fs::read_to_string(worktree.join("README.md")).unwrap(),
        expected
    );
    verify_worker_journal_identity(&fs::metadata(&path).unwrap(), &identity).unwrap();
}

#[test]
fn worker_journal_observation_detects_create_delete_restore_and_executable_mode() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let mut record = observed_entry(&worktree, &["/bin/sh", "-c", "mv README.md moved.md"]);
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    record.command[2] = "mv moved.md README.md; chmod +x README.md".to_string();
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    record.command[2] = "chmod -x README.md".to_string();
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    let records =
        parse_worker_execution_journal(&fs::read(path).unwrap(), Path::new("journal")).unwrap();
    assert_eq!(
        records[1].changed_paths,
        vec![PathBuf::from("README.md"), PathBuf::from("moved.md")]
    );
    assert_eq!(records[3].changed_paths, records[1].changed_paths);
    assert_eq!(records[5].changed_paths, vec![PathBuf::from("README.md")]);
    assert!(records[5].observation.as_ref().unwrap().after.is_empty());
}

#[test]
fn worker_journal_refuses_incomplete_or_discontinuous_observation() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let record = observed_entry(&worktree, &["/bin/sh", "-c", "printf edited >> README.md"]);
    run_worker_execution_journal_command(&path, &identity, &record, false).unwrap();
    let bytes = fs::read(&path).unwrap();
    let first = bytes.split_inclusive(|byte| *byte == b'\n').next().unwrap();
    assert!(parse_worker_execution_journal(first, &path)
        .unwrap_err()
        .to_string()
        .contains("unfinished"));
    let mut records = parse_worker_execution_journal(&bytes, &path).unwrap();
    records[1]
        .observation
        .as_mut()
        .unwrap()
        .before
        .insert(PathBuf::from("invented"), "0".repeat(64));
    assert!(validate_worker_journal_observations(&records)
        .unwrap_err()
        .to_string()
        .contains("continuity"));
}

#[test]
fn worker_journal_failed_command_retains_observed_mutation() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let record = observed_entry(
        &worktree,
        &["/bin/sh", "-c", "printf edited >> README.md; exit 7"],
    );
    let error = run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
    assert!(!error.to_string().contains("WorkerJournalPrelaunchRejected"));
    let records =
        parse_worker_execution_journal(&fs::read(path).unwrap(), Path::new("journal")).unwrap();
    assert_eq!(records[1].changed_paths, vec![PathBuf::from("README.md")]);
}

#[test]
fn worker_journal_enosys_launch_failure_has_completed_observation() {
    let _error = Openat2Error::force(libc::ENOSYS).with_statx_enosys();
    let (_temp, worktree, path, identity) = observed_fixture();
    let record = observed_entry(&worktree, &["/no-such-maco-test-command"]);
    let error = run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
    assert!(error.to_string().contains("failed to launch"));
    assert!(!error.to_string().contains("WorkerJournalPrelaunchRejected"));
    let records = parse_worker_execution_journal(&fs::read(&path).unwrap(), &path).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].observation.as_ref().unwrap().phase,
        WorkerJournalObservationPhase::Completed
    );
    assert!(records[1].changed_paths.is_empty());
}

#[test]
fn worker_journal_enosys_observation_failure_is_terminal_and_refuses_retry() {
    let _error = Openat2Error::force(libc::ENOSYS).with_statx_enosys();
    for command in [
        "rm README.md; ln -s ../outside README.md",
        "printf 'ref: refs/heads/other\\n' > .git/HEAD",
        "mv ../worktree ../moved; mkdir ../worktree",
    ] {
        let (_temp, worktree, path, identity) = observed_fixture();
        let outside = worktree.parent().unwrap().join("outside");
        fs::write(&outside, "outside unchanged").unwrap();
        let record = observed_entry(&worktree, &["/bin/sh", "-c", command]);
        let error =
            run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
        assert!(
            error.to_string().contains("terminal failure preserved"),
            "{error:#}"
        );
        assert!(!error.to_string().contains("WorkerJournalPrelaunchRejected"));
        let bytes = fs::read(&path).unwrap();
        let records: Vec<WorkerExecutionJournalEntry> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].observation.as_ref().unwrap().phase,
            WorkerJournalObservationPhase::Started
        );
        let failed = records[1].observation.as_ref().unwrap();
        assert_eq!(failed.phase, WorkerJournalObservationPhase::Failed);
        assert!(failed
            .failure
            .as_ref()
            .is_some_and(|error| !error.is_empty()));
        assert_eq!(failed.before, failed.after);
        let error = parse_worker_execution_journal(&bytes, &path).unwrap_err();
        assert!(
            error.to_string().contains("terminal observation failure"),
            "{error:#}"
        );
        assert!(run_worker_execution_journal_command(&path, &identity, &record, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside unchanged");
    }
}

#[test]
fn worker_journal_enosys_completion_overflow_records_terminal_failure() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let (_temp, worktree, path, identity) = observed_fixture();
    let mut filler = entry();
    filler.command = vec!["x".repeat(MAX_WORKER_EXECUTION_JOURNAL_BYTES - 12_000)];
    append_precreated_worker_execution_journal(&path, &identity, &filler).unwrap();
    let record = observed_entry(
        &worktree,
        &[
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 200 ]; do printf new > file-$i; i=$((i + 1)); done",
        ],
    );
    let error = run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
    assert!(
        error.to_string().contains("terminal failure preserved"),
        "{error:#}"
    );
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() <= MAX_WORKER_EXECUTION_JOURNAL_BYTES);
    let failed: WorkerExecutionJournalEntry =
        serde_json::from_slice(bytes.split(|byte| *byte == b'\n').nth(2).unwrap()).unwrap();
    assert_eq!(
        failed.observation.unwrap().phase,
        WorkerJournalObservationPhase::Failed
    );
    assert!(parse_worker_execution_journal(&bytes, &path)
        .unwrap_err()
        .to_string()
        .contains("terminal observation failure"));
}

#[test]
fn worker_journal_reserves_terminal_failure_space_before_execution() {
    let (_temp, worktree, path, identity) = observed_fixture();
    let mut filler = entry();
    filler.command = vec!["x".repeat(MAX_WORKER_EXECUTION_JOURNAL_BYTES - 4_000)];
    append_precreated_worker_execution_journal(&path, &identity, &filler).unwrap();
    let bytes = fs::read(&path).unwrap();
    let record = observed_entry(&worktree, &["/bin/sh", "-c", "touch should-not-run"]);
    let error = run_worker_execution_journal_command(&path, &identity, &record, false).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no room for command start and terminal failure"),
        "{error:#}"
    );
    assert!(!worktree.join("should-not-run").exists());
    assert_eq!(fs::read(path).unwrap(), bytes);
}
