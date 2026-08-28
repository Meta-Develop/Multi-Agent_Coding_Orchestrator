    #[cfg(unix)]
    #[test]
    fn absent_process_group_skips_termination_grace() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        command.process_group(0);
        let mut child = command.spawn().expect("spawn short-lived child");
        child.wait().expect("wait for short-lived child");
        let wait_calls = std::cell::Cell::new(0usize);

        let error =
            terminate_unix_process_group_with_wait(&mut child, true, "short-lived child", |_| {
                wait_calls.set(wait_calls.get() + 1)
            });

        assert_eq!(error, None);
        assert_eq!(wait_calls.get(), 0, "missing groups must skip TERM grace");
    }

    #[cfg(unix)]
    #[test]
    fn required_containment_kills_setsid_pipe_and_stdin_holders() {
        skip_without_containment!();
        const READINESS_FUSE: Duration = Duration::from_secs(10);
        const POST_RELEASE_BOUND: Duration = Duration::from_secs(2);

        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let escaped_pid_path = temp.path().join("escaped.pid");
        let target_ready_path = temp.path().join("target-ready");
        let release_target_path = temp.path().join("release-target");
        let command = format!(
            "exec 3<&0; setsid sh -c 'echo $$ > \"{}\"; sleep 30' <&3 & i=0; while [ ! -s \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done; test -s \"{}\" || exit 1; touch \"{}\"; while [ ! -e \"{}\" ]; do sleep 0.01; done",
            escaped_pid_path.display(),
            escaped_pid_path.display(),
            escaped_pid_path.display(),
            target_ready_path.display(),
            release_target_path.display(),
        );
        let spec = ProcessSpec::shell(
            "escaped pipe holder",
            Shell::UnixSh,
            command,
            temp.path(),
            1024,
        )
        .with_stdin(StdinMode::Bytes(vec![b'x'; 4 * 1024 * 1024]))
        // Allow shared systemd-slot and setup contention to settle before the target publishes
        // readiness; the post-ready cleanup remains independently bounded below.
        .with_timeout(Some(Duration::from_secs(10)));
        let (completion_tx, completion_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = completion_tx.send(run_process(spec));
        });
        let output = {
            // This fuse is independent of the process timeout and post-release bound. Expiry
            // means the strict target made no observable readiness progress for ten seconds.
            let readiness_deadline = Instant::now()
                .checked_add(READINESS_FUSE)
                .expect("representable strict readiness deadline");
            while !target_ready_path.exists() && !worker.is_finished() {
                assert!(
                    Instant::now() < readiness_deadline,
                    "escaped pipe holder did not publish readiness within ten seconds"
                );
                thread::sleep(POLL_INTERVAL);
            }
            assert!(
                target_ready_path.exists(),
                "escaped pipe holder exited before publishing readiness"
            );

            // Shared systemd-slot and setup contention is not kill latency. Release the main
            // shell only after its escaped stdin/pipe holder is ready, then keep the safety bound
            // focused on finalization proving the complete contained tree empty. The completion
            // event is emitted after the complete `run_process` call, including its blocking
            // containment commands and internal I/O joins. Two seconds preserves the original
            // post-release contract; expiry means cleanup itself stopped being prompt. Avoiding a
            // JoinHandle wait ensures a regression fails this test instead of hanging the suite.
            let release_started = Instant::now();
            fs::write(&release_target_path, b"release").expect("release escaped pipe holder");
            let completion = completion_rx
                .recv_timeout(POST_RELEASE_BOUND.saturating_sub(release_started.elapsed()))
                .expect(
                    "escaped pipe holder completed within its two-second post-release contract",
                );
            let post_release_elapsed = release_started.elapsed();
            assert!(
                post_release_elapsed < POST_RELEASE_BOUND,
                "escaped pipe holder exceeded its whole post-release two-second contract: {post_release_elapsed:?}"
            );
            completion.expect("run escaped pipe holder")
        };

        let escaped_pid = std::fs::read_to_string(&escaped_pid_path)
            .expect("escaped process pid")
            .trim()
            .parse::<u32>()
            .expect("numeric escaped process pid");
        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        assert_eq!(output.process_error, None);
        assert!(output.process_tree.is_verified_empty());
        let escaped_pid = libc::pid_t::try_from(escaped_pid).expect("pid_t escaped pid");
        // SAFETY: signal 0 probes existence without delivering a signal.
        assert_eq!(unsafe { libc::kill(escaped_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "escaped descendant survived return"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stdin_and_environment_modes_are_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut environment = BTreeMap::new();
        environment.insert("MACO_PROCESS_TEST".to_string(), "present".to_string());
        let spec = ProcessSpec::shell(
            "stdin/env command",
            Shell::UnixSh,
            "read value; printf '%s:%s:%s' \"$MACO_PROCESS_TEST\" \"$value\" \"${HOME-unset}\"",
            temp.path(),
            1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Bytes(b"payload\n".to_vec()))
        .with_timeout(Some(Duration::from_secs(1)));

        let output = run_process(spec).expect("run stdin/env command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(
            output.stdout.summarize_chars(1024).text,
            "present:payload:unset"
        );
        assert_eq!(output.stdin_error, None);
    }

    #[test]
    fn spawn_error_identifies_command_label_and_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_program = temp.path().join("missing-program");
        let spec = ProcessSpec::direct(
            "missing command",
            &missing_program,
            Vec::<OsString>::new(),
            temp.path(),
            128,
        );

        let error = run_process(spec).expect_err("missing command must fail to spawn");

        match &error {
            ProcessRunError::Spawn {
                label,
                command,
                current_dir,
                ..
            } => {
                assert_eq!(label, "missing command");
                assert!(command.contains(&missing_program.display().to_string()));
                assert_eq!(current_dir, temp.path());
            }
            other => panic!("expected spawn error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invalid_tee_path_prevents_child_side_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("child-ran");
        let missing_tee_parent = temp.path().join("missing").join("stdout.log");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "command with invalid tee",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(missing_tee_parent));

        let error = run_process(spec).expect_err("invalid tee must fail before spawn");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn new_tee_preflight_error_removes_only_created_inode() {
        const CHILD_ENV: &str = "MACO_TEST_NEW_TEE_PREFLIGHT_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let tee = root.join("new-tee.log");
            let marker = root.join("target-ran");
            let error = run_process(
                ProcessSpec::shell(
                    "new tee preflight failure",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_stdout(StreamCapture::bounded(128).tee_to(&tee)),
            )
            .expect_err("synthetic new tee preflight failure");
            assert!(matches!(error, ProcessRunError::OpenTee { .. }));
            assert!(!tee.exists());
            assert!(!marker.exists());
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::new_tee_preflight_error_removes_only_created_inode",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_TEE_ROOT", temp.path())
            .env("MACO_TEST_FAIL_NEW_TEE_PREFLIGHT", "1")
            .status()
            .expect("run isolated new tee preflight failure");
        assert!(status.success());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn same_tee_file_is_rejected_before_child_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let tee_path = temp.path().join("combined.log");
        let marker = temp.path().join("child-ran");
        std::fs::write(&tee_path, "preserve me").expect("write existing tee");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell("same tee command", Shell::UnixSh, command, temp.path(), 128)
            .with_stdout(StreamCapture::bounded(128).tee_to(&tee_path))
            .with_stderr(StreamCapture::bounded(128).tee_to(&tee_path));

        let error = run_process(spec).expect_err("same tee must be rejected");

        assert!(matches!(error, ProcessRunError::TeeConflict { .. }));
        assert_eq!(
            std::fs::read_to_string(&tee_path).expect("read preserved tee"),
            "preserve me"
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_tee_files_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let stderr_path = temp.path().join("stderr.log");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::hard_link(&stdout_path, &stderr_path).expect("hard link stderr tee");
        let spec = ProcessSpec::shell(
            "hard-linked tee command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));

        let error = run_process(spec).expect_err("hard-linked tees must be rejected");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved tee"),
            "preserve me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn second_tee_preflight_failure_preserves_first_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let invalid_stderr_path = temp.path().join("stderr-directory");
        let marker = temp.path().join("child-ran");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::create_dir(&invalid_stderr_path).expect("create invalid stderr directory");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "transactional tee command",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));

        let error = run_process(spec).expect_err("invalid second tee must fail preflight");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved stdout tee"),
            "preserve me"
        );
        assert!(!marker.exists());

        let new_stdout_path = temp.path().join("new-stdout.log");
        let second_spec = ProcessSpec::shell(
            "new tee rollback command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&new_stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));
        let second_error =
            run_process(second_spec).expect_err("new first tee must roll back on second failure");
        assert!(matches!(second_error, ProcessRunError::OpenTee { .. }));
        assert!(!new_stdout_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tee_transaction_rolls_back_single_and_second_helper_start_failures() {
        const CHILD_ENV: &str = "MACO_TEST_TEE_TRANSACTION_CHILD";
        if let Some(case) = env::var_os(CHILD_ENV) {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let stdout_path = root.join("stdout.log");
            let stderr_path = root.join("stderr.log");
            let marker = root.join("target-ran");
            let mut stdout_before = None;
            let mut spec = ProcessSpec::shell(
                "transactional helper failure",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                &root,
                128,
            )
            .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path));
            match case.to_string_lossy().as_ref() {
                "single" => {
                    fs::write(&stdout_path, "original stdout").expect("seed stdout");
                }
                "second" | "second-truncate" => {
                    use std::os::unix::fs::MetadataExt;
                    fs::write(&stdout_path, "original stdout").expect("seed stdout");
                    fs::write(&stderr_path, "original stderr").expect("seed stderr");
                    let metadata = fs::metadata(&stdout_path).expect("stdout metadata before");
                    stdout_before = Some((
                        metadata.ino(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                        metadata.len(),
                    ));
                    spec = spec.with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));
                }
                "new-second" => {
                    spec = spec.with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));
                }
                other => panic!("unexpected tee transaction case {other}"),
            }

            let error = run_process(spec).expect_err("synthetic tee helper failure");
            assert!(matches!(error, ProcessRunError::OpenTee { .. }));
            assert!(!marker.exists());
            match case.to_string_lossy().as_ref() {
                "single" => {
                    assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
                }
                "second" | "second-truncate" => {
                    use std::os::unix::fs::MetadataExt;
                    assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
                    assert_eq!(fs::read_to_string(&stderr_path).unwrap(), "original stderr");
                    let metadata = fs::metadata(&stdout_path).expect("stdout metadata after");
                    if case == "second" {
                        assert_eq!(
                            stdout_before,
                            Some((
                                metadata.ino(),
                                metadata.mtime(),
                                metadata.mtime_nsec(),
                                metadata.len(),
                            )),
                            "pre-truncate helper failure rewrote untouched stdout"
                        );
                    }
                }
                "new-second" => {
                    assert!(!stdout_path.exists());
                    assert!(!stderr_path.exists());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                fs::read_dir(&root)
                    .expect("tee root entries")
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                    .count(),
                0
            );
            return;
        }

        for (case, failpoint, failed_stream) in [
            ("single", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stdout"),
            ("second", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stderr"),
            (
                "second-truncate",
                "MACO_TEST_FAIL_TEE_TRUNCATE_STREAM",
                "stderr",
            ),
            ("new-second", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stderr"),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let mut command =
                Command::new(std::env::current_exe().expect("current test executable"));
            command
                .args([
                    "--exact",
                    "process_runner::tests::tee_transaction_rolls_back_single_and_second_helper_start_failures",
                ])
                .env(CHILD_ENV, case)
                .env("MACO_TEST_TEE_ROOT", temp.path())
                .env(failpoint, failed_stream);
            if case == "second" {
                command.env("MACO_TEST_FAIL_TEE_RESTORE", "1");
            }
            let status = command.status().expect("run isolated tee transaction case");
            assert!(status.success(), "tee transaction child {case} failed");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tee_transaction_rolls_back_spawn_and_pre_release_io_failures() {
        const CHILD_ENV: &str = "MACO_TEST_TEE_SETUP_ROLLBACK_CHILD";
        if let Some(case) = env::var_os(CHILD_ENV) {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let stdout_path = root.join("stdout.log");
            let stderr_path = root.join("stderr.log");
            let helper_pids = root.join("helper-pids");
            let marker = root.join("target-ran");
            fs::write(&stdout_path, "original stdout").expect("seed stdout");
            fs::write(&stderr_path, "original stderr").expect("seed stderr");
            let error = run_process(
                ProcessSpec::shell(
                    "tee setup rollback",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_containment(ContainmentPolicy::TrustedBestEffort)
                .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
                .with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path))
                .with_timeout(Some(Duration::from_secs(3))),
            )
            .expect_err("synthetic setup failure");
            match case.to_string_lossy().as_ref() {
                "spawn" => assert!(matches!(error, ProcessRunError::Spawn { .. })),
                "io" => assert!(matches!(error, ProcessRunError::IoSetup { .. })),
                other => panic!("unexpected setup rollback case {other}"),
            }
            assert!(!marker.exists());
            assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
            assert_eq!(fs::read_to_string(&stderr_path).unwrap(), "original stderr");
            for pid in fs::read_to_string(helper_pids)
                .expect("helper pids")
                .lines()
            {
                let pid = pid.parse::<libc::pid_t>().expect("helper pid");
                // SAFETY: signal zero only probes a tee helper started by this isolated test.
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
            assert_eq!(
                fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                    .count(),
                0
            );
            return;
        }

        for (case, failpoint) in [
            ("spawn", "MACO_TEST_FAIL_BEFORE_CHILD_SPAWN"),
            ("io", "MACO_TEST_FAIL_PRE_RELEASE_IO_SETUP"),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let status = Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "process_runner::tests::tee_transaction_rolls_back_spawn_and_pre_release_io_failures",
                ])
                .env(CHILD_ENV, case)
                .env("MACO_TEST_TEE_ROOT", temp.path())
                .env(
                    "MACO_TEST_TEE_HELPER_PID_FILE",
                    temp.path().join("helper-pids"),
                )
                .env(failpoint, "1")
                .status()
                .expect("run isolated tee setup rollback case");
            assert!(status.success(), "tee setup rollback child {case} failed");
        }
    }

    #[cfg(unix)]
    #[test]
    fn tee_preflight_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.log");
        let link = temp.path().join("tee.log");
        let marker = temp.path().join("target-ran");
        fs::write(&target, "preserve target").expect("seed symlink target");
        symlink(&target, &link).expect("create tee symlink");
        let error = run_process(
            ProcessSpec::shell(
                "symlink tee",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                temp.path(),
                128,
            )
            .with_stdout(StreamCapture::bounded(128).tee_to(&link)),
        )
        .expect_err("symlink tee must fail before target start");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(fs::read_to_string(target).unwrap(), "preserve target");
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tee_transaction_detects_path_swap_and_restores_pinned_inode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let moved = temp.path().join("original-inode.log");
        fs::write(&path, "original contents").expect("seed tee");
        let capture = StreamCapture::bounded(128).tee_to(&path);
        let transaction = prepare_tees(
            "path swap",
            &capture,
            &StreamCapture::bounded(128),
            false,
            None,
            "test",
        )
        .expect("prepare tee transaction");
        let helper_pid = transaction
            .stdout
            .as_ref()
            .and_then(|tee| tee.writer.as_ref())
            .map(|writer| writer.helper.child.id())
            .expect("stdout helper pid");
        fs::rename(&path, &moved).expect("move pinned tee inode");
        fs::write(&path, "replacement contents").expect("install replacement path");

        let error = transaction
            .validate("path swap")
            .expect_err("path swap must invalidate tee transaction");
        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        drop(transaction);

        assert_eq!(fs::read_to_string(moved).unwrap(), "original contents");
        assert_eq!(fs::read_to_string(path).unwrap(), "replacement contents");
        let helper_pid = libc::pid_t::try_from(helper_pid).expect("helper pid_t");
        // SAFETY: signal zero only probes the helper PID captured above.
        assert_eq!(unsafe { libc::kill(helper_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_tee_path_swap_never_unlinks_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let moved = temp.path().join("opened-inode.log");
        let capture = StreamCapture::bounded(128).tee_to(&path);
        let transaction = prepare_tees(
            "created path swap",
            &capture,
            &StreamCapture::bounded(128),
            false,
            None,
            "test",
        )
        .expect("prepare new tee transaction");
        let helper_pid = transaction
            .stdout
            .as_ref()
            .and_then(|tee| tee.writer.as_ref())
            .map(|writer| writer.helper.child.id())
            .expect("stdout helper pid");
        fs::rename(&path, &moved).expect("move opened tee inode");
        fs::write(&path, "replacement contents").expect("install replacement path");

        let error = transaction
            .validate("created path swap")
            .expect_err("created path swap must invalidate transaction");
        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        drop(transaction);

        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement contents");
        assert_eq!(fs::metadata(&moved).unwrap().len(), 0);
        let helper_pid = libc::pid_t::try_from(helper_pid).expect("helper pid_t");
        // SAFETY: signal zero only probes the helper PID captured above.
        assert_eq!(unsafe { libc::kill(helper_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                .count(),
            0
        );
    }

    #[test]
    fn tee_backup_restores_content_and_removes_temporary_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        std::fs::write(&path, "original tee contents").expect("write tee source");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict tee source permissions");
        }
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee source");
        let backup = TeeBackup::create(&source, &path).expect("create tee backup");
        let backup_path = backup.path.clone();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backup_path)
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let mut destination = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee destination");
        destination.set_len(0).expect("truncate destination");
        destination
            .write_all(b"partial")
            .expect("write partial tee");

        backup
            .restore(&mut destination)
            .expect("restore tee backup");
        drop(destination);
        drop(backup);

        assert_eq!(
            std::fs::read_to_string(&path).expect("read restored tee"),
            "original tee contents"
        );
        assert!(!backup_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn wait_error_evidence_retains_captured_output_and_cleanup_diagnostics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::shell(
            "evidence child",
            Shell::UnixSh,
            "printf retained-stdout; printf retained-stderr >&2; sleep 30",
            temp.path(),
            1024,
        )
        .with_stdin(StdinMode::Null)
        .with_containment(ContainmentPolicy::TrustedBestEffort);
        let cancellation = ProcessCancellation::new();
        let mut prepared_tree = PreparedProcessTree::prepare(
            spec.containment,
            &spec.side_effects,
            "evidence child",
            "sh",
            None,
            &cancellation,
        )
        .expect("prepare evidence containment");
        let mut command = prepared_tree
            .build_command(&spec)
            .expect("build evidence child");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn evidence child");
        let attached_tree = prepared_tree
            .attach(&mut child, "evidence child", "sh", None, &cancellation)
            .expect("attach evidence child");
        let prepared = PreparedChildIo::take(&mut child, &StdinMode::Null)
            .expect("prepare evidence child I/O");
        let mut process_tree = attached_tree
            .release(&mut child, "evidence child", "sh", None, &cancellation)
            .expect("release evidence child");
        let (input_writer, mut output_drainers) =
            prepared.start("evidence child", StdinMode::Null, 1024, 1024, None, None);
        // Real pipe-reader delivery is part of this integration test. Sixty seconds is a harness
        // fuse for two tiny writes; expiry means the owned reader threads made no observable
        // progress, not that a loaded host scheduled them a few milliseconds late.
        let deadline = Instant::now() + Duration::from_secs(60);
        while output_drainers.stdout.capture.bytes.is_empty()
            || output_drainers.stderr.capture.bytes.is_empty()
        {
            output_drainers.drain_ready();
            assert!(Instant::now() < deadline, "child output was not captured");
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }

        let evidence = cleanup_after_wait_error(
            &mut child,
            &mut process_tree,
            "evidence child",
            output_drainers,
            input_writer,
        );

        assert_eq!(evidence.stdout.as_bytes(), b"retained-stdout");
        assert_eq!(evidence.stderr.as_bytes(), b"retained-stderr");
        let error = ProcessRunError::Wait {
            label: "evidence child".to_string(),
            command: "sh".to_string(),
            evidence: Box::new(evidence),
            source: std::io::Error::other("synthetic wait failure"),
        };
        assert!(error.to_string().contains("retained-stdout"));
        assert!(error.to_string().contains("retained-stderr"));
    }

    #[test]
    fn platform_shell_is_concrete() {
        #[cfg(target_os = "windows")]
        assert_eq!(Shell::for_current_platform(), Shell::WindowsCmd);

        #[cfg(not(target_os = "windows"))]
        assert_eq!(Shell::for_current_platform(), Shell::UnixSh);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_children_start_suspended_in_a_new_process_group() {
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_SUSPENDED, 0);
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_NEW_PROCESS_GROUP, 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tee_identity_uses_volume_and_file_index() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let hard_link = temp.path().join("tee-hardlink.log");
        let replacement = temp.path().join("replacement.log");
        fs::write(&path, "tee").expect("write tee");
        fs::hard_link(&path, &hard_link).expect("hard-link tee");
        fs::write(&replacement, "replacement").expect("write replacement");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee");

        assert!(tee_path_matches_file(&hard_link, &file).expect("hard-link identity"));
        assert!(!tee_path_matches_file(&replacement, &file).expect("replacement identity"));
    }

    #[test]
    fn bounded_buffer_never_grows_past_limit() {
        let mut buffer = BoundedBuffer::new(3);
        buffer.push(b"abcdef");
        buffer.push(b"ghij");
        let captured = buffer.into_captured();
        assert_eq!(captured.as_bytes(), b"abc");
        assert!(captured.is_truncated());
    }

    #[test]
    fn direct_command_constructor_preserves_arguments() {
        let spec = ProcessSpec::direct(
            "direct",
            PathBuf::from("program"),
            ["one", "two"],
            PathBuf::from("."),
            128,
        );
        assert_eq!(
            spec.command,
            ProcessCommand::Direct {
                program: PathBuf::from("program"),
                args: vec![OsString::from("one"), OsString::from("two")],
            }
        );
        assert!(spec.pinned_direct.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn agent_lifecycle_metadata_stamps_environment_and_registers_running_process() {
        skip_without_containment!();
        #[cfg(target_os = "linux")]
        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        git2::Repository::init(temp.path()).expect("init repository");
        let metadata = AgentLaunchMetadata::new(temp.path(), "worker", "runner-run", "runner-task")
            .expect("lifecycle metadata");
        let sleep = [
            "/run/current-system/sw/bin/sleep",
            "/usr/bin/sleep",
            "/bin/sleep",
        ]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .expect("sleep executable")
        .to_path_buf();
        let spec = ProcessSpec::direct("lifecycle sleep", sleep, ["60"], temp.path(), 128)
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::from([(
                "PATH".to_string(),
                "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
            )])))
            .with_agent_lifecycle(metadata);
        let EnvironmentMode::ClearAndSet(environment) = &spec.environment else {
            panic!("expected clear-and-set environment");
        };
        assert_eq!(
            environment.get(MACO_RUN_ID_ENV).map(String::as_str),
            Some("runner-run")
        );
        assert_eq!(
            environment.get(MACO_TASK_ID_ENV).map(String::as_str),
            Some("runner-task")
        );

        let registry = AgentRegistry::open(temp.path()).expect("agent registry");
        let runner = thread::spawn(move || run_process(spec));
        let registered = loop {
            let processes = registry
                .list(&crate::agent_lifecycle::AgentListFilter::default())
                .expect("list lifecycle processes");
            if let Some(process) = processes.first() {
                break process.clone();
            }
            assert!(
                !runner.is_finished(),
                "process runner completed before registering its agent lifecycle identity"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(registered.run_id, "runner-run");
        assert_eq!(registered.task_id, "runner-task");
        assert_eq!(registered.argv.last().map(String::as_str), Some("60"));

        // This is the one real signal-delivery deadline in the test. Thirty seconds is a liveness
        // margin for stopping one local sleep process; expiry means lifecycle termination made no
        // progress, not that registration ordering was scheduled a few milliseconds late.
        let stopped = registry
            .stop_selector("runner-task", Duration::from_secs(30))
            .expect("stop lifecycle process");
        assert_eq!(stopped.stopped.len(), 1);
        let output = runner
            .join()
            .unwrap_or_else(|_| panic!("process runner thread panicked"))
            .expect("process runner result");
        assert!(output.status.is_some_and(|status| !status.success()));
    }

    #[test]
    fn shell_constructor_preserves_general_unpinned_behavior() {
        let spec = ProcessSpec::shell(
            "shell",
            Shell::for_current_platform(),
            "echo unchanged",
            PathBuf::from("."),
            128,
        );
        assert!(matches!(spec.command, ProcessCommand::Shell { .. }));
        assert!(spec.pinned_direct.is_none());
        assert!(spec.command_display().contains("echo unchanged"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_guardian_bootstraps_helper_with_an_empty_environment() {
        assert!(SYSTEMD_GUARDIAN_SCRIPT
            .contains("if [ \"$target_environment_mode\" = descriptor ]; then"));
        assert!(SYSTEMD_GUARDIAN_SCRIPT.contains("exec \"$env_program\" -i \"$@\" || exit 125"));
        let descriptor_branch = SYSTEMD_GUARDIAN_SCRIPT
            .split("if [ \"$target_environment_mode\" = descriptor ]; then")
            .nth(1)
            .and_then(|text| text.split("fi").next())
            .expect("descriptor guardian branch");
        assert!(!descriptor_branch.contains(". \"$1\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_direct_capability_is_direct_only_and_detects_command_drift() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("program");
        fs::write(&program, b"native executable fixture").expect("write program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod program");
        let capability = PinnedDirectExecutable::capture_for_test(&program).expect("capture");

        let spec = ProcessSpec::direct("pinned", &program, ["--fixed"], temp.path(), 128)
            .with_pinned_direct_executable(capability.clone())
            .expect("attach capability");
        assert!(spec.pinned_direct.is_some());
        assert!(spec.command_display().contains("arguments redacted"));
        assert!(!spec.command_display().contains("--fixed"));

        let mut drifted = spec.clone();
        let ProcessCommand::Direct { args, .. } = &mut drifted.command else {
            panic!("direct command");
        };
        args.push(OsString::from("--drifted"));
        let error = drifted
            .pinned_direct
            .as_ref()
            .expect("pinned binding")
            .validate_command(&drifted.command)
            .expect_err("argv drift must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let shell_error = ProcessSpec::shell("shell", Shell::UnixSh, ":", temp.path(), 128)
            .with_pinned_direct_executable(capability)
            .expect_err("shell pinning must fail");
        assert_eq!(shell_error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_pinned_capability_refuses_untrusted_development_helper() {
        use std::os::unix::fs::PermissionsExt;

        if pinned_exec::validated_current_helper_path().is_ok() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("program");
        fs::write(&program, b"native executable fixture").expect("write program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod program");
        let error = PinnedDirectExecutable::capture(&program)
            .expect_err("development helper must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a root-owned installed maco helper and trusted user-systemd runtime"]
    fn pinned_direct_strict_runtime_executes_only_after_helper_bootstrap() {
        let program = trusted_system_executable(
            "true",
            &[
                "/usr/bin/true",
                "/bin/true",
                "/run/current-system/sw/bin/true",
            ],
        )
        .expect("trusted true");
        let capability = PinnedDirectExecutable::capture(&program).expect("capture true");
        let output = run_process(
            ProcessSpec::direct(
                "pinned true",
                &program,
                Vec::<OsString>::new(),
                Path::new("/"),
                128,
            )
            .with_pinned_direct_executable(capability)
            .expect("pin true")
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_stdin(StdinMode::Null),
        )
        .expect("run pinned true");
        assert!(output.safety_sensitive_succeeded());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_best_effort_is_explicit_and_never_reported_as_verified() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = run_process(
            ProcessSpec::shell(
                "trusted compatibility command",
                Shell::UnixSh,
                ":",
                temp.path(),
                128,
            )
            .with_containment(ContainmentPolicy::TrustedBestEffort),
        )
        .expect("run trusted compatibility command");
        assert_eq!(
            output.process_tree,
            ContainmentEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        );
        assert!(!output.process_tree.is_verified_empty());
    }

    #[test]
    fn required_containment_platform_contract_is_explicit_and_fail_closed() {
        #[cfg(target_os = "linux")]
        assert_eq!(
            RequiredContainmentPlatform::current(),
            RequiredContainmentPlatform::Linux
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            RequiredContainmentPlatform::current(),
            RequiredContainmentPlatform::MacOs
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            RequiredContainmentPlatform::current(),
            RequiredContainmentPlatform::Windows
        );
        assert_eq!(
            classify_required_containment_backend(RequiredContainmentPlatform::Linux),
            Ok(ReviewedRequiredContainmentBackend::LinuxSystemdCgroupV2)
        );
        assert_eq!(
            classify_required_containment_backend(RequiredContainmentPlatform::MacOs),
            Err(RequiredContainmentRefusal::MacOsHasNoReviewedProfile)
        );
        assert_eq!(
            classify_required_containment_backend(RequiredContainmentPlatform::Windows),
            Err(RequiredContainmentRefusal::WindowsHasNoReviewedProfile)
        );
        assert_eq!(
            classify_required_containment_backend(RequiredContainmentPlatform::OtherUnix),
            Err(RequiredContainmentRefusal::OtherUnixHasNoReviewedProfile)
        );
        assert_eq!(
            classify_required_containment_backend(RequiredContainmentPlatform::Other),
            Err(RequiredContainmentRefusal::PlatformHasNoReviewedProfile)
        );
    }

    #[test]
    fn unsupported_writable_platform_refusal_is_typed_and_user_visible() {
        for (platform, platform_name, rejected_primitive) in [
            (RequiredContainmentPlatform::MacOs, "macOS", "process group"),
            (
                RequiredContainmentPlatform::Windows,
                "Windows",
                "Job Object alone",
            ),
        ] {
            let error = select_required_containment_backend(
                platform,
                "writable runtime",
                "must-not-spawn",
            )
            .expect_err("unsupported writable platform must refuse");
            let ProcessRunError::ContainmentUnavailable { source, .. } = &error else {
                panic!("platform refusal must remain a containment-unavailable error");
            };
            let refusal = source
                .get_ref()
                .and_then(|source| source.downcast_ref::<RequiredContainmentRefusal>());
            assert!(refusal.is_some(), "refusal source must retain its type");
            let rendered = error.to_string();
            assert!(rendered.contains(platform_name));
            assert!(rendered.contains("refused before spawn"));
            assert!(rendered.contains(rejected_primitive));
            assert!(rendered.contains("not verified side-effect confinement"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_user_systemd_manager_remains_a_typed_pre_spawn_refusal() {
        let source = delegated_systemd_user_manager_cgroup(
            "0::/system.slice/issue-339-hosted-runner.service\n",
        )
        .expect_err("system service cgroup must not satisfy strict containment");
        let error = containment_setup_error(
            "issue 339 strict runtime".to_string(),
            "must-not-spawn".to_string(),
            source,
        );

        assert!(matches!(
            &error,
            ProcessRunError::EnvironmentFailure {
                failure,
                target_process_started: false,
                ..
            } if failure.category
                == crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
                && failure.summary.contains("not inside a delegated systemd user manager")
        ));
        assert!(error.to_string().contains("must-not-spawn"));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_best_effort_preparation_does_not_require_user_systemd() {
        let cancellation = ProcessCancellation::new();
        let prepared = PreparedProcessTree::prepare(
            ContainmentPolicy::TrustedBestEffort,
            &SideEffectConfinementProfile::TrustedCompatibility,
            "simulated runtime",
            "no-systemd-probe",
            None,
            &cancellation,
        )
        .expect("trusted simulation compatibility must not require systemd");

        assert!(matches!(
            prepared.backend,
            PreparedContainmentBackend::UnixProcessGroup
        ));
        assert_eq!(
            prepared.side_effects,
            SideEffectConfinementEvidence::TrustedBestEffort(
                SideEffectConfinementProfileKind::TrustedCompatibility
            )
        );
    }

    #[test]
    fn ownership_setup_errors_preserve_cleanup_diagnostics() {
        let error = ProcessRunError::ProcessOwnership {
            label: "child".to_string(),
            command: "command".to_string(),
            source: std::io::Error::other("attach failed"),
        };
        let error =
            append_process_run_error_cleanup(error, Some("kill failed; reap failed".to_string()));
        let rendered = error.to_string();
        assert!(rendered.contains("attach failed"));
        assert!(rendered.contains("kill failed; reap failed"));
    }

    #[cfg(unix)]
    fn nested_usage_record(
        parent: &str,
        child: &str,
        runtime: NestedUsageRuntimeKind,
        input: usize,
        output: usize,
        cost_usd: f64,
    ) -> NestedWorkerUsageRecord {
        NestedWorkerUsageRecord {
            schema: NESTED_USAGE_SCHEMA_V1.to_string(),
            parent_span_id: parent.to_string(),
            child_span_id: child.to_string(),
            role: "worker".to_string(),
            runtime,
            model: Some("gpt-5.6-sol".to_string()),
            usage: Some(crate::llm::Usage {
                input_tokens: input,
                output_tokens: output,
                total_tokens: input + output,
            }),
            cost_usd: Some(cost_usd),
            duration_ms: Some(8),
            complete: true,
            incomplete_reason: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn nested_worker_usage_is_harvested_across_fake_and_cli_process_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_path = temp.path().join("nested-usage.jsonl");
        let payload_path = temp.path().join("payload.jsonl");
        let parent = parent_span_id("run-337", "child-o1");
        let payload = format!(
            "{}\n{}\n",
            encode_nested_usage_record(&nested_usage_record(
                &parent,
                "worker-fake",
                NestedUsageRuntimeKind::Fake,
                11,
                4,
                0.011,
            ))
            .expect("encode fake record"),
            encode_nested_usage_record(&nested_usage_record(
                &parent,
                "worker-codex",
                NestedUsageRuntimeKind::Codex,
                30,
                6,
                0.022,
            ))
            .expect("encode cli record"),
        );
        std::fs::write(&payload_path, payload).expect("write nested usage payload");
        prepare_nested_usage_journal(&journal_path).expect("exclusive-create journal");

        let output = run_process(
            ProcessSpec::shell(
                "nested usage cli child",
                Shell::UnixSh,
                format!(
                    "test \"${{{MACO_PARENT_SPAN_ID_ENV}}}\" = '{parent}' && cat '{}' >> \"${{{MACO_NESTED_USAGE_JOURNAL_ENV}}}\"",
                    payload_path.display()
                ),
                temp.path(),
                1024,
            )
            .with_containment(ContainmentPolicy::TrustedBestEffort)
            .with_nested_usage(NestedUsageRequest {
                journal_path: journal_path.clone(),
                parent_span_id: parent.clone(),
            }),
        )
        .expect("trusted nested-usage child must run without user-systemd");
        assert!(output.status.is_some_and(|status| status.success()));
        assert!(matches!(
            output.process_tree,
            ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        ));

        let observation = harvest_nested_usage_journal(&journal_path, &parent);
        assert!(observation.completeness.is_process_observed());
        assert_eq!(observation.records.len(), 2);
        assert_eq!(
            observation.records[0].runtime,
            NestedUsageRuntimeKind::Fake
        );
        assert_eq!(
            observation.records[1].runtime,
            NestedUsageRuntimeKind::Codex
        );
        assert!(observation
            .records
            .iter()
            .all(|record| record.parent_span_id == parent));

        let reconciled = reconcile_nested_usage(&observation);
        assert_eq!(reconciled.rolling.tokens, 51);
        assert_eq!(reconciled.rolling.cost_usd, Some(0.033));
    }

    #[cfg(unix)]
    #[test]
    fn nested_usage_env_is_stamped_for_clear_and_set_child_environments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_path = temp.path().join("nested-usage.jsonl");
        let parent = parent_span_id("run-337", "task-env");
        prepare_nested_usage_journal(&journal_path).expect("exclusive-create journal");
        let output = run_process(
            ProcessSpec::shell(
                "nested usage env probe",
                Shell::UnixSh,
                format!(
                    "printf '%s\\n%s\\n' \"${{{MACO_NESTED_USAGE_JOURNAL_ENV}}}\" \"${{{MACO_PARENT_SPAN_ID_ENV}}}\""
                ),
                temp.path(),
                1024,
            )
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_containment(ContainmentPolicy::TrustedBestEffort)
            .with_nested_usage(NestedUsageRequest {
                journal_path: journal_path.clone(),
                parent_span_id: parent.clone(),
            }),
        )
        .expect("env probe");
        let stdout = String::from_utf8_lossy(output.stdout.as_bytes());
        assert!(stdout.contains(&journal_path.to_string_lossy().into_owned()));
        assert!(stdout.contains(&parent));
    }
