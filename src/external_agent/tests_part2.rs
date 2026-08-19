    #[cfg(unix)]
    #[test]
    fn codex_auth_accepts_only_bounded_private_single_link_regular_file() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let home = temp.path().join("codex-home");
        fs::create_dir(&home)?;
        let auth = home.join("auth.json");
        fs::write(&auth, br#"{"token":"redacted"}"#)?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let validated =
            ValidatedCodexAuth::load_from_home(&home)?.context("validated auth source")?;
        assert_eq!(validated.bytes, br#"{"token":"redacted"}"#);
        validated.verify_source_unchanged()?;

        fs::set_permissions(&auth, fs::Permissions::from_mode(0o644))?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let alias = home.join("auth-alias");
        fs::hard_link(&auth, &alias)?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        fs::remove_file(&alias)?;
        fs::remove_file(&auth)?;
        std::os::unix::fs::symlink("missing-auth", &auth)?;
        assert!(ValidatedCodexAuth::load_from_home(&home).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn version_preflight_setup_timeout_is_typed_and_retains_containment_evidence() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let marker = temp.path().join("must-not-run");
        let agent = temp.path().join("fake-agent.sh");
        fs::write(&agent, format!("#!/bin/sh\ntouch '{}'\n", marker.display()))?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "do not start\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            agent,
            temp.path(),
            &prompt,
            incoming.join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::ZERO,
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly);

        let report = run_external_agent(&spec);

        assert!(report.timed_out);
        assert_eq!(report.exit_code, None);
        assert_eq!(
            report.process_tree,
            Some(ProcessTreeEvidence::Unverified(
                ContainmentBackend::SystemdUserService
            ))
        );
        assert_eq!(
            report.side_effects,
            Some(SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::ExternalCodex
            ))
        );
        assert!(report.environment_blocked());
        assert_eq!(
            report
                .environment_failures()
                .iter()
                .map(|failure| failure.category)
                .collect::<Vec<_>>(),
            vec![EnvironmentFailureCategory::ProbeFailed]
        );
        assert!(
            report
                .stdout
                .run_metadata
                .environment_preflight_process_started
        );
        assert!(!report.stdout.target_launch_attempted);
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out before command start")));
        assert!(!marker.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn target_setup_timeout_is_generic_and_does_not_start_target() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let marker = temp.path().join("must-not-run");
        let agent = temp.path().join("fake-agent.sh");
        fs::write(&agent, format!("#!/bin/sh\ntouch '{}'\n", marker.display()))?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "do not start\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            agent,
            temp.path(),
            &prompt,
            incoming.join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::ZERO,
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly);

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert!(report.timed_out);
        assert_eq!(report.exit_code, None);
        assert!(!report.environment_blocked());
        assert!(report.environment_failures().is_empty());
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out before command start")));
        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn pre_cancelled_external_agent_is_generic() {
        let spec = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "events",
            "report",
            Duration::from_secs(1),
        );
        let cancellation = ProcessCancellation::new();
        cancellation.cancel();

        let report = run_external_agent_nonpublishable_simulation_cancellable(&spec, &cancellation);

        assert!(!report.timed_out);
        assert!(!report.environment_blocked());
        assert!(report.environment_failures().is_empty());
        assert!(!report.stdout.target_launch_attempted);
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("cancelled")));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_custom_runs_at_most_version_diagnostic_and_never_target() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let marker = temp.path().join("actual-target-ran");
        let agent = temp.path().join("custom-codex.sh");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'codex-cli 0.142.3\\n'; exit 0; fi\ntouch '{}'\n",
                marker.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "never run custom target\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            agent,
            temp.path(),
            &prompt,
            incoming.join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent(&spec);

        assert!(!marker.exists());
        assert!(!report.publishable);
        assert_eq!(report.program_trust, ExternalProgramTrust::ExplicitCustom);
        assert_eq!(report.codex_permissions, None);
        if report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("strict-offline version diagnostic"))
        {
            assert_eq!(report.process_tree, None);
            assert_eq!(report.side_effects, None);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_external_agent_drains_large_stdout_and_stderr_while_child_runs() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'O'
    i=$((i + 1))
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'E' >&2
    i=$((i + 1))
done
printf '\n{"type":"done"}\n'
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            output_dir.join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert_eq!(report.exit_code, Some(0));
        assert!(
            !report.timed_out,
            "large output child should exit before timeout: {report:?}"
        );
        assert_eq!(report.error, None);
        assert!(report.simulation_succeeded());
        assert!(!report.succeeded());
        assert!(report.stdout.truncated);
        assert!(report.stderr.truncated);
        assert!(report.stdout.text.len() >= OUTPUT_CHAR_LIMIT);
        assert!(report.stderr.text.len() >= OUTPUT_CHAR_LIMIT);
        let exact_tee = fs::read(&spec.json_log)?;
        assert!(exact_tee.len() > OUTPUT_CHAR_LIMIT);
        assert_eq!(report.stdout_bytes(), exact_tee);

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_stdout_accessor_preserves_non_utf8_bytes() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
cat >/dev/null
printf 'A\377B\n'
"#,
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "read-only prompt\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            output_dir.join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.error, None);
        assert_eq!(report.stdout_bytes(), b"A\xffB\n");
        assert!(report.stdout.text.contains('\u{fffd}'));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_external_agent_finalizes_descendant_holding_output_pipes() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
(
    trap '' TERM
    printf 'descendant started\n'
    printf 'descendant stderr started\n' >&2
    while :; do
        sleep 1
    done
) &
printf 'parent exiting\n'
exit 0
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;
        let output_dir = temp.path().join("incoming");
        fs::create_dir(&output_dir)?;
        fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            output_dir.join("events.jsonl"),
            output_dir.join("last-message.txt"),
            Duration::from_secs(1),
        );

        let started = Instant::now();
        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "process-tree finalization should return promptly instead of hanging: {report:?}"
        );
        assert!(
            !report.timed_out,
            "a normally exited parent should remain successful after descendant teardown: {report:?}"
        );
        assert_eq!(report.exit_code, Some(0));
        assert_eq!(report.error, None);
        assert!(report.simulation_succeeded());
        assert!(!report.succeeded());
        assert!(report.stdout.text.contains("parent exiting"));
        assert!(report.stdout.text.contains("descendant started"));
        assert!(report.stderr.text.contains("descendant stderr started"));

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_agent_cancellation_reaches_target_and_prevents_delayed_mutation() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::thread;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let started = temp.path().join("started");
        let delayed = temp.path().join("delayed");
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\ncat >/dev/null\ntouch '{}'\n(sleep 0.3; touch '{}') &\ntrap '' TERM\nwhile :; do sleep 1; done\n",
                started.display(),
                delayed.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run until cancelled\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            incoming.join("events.jsonl"),
            incoming.join("last-message.txt"),
            Duration::from_secs(5),
        );
        let cancellation = ProcessCancellation::new();
        let worker_cancellation = cancellation.clone();
        let worker = thread::spawn(move || {
            run_external_agent_nonpublishable_simulation_cancellable(&spec, &worker_cancellation)
        });

        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !started.exists() {
            assert!(
                Instant::now() < ready_deadline,
                "external target did not reach ready gate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        cancellation.cancel();
        let report = worker
            .join()
            .unwrap_or_else(|_| panic!("external cancellation worker panicked"));

        assert!(!report.timed_out);
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("cancelled")));
        assert!(!report.environment_blocked());
        assert!(report.environment_failures().is_empty());
        assert!(report.process_tree.is_some());
        thread::sleep(Duration::from_millis(400));
        assert!(!delayed.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_output_rebind_is_rejected_without_following_attacker_symlink() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, "untouched")?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            format!(
                r#"#!/bin/sh
set -eu
report=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    shift
    report=$1
  fi
  shift
done
printf '{{"ok":true}}\n' > "$report"
mv "$report" "$report.moved"
ln -s '{}' "$report"
"#,
                sentinel.display()
            ),
        )?;
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "test output identity\n")?;
        let incoming = temp.path().join("incoming");
        fs::create_dir(&incoming)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            incoming.join("events.jsonl"),
            incoming.join("report.json"),
            Duration::from_secs(3),
        );

        let report = run_external_agent_nonpublishable_simulation(&spec);

        assert!(report.output_last_message().is_none());
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("reservation changed")));
        assert_eq!(fs::read(&sentinel)?, b"untouched");
        Ok(())
    }
