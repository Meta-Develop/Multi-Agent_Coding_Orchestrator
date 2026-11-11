//! Vibe integration tests. Fake executable and synthetic inputs only: no
//! installed Vibe, no network, no real credential files are ever opened.
use super::*;

#[cfg(target_os = "linux")]
mod automatic_journal {
    use super::*;
    use clap::Parser;

    fn fixture() -> Result<(
        tempfile::TempDir,
        ExternalAgentCommand,
        ProtectedWorktreeControls,
        ExternalOutputStaging,
        Option<SideEffectConfinementProfile>,
        BoundWorkerJournalAppend,
    )> {
        let (temp, mut spec, controls) = worker_journal_append_binding_tests::fixture();
        spec = spec
            .with_runtime_adapter(
                RuntimeId::Vibe,
                RuntimeAdapterConfig::defaults(RuntimeId::Vibe),
            )
            .with_model_selection(Some("mistral-small-latest".into()), None)
            .with_writable_runtime_selection("worker", RuntimeId::Vibe, true)?
            .with_worktree_writable_confinement(WorktreeWritableAdmission {
                version: WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION,
                assignment_id: "worker".into(),
                attempt: 1,
                target: WritableLaunchTarget::ManagedChildWorktree,
                worktree: ManagedWorktreeAdmission {
                    kind: ManagedWorktreeAdmissionKind::ManagedDisposable,
                    worktree_id: "worker".into(),
                },
                claims: HeldPathClaimsAdmission {
                    state: HeldPathClaimsAdmissionState::Held,
                    token: 41,
                    paths: vec![PathBuf::from("source.txt")],
                },
                native_sandbox: NativeSandboxAdmission {
                    runtime: RuntimeId::Vibe,
                    workspace_access: WorkspaceAccess::ReadWrite,
                    side_effect_confinement: SideEffectConfinement::Verified,
                },
            });
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            "run",
            "worker",
            1,
            &spec.program,
            spec.model.as_deref(),
            "vibe-worker-duty",
        )?;
        spec = spec
            .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant);
        let repo = git2::Repository::init(&spec.cwd)?;
        fs::write(spec.cwd.join("source.txt"), "original\n")?;
        let mut index = repo.index()?;
        index.add_path(Path::new("source.txt"))?;
        index.write()?;
        let oid = index.write_tree()?;
        let tree = repo.find_tree(oid)?;
        let signature = git2::Signature::now("Fixture", "fixture@example.invalid")?;
        repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])?;
        fs::write(&spec.prompt, b"synthetic Worker prompt")?;
        let mut staging = ExternalOutputStaging::create_under(temp.path(), &spec.cwd)?;
        staging.stage_vibe_launch(&spec)?;
        let mut profile = worker_journal_append_binding_tests::profile(&spec);
        let mut prompt = fs::read(&spec.prompt)?;
        let mut argv = runtime_adapter_argv(&spec)?;
        let binding = bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::ExplicitCustom,
            &mut prompt,
            &mut profile,
            &mut argv,
        )?
        .context("expected Vibe journal binding")?;
        let prompt = String::from_utf8(prompt)?;
        assert!(prompt.contains("Parent-bound automatic Vibe Worker journal:"));
        assert!(!prompt.contains("Native apply_patch/Edit"));
        assert!(!prompt.contains("--observe-changes"));
        Ok((temp, spec, controls, staging, profile, binding))
    }

    #[test]
    fn vibe_production_journal_shell_pins_config_argv_and_readonly_controls() -> Result<()> {
        let (_temp, spec, controls, mut staging, mut profile, binding) = fixture()?;
        // Match production order: effective prompt delivery precedes shim binding.
        let mut target = spec.clone();
        target.prompt = staging.stage_worker_effective_prompt(&spec.cwd, b"effective prompt")?;
        let original_profile = profile.clone();
        let mut argv = runtime_adapter_argv(&target)?;
        let mut expected_argv = argv.clone();
        expected_argv.drain(12..16);
        vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &target,
            Some(&binding),
            &mut argv,
            &mut profile,
        )?;
        let staged = staging.vibe.as_ref().unwrap();
        vibe::verify_journal_shell(staged)?;
        let shell = staged.journal_shell.as_ref().unwrap();
        let config = fs::read_to_string(staged.config.path())?;
        let base = crate::runtime_adapter::vibe::config_document(&staged.evidence.model)?;
        let encoded = config
            .strip_prefix(&base)
            .unwrap()
            .strip_prefix("\n[tools.bash]\nshell = ")
            .unwrap()
            .trim_end();
        assert_eq!(
            serde_json::from_str::<String>(encoded)?,
            shell.path.to_str().unwrap()
        );
        let source = fs::read_to_string(&shell.path)?;
        let prefix = binding.command_prefix()?;
        let mut expected = prefix.clone();
        expected.extend([
            "--cwd".into(),
            spec.cwd.to_str().unwrap().into(),
            "--auto-timestamps".into(),
            "--".into(),
            "/bin/bash".into(),
            "-c".into(),
        ]);
        assert!(source.contains(&format!(
            "exec {} \"$2\"\n",
            expected
                .iter()
                .map(|value| vibe::shell_quote(value))
                .collect::<Vec<_>>()
                .join(" "),
        )));
        assert!(!source.contains("SHELL"));
        assert_eq!(binding.helper_path, env::current_exe()?);
        assert_eq!(
            prefix[4],
            controls.exact_writable_artifact_files[0]
                .path
                .to_str()
                .unwrap()
        );
        assert_eq!(
            prefix[6],
            controls.exact_writable_artifact_files[0]
                .identity
                .device
                .to_string()
        );
        assert_eq!(
            prefix[8],
            controls.exact_writable_artifact_files[0]
                .identity
                .inode
                .to_string()
        );
        assert_eq!(argv, expected_argv);
        let tools: Vec<_> = argv
            .windows(2)
            .filter(|pair| pair[0] == "--enabled-tools")
            .map(|pair| pair[1].to_str().unwrap())
            .collect();
        assert_eq!(tools, ["bash", "read_file"]);
        let Some(SideEffectConfinementProfile::ExternalCodex(original)) = original_profile else {
            panic!("ExternalCodex expected");
        };
        assert_eq!(
            profile,
            Some(SideEffectConfinementProfile::ExternalCodex(
                original
                    .with_visible_read_only_file(&binding.helper_path)
                    .with_visible_read_only_file(staged.config.path())
                    .with_visible_read_only_file(&shell.path),
            ))
        );
        assert_eq!(
            sha256_hex(&fs::read(staged.config.path())?),
            staged.evidence.config_sha256
        );
        assert!(staged.evidence.matches(&spec));
        staging.vibe.take().unwrap().cleanup()?;
        Ok(())
    }

    /// In lib tests the held running image is the test harness, not the CLI.
    /// Capture only the shim's exec argv, then invoke the real CLI/helper with
    /// those exact arguments in-process. No caller-selected helper is installed.
    fn capture_shim_argv(
        shell: &Path,
        capture: &Path,
        flag: &str,
        script: &str,
    ) -> Result<std::process::Output> {
        Ok(std::process::Command::new(shell)
            .args([flag, script])
            .env_clear()
            .env("VIBE_TEST_ARGV", capture)
            .env(
                "BASH_FUNC_exec%%",
                "() { printf '%s\\0' \"$@\" >> \"$VIBE_TEST_ARGV\";\n}",
            )
            .output()?)
    }

    fn captured_args(capture: &Path) -> Result<Vec<String>> {
        fs::read(capture)?
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| Ok(String::from_utf8(part.to_vec())?))
            .collect()
    }

    #[test]
    fn vibe_trusted_project_config_cannot_override_managed_shell() -> Result<()> {
        // Vibe's --trust enables the higher-priority project layer. Both the
        // cwd and ancestor discovery locations must fail before shim release.
        for ancestor in [false, true] {
            let (temp, spec, controls, mut staging, mut profile, binding) = fixture()?;
            let directory = if ancestor { temp.path() } else { &spec.cwd };
            let project = directory.join(".vibe/config.toml");
            fs::create_dir_all(project.parent().unwrap())?;
            fs::write(&project, "[tools.bash]\nshell = \"/bin/bash\"\n")?;
            let staged = staging.vibe.as_mut().unwrap();
            let config = fs::read(staged.config.path())?;
            let mut argv = runtime_adapter_argv(&spec)?;
            assert!(argv.iter().any(|argument| argument == "--trust"));
            let original_argv = argv.clone();
            let original_profile = profile.clone();
            let error =
                vibe::prepare_journal_shell(staged, &spec, Some(&binding), &mut argv, &mut profile)
                    .unwrap_err();
            let diagnostic = format!("{error:#}");
            assert!(diagnostic.contains("trusted project TOML can override the managed shell"));
            assert!(diagnostic.contains(project.to_str().unwrap()));
            assert!(staged.journal_shell.is_none());
            assert_eq!(fs::read(staged.config.path())?, config);
            assert_eq!(argv, original_argv);
            assert_eq!(profile, original_profile);
            assert!(fs::read(&controls.exact_writable_artifact_files[0].path)?.is_empty());

            // Also check the final pre-release gate, after successful staging.
            fs::remove_file(&project)?;
            vibe::prepare_journal_shell(staged, &spec, Some(&binding), &mut argv, &mut profile)?;
            vibe::verify_journal_shell(staged)?;
            fs::write(&project, "[tools.bash]\nshell = \"/bin/bash\"\n")?;
            assert!(vibe::verify_journal_shell(staged).is_err());
        }
        Ok(())
    }

    #[test]
    fn vibe_project_agent_profile_without_config_cannot_override_managed_shell() -> Result<()> {
        let (_temp, spec, controls, mut staging, mut profile, binding) = fixture()?;
        let agents = spec.cwd.join(".vibe/agents");
        let project = agents.join("auto-approve.toml");
        let override_profile = "[tools.bash]\nshell = \"/bin/bash\"\n";
        fs::create_dir_all(&agents)?;
        fs::write(&project, override_profile)?;
        assert!(!spec.cwd.join(".vibe/config.toml").exists());
        let staged = staging.vibe.as_mut().unwrap();
        let config = fs::read(staged.config.path())?;
        let mut argv = runtime_adapter_argv(&spec)?;
        assert!(argv
            .windows(2)
            .any(|pair| pair[0] == "--agent" && pair[1] == "auto-approve"));
        let original_argv = argv.clone();
        let original_profile = profile.clone();
        let error =
            vibe::prepare_journal_shell(staged, &spec, Some(&binding), &mut argv, &mut profile)
                .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("project agent profiles can override the managed shell"));
        assert!(diagnostic.contains(agents.to_str().unwrap()));
        assert!(staged.journal_shell.is_none());
        assert_eq!(fs::read(staged.config.path())?, config);
        assert_eq!(argv, original_argv);
        assert_eq!(profile, original_profile);
        assert!(fs::read(&controls.exact_writable_artifact_files[0].path)?.is_empty());

        // The same directory must also be refused if it appears after staging.
        fs::remove_file(&project)?;
        fs::remove_dir(&agents)?;
        vibe::prepare_journal_shell(staged, &spec, Some(&binding), &mut argv, &mut profile)?;
        vibe::verify_journal_shell(staged)?;
        fs::create_dir(&agents)?;
        fs::write(&project, override_profile)?;
        assert!(!spec.cwd.join(".vibe/config.toml").exists());
        let error = vibe::verify_journal_shell(staged).unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("project agent profiles can override the managed shell"));
        assert!(diagnostic.contains(agents.to_str().unwrap()));
        Ok(())
    }

    #[test]
    fn vibe_fresh_journal_relaunch_observes_retained_edits_once() -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let (temp, mut spec, _controls, mut prior_staging, mut profile, prior_binding) = fixture()?;
        let mut argv = runtime_adapter_argv(&spec)?;
        vibe::prepare_journal_shell(
            prior_staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&prior_binding),
            &mut argv,
            &mut profile,
        )?;
        let prior_shell = &prior_staging
            .vibe
            .as_ref()
            .unwrap()
            .journal_shell
            .as_ref()
            .unwrap()
            .path;
        let capture = temp.path().join("prior-argv");
        assert!(capture_shim_argv(
            prior_shell,
            &capture,
            "-c",
            "printf 'retained\\n' >> source.txt",
        )?
        .status
        .success());
        crate::cli::Cli::try_parse_from(captured_args(&capture)?)?.run()?;
        let retained = fs::read(spec.cwd.join("source.txt"))?;
        assert_eq!(retained, b"original\nretained\n");
        let prior_journal = fs::read(&prior_binding.journal.path)?;
        let prior_records = crate::supervise::parse_worker_execution_journal(
            &prior_journal,
            &prior_binding.journal.path,
        )?;
        let prior_observation =
            serde_json::to_value(prior_records.last().unwrap().observation.as_ref().unwrap())?;
        let head = git2::Repository::open(&spec.cwd)?.head()?.target().unwrap();
        let WorktreeWritableConfinementAuthority::Direct(mut admission) = spec
            .worktree_writable_confinement
            .as_ref()
            .unwrap()
            .authority
            .clone()
        else {
            panic!("direct Worker admission expected");
        };
        let claims = admission.claims.clone();
        admission.attempt = 2;

        // A real fresh journal in a new attempt directory; keep the old inode
        // and bytes intact, with the same cwd, HEAD and held claim authority.
        let incoming = temp.path().join("relaunch");
        fs::create_dir_all(incoming.join("worker-journals"))?;
        let journal = incoming.join("worker-journals/worker.jsonl");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&journal)?;
        let identity = exact_writable_artifact_identity(&file.metadata()?)?;
        let controls = ProtectedWorktreeControls {
            exact_writable_artifact_files: vec![ExactWritableArtifactFile {
                worker_id: "worker".into(),
                path: journal.clone(),
                held_file: std::sync::Arc::new(file),
                identity,
            }],
            writable_artifact_root: Some(incoming.clone()),
            ..ProtectedWorktreeControls::default()
        };
        spec.worker_journal_artifacts.clear();
        spec = spec
            .with_worker_journal_artifact("worker", &incoming, &journal)
            .with_worktree_writable_confinement(admission);
        let grant = crate::mutation_taxonomy::admit_assignment_child_process_intent(
            "run",
            "worker",
            2,
            &spec.program,
            spec.model.as_deref(),
            "vibe-worker-duty",
        )?;
        spec = spec
            .with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant);
        let mut staging = ExternalOutputStaging::create_under(temp.path(), &spec.cwd)?;
        staging.stage_vibe_launch(&spec)?;
        let mut profile = worker_journal_append_binding_tests::profile(&spec);
        let mut prompt = fs::read(&spec.prompt)?;
        let mut argv = runtime_adapter_argv(&spec)?;
        let binding = bind_worker_journal_append_operation(
            &spec,
            &controls,
            ExternalExecutionRuntime::Verified,
            ExternalProgramTrust::ExplicitCustom,
            &mut prompt,
            &mut profile,
            &mut argv,
        )?
        .context("expected fresh Vibe journal binding")?;
        assert_ne!(binding.journal.path, prior_binding.journal.path);
        assert!(fs::read(&journal)?.is_empty());
        vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )?;
        vibe::verify_journal_shell(staging.vibe.as_ref().unwrap())?;
        assert_eq!(fs::read(spec.cwd.join("source.txt"))?, retained);
        let initial =
            crate::supervise::parse_worker_execution_journal(&fs::read(&journal)?, &journal)?;
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].command, ["true"]);
        assert_eq!(initial[0].changed_paths, [PathBuf::from("source.txt")]);
        let observation = serde_json::to_value(initial[0].observation.as_ref().unwrap())?;
        assert_eq!(observation["phase"], "native_edit");
        assert_eq!(observation["before"], serde_json::json!({}));
        assert_eq!(observation["after"].as_object().unwrap().len(), 1);
        assert_eq!(
            observation["after"]["source.txt"].as_str().unwrap().len(),
            64
        );
        assert_eq!(observation["after"], prior_observation["after"]);
        assert_eq!(
            observation["worktree_identity"],
            prior_observation["worktree_identity"]
        );
        assert_eq!(observation["head_oid"], head.to_string());
        assert_eq!(observation["worktree"], spec.cwd.to_str().unwrap());
        assert_eq!(observation["declared_paths"], serde_json::json!([]));
        assert!(observation.get("failure").is_none());

        let shell = &staging
            .vibe
            .as_ref()
            .unwrap()
            .journal_shell
            .as_ref()
            .unwrap()
            .path;
        // The first call can be read-only; no model-issued recovery is needed.
        let capture = temp.path().join("readonly-argv");
        let read_script = r#"test "$(/bin/cat source.txt)" = "$(printf 'original\nretained\n')""#;
        assert!(capture_shim_argv(shell, &capture, "-c", read_script)?
            .status
            .success());
        crate::cli::Cli::try_parse_from(captured_args(&capture)?)?.run()?;
        let readonly =
            crate::supervise::parse_worker_execution_journal(&fs::read(&journal)?, &journal)?;
        assert_eq!(readonly.len(), 3);
        for record in &readonly[1..] {
            assert_eq!(record.command, ["/bin/bash", "-c", read_script]);
            assert_eq!(record.cwd, spec.cwd);
            assert!(record.changed_paths.is_empty());
            let current = serde_json::to_value(record.observation.as_ref().unwrap())?;
            assert_eq!(current["before"], observation["after"]);
            assert_eq!(current["after"], observation["after"]);
        }
        let capture = temp.path().join("relaunch-argv");
        let script = "printf 'once\\n' >> source.txt";
        assert!(capture_shim_argv(shell, &capture, "-c", script)?
            .status
            .success());
        crate::cli::Cli::try_parse_from(captured_args(&capture)?)?.run()?;
        assert_eq!(
            fs::read(spec.cwd.join("source.txt"))?,
            b"original\nretained\nonce\n"
        );
        let bytes = fs::read(&journal)?;
        let records = crate::supervise::parse_worker_execution_journal(&bytes, &journal)?;
        assert_eq!(records.len(), 5);
        assert_eq!(records[..3], readonly);
        for (record, phase) in records[3..].iter().zip(["started", "completed"]) {
            assert_eq!(record.command, ["/bin/bash", "-c", script]);
            assert_eq!(record.cwd, spec.cwd);
            assert!(!record.start_timestamp.is_empty() && !record.end_timestamp.is_empty());
            let current = serde_json::to_value(record.observation.as_ref().unwrap())?;
            assert_eq!(current["phase"], phase);
            for key in [
                "worktree",
                "worktree_identity",
                "head_oid",
                "declared_paths",
            ] {
                assert_eq!(current[key], observation[key]);
            }
            assert_eq!(current["before"], observation["after"]);
            assert!(current.get("failure").is_none());
        }
        assert!(records[3].changed_paths.is_empty());
        assert_eq!(records[4].changed_paths, [PathBuf::from("source.txt")]);
        spec.verified_writable_capabilities(RuntimeId::Vibe)?;
        let WorktreeWritableConfinementAuthority::Direct(admission) = &spec
            .worktree_writable_confinement
            .as_ref()
            .unwrap()
            .authority
        else {
            panic!("direct Worker admission expected");
        };
        assert_eq!(admission.claims, claims);

        // A subsequent unobserved mutation is NOT silently absorbed by the shim.
        fs::write(spec.cwd.join("source.txt"), "unexpected mutation\n")?;
        let capture = temp.path().join("refused-argv");
        assert!(capture_shim_argv(
            shell,
            &capture,
            "-c",
            "printf 'must not execute\\n' >> source.txt",
        )?
        .status
        .success());
        let error = crate::cli::Cli::try_parse_from(captured_args(&capture)?)?
            .run()
            .unwrap_err();
        assert!(format!("{error:#}").contains("WorkerJournalObservationRequired"));
        assert_eq!(fs::read(&journal)?, bytes);
        assert_eq!(
            fs::read_to_string(spec.cwd.join("source.txt"))?,
            "unexpected mutation\n"
        );
        assert_eq!(fs::read(&prior_binding.journal.path)?, prior_journal);
        assert_eq!(
            git2::Repository::open(&spec.cwd)?.head()?.target(),
            Some(head)
        );
        Ok(())
    }

    #[test]
    fn vibe_journal_shell_refuses_login_dump_and_preserves_exact_script_once() -> Result<()> {
        let (temp, spec, controls, mut staging, mut profile, binding) = fixture()?;
        let mut argv = runtime_adapter_argv(&spec)?;
        vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )?;
        let shell = &staging
            .vibe
            .as_ref()
            .unwrap()
            .journal_shell
            .as_ref()
            .unwrap()
            .path;
        let capture = temp.path().join("captured-argv");
        let journal = &controls.exact_writable_artifact_files[0].path;
        let initial_journal = fs::read(journal)?;
        let marker = temp.path().join("login-must-not-run");
        let dump = format!(
            "touch {}; printf 'synthetic private environment dump'",
            vibe::shell_quote(marker.to_str().unwrap())
        );
        for flag in ["-lc", "-x", "--command"] {
            let refused = capture_shim_argv(shell, &capture, flag, &dump)?;
            assert_eq!(refused.status.code(), Some(64));
            assert!(refused.stdout.is_empty() && refused.stderr.is_empty());
            assert!(!marker.exists() && !capture.exists());
            assert_eq!(fs::read(journal)?, initial_journal);
        }

        let script = "value=\"single ' quote \\\\ and spaces\"\nprintf '%s\\n' \"$value\" >> source.txt\n/bin/bash -c 'printf \"nested\\n\"' >> source.txt\nprintf 'real stdout\\n'\nprintf 'real stderr\\n' >&2";
        let output = capture_shim_argv(shell, &capture, "-c", script)?;
        assert!(output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        let args = captured_args(&capture)?;
        let mut expected = binding.command_prefix()?;
        expected.extend([
            "--cwd".into(),
            spec.cwd.to_str().unwrap().into(),
            "--auto-timestamps".into(),
            "--".into(),
            "/bin/bash".into(),
            "-c".into(),
            script.into(),
        ]);
        assert_eq!(args, expected);
        assert_eq!(
            fs::read_to_string(spec.cwd.join("source.txt"))?,
            "original\n"
        );
        crate::cli::Cli::try_parse_from(args)?.run()?;
        let records =
            crate::supervise::parse_worker_execution_journal(&fs::read(journal)?, journal)?;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].command, ["true"]);
        for record in &records[1..] {
            assert_eq!(record.command, ["/bin/bash", "-c", script]);
            assert_eq!(record.cwd, spec.cwd);
            assert!(!record.start_timestamp.is_empty() && !record.end_timestamp.is_empty());
        }
        assert_eq!(records[2].changed_paths, [PathBuf::from("source.txt")]);
        assert_eq!(
            fs::read_to_string(spec.cwd.join("source.txt"))?,
            "original\nsingle ' quote \\ and spaces\nnested\n"
        );
        Ok(())
    }

    #[test]
    fn vibe_journal_shell_keeps_command_and_journal_failures_visible() -> Result<()> {
        let (temp, spec, controls, mut staging, mut profile, binding) = fixture()?;
        let mut argv = runtime_adapter_argv(&spec)?;
        vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )?;
        let shell = &staging
            .vibe
            .as_ref()
            .unwrap()
            .journal_shell
            .as_ref()
            .unwrap()
            .path;
        let output = std::process::Command::new(shell)
            .args(["-c", "exit 0"])
            .env_clear()
            .env(
                "BASH_FUNC_exec%%",
                "() { printf 'helper stdout\\n'; printf 'helper stderr\\n' >&2; return 37;\n}",
            )
            .output()?;
        assert_eq!(output.status.code(), Some(37));
        assert_eq!(output.stdout, b"helper stdout\n");
        assert_eq!(output.stderr, b"helper stderr\n");

        let capture = temp.path().join("failure-argv");
        let script = "printf 'mutation before failure\\n' >> source.txt; exit 23";
        assert!(capture_shim_argv(shell, &capture, "-c", script)?
            .status
            .success());
        let error = crate::cli::Cli::try_parse_from(captured_args(&capture)?)?
            .run()
            .unwrap_err();
        assert!(format!("{error:#}").contains("exit status: 23"));
        let journal = &controls.exact_writable_artifact_files[0].path;
        let records =
            crate::supervise::parse_worker_execution_journal(&fs::read(journal)?, journal)?;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].command, ["true"]);
        assert_eq!(records[2].command, ["/bin/bash", "-c", script]);
        assert_eq!(records[2].changed_paths, [PathBuf::from("source.txt")]);
        assert_eq!(
            fs::read_to_string(spec.cwd.join("source.txt"))?,
            "original\nmutation before failure\n"
        );
        // A wrong inode fails in the real appender before executing the script.
        let mut args = binding.command_prefix()?;
        args[8] = (binding.journal.identity.inode + 1).to_string();
        args.extend([
            "--cwd".into(),
            spec.cwd.to_str().unwrap().into(),
            "--auto-timestamps".into(),
            "--".into(),
            "/bin/bash".into(),
            "-c".into(),
            "printf 'must not execute' >> source.txt".into(),
        ]);
        let before = fs::read(journal)?;
        assert!(crate::cli::Cli::try_parse_from(args)?.run().is_err());
        assert_eq!(fs::read(journal)?, before);
        assert!(!fs::read_to_string(spec.cwd.join("source.txt"))?.contains("must not execute"));
        Ok(())
    }

    #[test]
    fn vibe_journal_shell_requires_binding_and_detects_control_changes() -> Result<()> {
        let (_temp, spec, _controls, mut staging, mut profile, mut binding) = fixture()?;
        let mut argv = runtime_adapter_argv(&spec)?;
        assert!(vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            None,
            &mut argv,
            &mut profile,
        )
        .is_err());
        let original = argv.clone();
        for shape in ["readonly", "primary", "auditor", "codex"] {
            let mut changed = spec.clone();
            match shape {
                "readonly" => changed.workspace_access = WorkspaceAccess::ReadOnly,
                "primary" => changed.writable_launch_target = WritableLaunchTarget::PrimaryWorktree,
                "auditor" => changed.agent_lifecycle.as_mut().unwrap().role = "auditor".into(),
                "codex" => changed.invocation = ExternalAgentInvocation::CodexSupervisor,
                _ => unreachable!(),
            }
            let before = profile.clone();
            vibe::prepare_journal_shell(
                staging.vibe.as_mut().unwrap(),
                &changed,
                None,
                &mut argv,
                &mut profile,
            )?;
            assert_eq!(argv, original);
            assert_eq!(profile, before);
            assert!(staging.vibe.as_ref().unwrap().journal_shell.is_none());
        }
        let digest = binding.helper_sha256.clone();
        binding.helper_sha256 = "0".repeat(64);
        assert!(vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )
        .is_err());
        binding.helper_sha256 = digest;
        let original_profile = profile.clone();
        profile = None;
        assert!(vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )
        .is_err());
        profile = original_profile;
        argv.push("--extra-tool".into());
        assert!(vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )
        .is_err());
        argv = original;
        // Projection uses the production builder even if the incoming profile
        // does not already contain the exact bound helper.
        profile = worker_journal_append_binding_tests::profile(&spec);
        vibe::prepare_journal_shell(
            staging.vibe.as_mut().unwrap(),
            &spec,
            Some(&binding),
            &mut argv,
            &mut profile,
        )?;
        let staged = staging.vibe.as_ref().unwrap();
        let Some(SideEffectConfinementProfile::ExternalCodex(mounted)) = &profile else {
            panic!("ExternalCodex expected");
        };
        for control in [
            &binding.helper_path,
            staged.config.path(),
            &staged.journal_shell.as_ref().unwrap().path,
        ] {
            assert!(mounted
                .visible_read_only_files()
                .contains(&control.to_path_buf()));
        }
        let config = fs::read(staged.config.path())?;
        fs::write(staged.config.path(), "tampered")?;
        assert!(vibe::verify_journal_shell(staged).is_err());
        fs::write(staged.config.path(), config)?;
        vibe::verify_journal_shell(staged)?;
        let shell = &staged.journal_shell.as_ref().unwrap().path;
        fs::write(shell, "#!/bin/bash\nexit 0\n")?;
        assert!(vibe::verify_journal_shell(staged).is_err());
        Ok(())
    }
}

fn vibe_command() -> ExternalAgentCommand {
    let mut command = ExternalAgentCommand::codex(
        "/opt/vibe-venv/bin/vibe",
        "/workspace",
        "/private/prompt.md",
        "/private/events.jsonl",
        "/private/last-message.raw",
        Duration::from_secs(30),
    );
    command.invocation = ExternalAgentInvocation::Vibe;
    command.model = Some("mistral-small-latest".to_string());
    command
}

#[test]
fn vibe_dotenv_parser_accepts_bare_and_quoted_keys() {
    let bare =
        vibe::parse_dotenv_mistral_key(b"# comment\nOTHER=x\nMISTRAL_API_KEY=abc123def456ghi789\n")
            .unwrap();
    assert_eq!(bare, "abc123def456ghi789");
    let quoted =
        vibe::parse_dotenv_mistral_key(b"MISTRAL_API_KEY=\"abc123def456ghi789\"\n").unwrap();
    assert_eq!(quoted, "abc123def456ghi789");
    let single = vibe::parse_dotenv_mistral_key(b"MISTRAL_API_KEY='abc123def456ghi789'\n").unwrap();
    assert_eq!(single, "abc123def456ghi789");
}

#[test]
fn vibe_dotenv_parser_refuses_missing_duplicate_malformed_and_nul() {
    assert!(vibe::parse_dotenv_mistral_key(b"OTHER=1\n").is_err());
    assert!(vibe::parse_dotenv_mistral_key(b"MISTRAL_API_KEY=a\nMISTRAL_API_KEY=b\n").is_err());
    assert!(vibe::parse_dotenv_mistral_key(b"not-an-assignment\n").is_err());
    assert!(vibe::parse_dotenv_mistral_key(b"MISTRAL_API_KEY=short\n").is_err());
    assert!(vibe::parse_dotenv_mistral_key(b"MISTRAL_API_KEY=with\0nul\n").is_err());
    assert!(vibe::parse_dotenv_mistral_key(b"\xff\xfe invalid utf8\n").is_err());
}

#[test]
fn vibe_privacy_environment_pins_model_and_disables_extensions() {
    let pins = vibe::privacy_environment("deepseek-v4-1-flash-1017");
    let map: BTreeMap<String, String> = pins.into_iter().collect();
    for key in [
        "VIBE_ENABLE_SUBAGENTS",
        "VIBE_ENABLE_MCP",
        "VIBE_ENABLE_CONNECTORS",
        "VIBE_ENABLE_TELEMETRY",
        "VIBE_ENABLE_OTEL",
        "VIBE_ENABLE_UPDATE_CHECKS",
        "VIBE_ENABLE_AUTO_UPDATE",
        "VIBE_ENABLE_BACKGROUND_PROCESSES",
        "VIBE_SESSION_LOGGING__GENERATE_TITLES",
    ] {
        assert_eq!(map.get(key).map(String::as_str), Some("false"), "{key}");
    }
    assert_eq!(
        map.get("VIBE_TEST_DISABLE_KEYRING").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        map.get("VIBE_ACTIVE_MODEL").map(String::as_str),
        Some("deepseek-v4-1-flash-1017")
    );
    assert_eq!(
        map.get("VIBE_ALLOWED_MODELS").map(String::as_str),
        Some("[\"deepseek-v4-1-flash-1017\"]")
    );
    // The models map is pinned so a project config alias cannot redefine the
    // requested model or its provider.
    let models: serde_json::Value = serde_json::from_str(map.get("VIBE_MODELS").unwrap()).unwrap();
    assert_eq!(
        models["deepseek-v4-1-flash-1017"]["name"],
        "deepseek-v4-1-flash-1017"
    );
    assert_eq!(
        models["deepseek-v4-1-flash-1017"]["alias"],
        "deepseek-v4-1-flash-1017"
    );
    assert_eq!(models["deepseek-v4-1-flash-1017"]["provider"], "mistral");
    let utility: serde_json::Value =
        serde_json::from_str(map.get("VIBE_UTILITY_MODELS").unwrap()).unwrap();
    assert_eq!(utility["title"], "deepseek-v4-1-flash-1017");
    assert_eq!(utility["smart_approve"], "deepseek-v4-1-flash-1017");

    // Two requested models pin different active/allowed/models maps.
    let other = vibe::privacy_environment("zai-glm-5-3");
    let other: BTreeMap<String, String> = other.into_iter().collect();
    assert_eq!(
        other.get("VIBE_ACTIVE_MODEL").map(String::as_str),
        Some("zai-glm-5-3")
    );
    assert_eq!(
        other.get("VIBE_ALLOWED_MODELS").map(String::as_str),
        Some("[\"zai-glm-5-3\"]")
    );
    let other_models: serde_json::Value =
        serde_json::from_str(other.get("VIBE_MODELS").unwrap()).unwrap();
    assert_eq!(other_models["zai-glm-5-3"]["provider"], "mistral");
    assert!(other_models.get("deepseek-v4-1-flash-1017").is_none());
}

#[test]
fn vibe_export_dir_is_staged_output_sibling() {
    let staged = Path::new("/private/staging/last-message.raw");
    let export = vibe::export_dir_for(staged);
    assert_eq!(
        export.file_name(),
        Some(OsStr::new("last-message.raw.vibe-export"))
    );
    assert_eq!(export.parent(), staged.parent());
    let name = vibe::export_dir_name(staged).unwrap();
    assert_eq!(name, OsString::from("last-message.raw.vibe-export"));
}

#[test]
fn vibe_adapter_argv_carries_export_dir_and_never_the_credential() {
    let mut spec = vibe_command();
    spec.runtime_adapter = Some(RuntimeAdapterConfig::defaults(RuntimeId::Vibe));
    spec.output_last_message = PathBuf::from("/private/staging/last-message.raw");
    let argv = runtime_adapter_argv(&spec).unwrap();
    let rendered = argv
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    for argument in &rendered {
        assert!(!argument.contains("MISTRAL_API_KEY"), "{argument}");
        assert!(
            !argument.contains("MACO_VIBE_CREDENTIAL_FILE"),
            "{argument}"
        );
    }
    assert!(
        rendered
            .iter()
            .any(|argument| argument.ends_with("last-message.raw.vibe-export")),
        "argv must reference the private export directory: {rendered:?}"
    );
}

#[test]
fn vibe_credential_redacted_from_raw_json_and_nested_evidence() {
    let synthetic = "abc123def456ghi789";
    let mut environment = BTreeMap::new();
    environment.insert("MISTRAL_API_KEY".to_string(), synthetic.to_string());
    let redactor = CredentialRedactor::from_runtime(&environment, None, None).unwrap();
    assert_eq!(
        redactor.redact_string(&format!("key {synthetic} end")),
        "key [REDACTED] end"
    );
    // JSON-quoted and wire-escaped forms are redacted; the surrounding JSON
    // quote characters themselves are preserved.
    let quoted = format!("\"{synthetic}\"");
    assert_eq!(
        redactor.redact_string(&format!("echo {quoted}")),
        "echo \"[REDACTED]\""
    );
    let nested = serde_json::to_string(synthetic).unwrap();
    assert_eq!(
        redactor.redact_string(&format!("nested {nested}")),
        "nested \"[REDACTED]\""
    );
    // The synthetic key is absent from every redacted form.
    for redacted in [
        redactor.redact_string(&format!("key {synthetic} end")),
        redactor.redact_string(&format!("echo {quoted}")),
        redactor.redact_string(&format!("nested {nested}")),
    ] {
        assert!(!redacted.contains(synthetic), "{redacted}");
    }
}

#[test]
fn vibe_journal_capture_with_runtime_credential_is_withheld() {
    let synthetic = "vibe-synthetic-journal-credential";
    let environment = BTreeMap::from([("MISTRAL_API_KEY".to_string(), synthetic.to_string())]);
    let redactor = CredentialRedactor::from_runtime(&environment, None, None).unwrap();
    let mut captures = vec![WorkerJournalArtifactCapture {
        worker_id: "vibe-worker".to_string(),
        path: PathBuf::from("/private/worker.jsonl"),
        command_binding: None,
        status: WorkerJournalArtifactCaptureStatus::Loaded(
            format!("{{\"command\":[\"curl\",\"Bearer {synthetic}\"]}}\n").into_bytes(),
        ),
    }];
    vibe::withhold_credential_journals(&mut captures, &redactor);
    for capture in &captures {
        let WorkerJournalArtifactCaptureStatus::Invalid(message) = &capture.status else {
            panic!("credential-bearing Vibe journal must be withheld");
        };
        assert!(message.contains("contained the runtime credential"));
        assert!(message.contains("withheld"));
        assert!(!message.contains(synthetic));
    }
    assert!(!format!("{captures:?}").contains(synthetic));
}

#[test]
fn vibe_journal_capture_without_runtime_credential_stays_byte_identical() {
    let environment = BTreeMap::from([(
        "MISTRAL_API_KEY".to_string(),
        "vibe-synthetic-journal-credential".to_string(),
    )]);
    let redactor = CredentialRedactor::from_runtime(&environment, None, None).unwrap();
    let bytes = b"{\"command\":[\"true\"],\"stdout\":\"unchanged\"}\n".to_vec();
    let mut captures = vec![WorkerJournalArtifactCapture {
        worker_id: "vibe-worker".to_string(),
        path: PathBuf::from("/private/worker.jsonl"),
        command_binding: None,
        status: WorkerJournalArtifactCaptureStatus::Loaded(bytes.clone()),
    }];
    vibe::withhold_credential_journals(&mut captures, &redactor);
    assert_eq!(
        captures[0].status,
        WorkerJournalArtifactCaptureStatus::Loaded(bytes)
    );
}

#[test]
fn vibe_writable_selection_refuses_non_worker_roles_and_phases() {
    let base = || {
        let mut command = vibe_command();
        command.agent_lifecycle = Some(ExternalAgentLifecycleIdentity {
            registry_repo: PathBuf::from("/registry"),
            role: "worker".to_string(),
            run_id: "run".to_string(),
            task_id: "worker".to_string(),
            parent: Some("orchestrator".to_string()),
        });
        command
    };

    // Without the explicit non-delegating terminal Worker selection.
    let error = base()
        .with_writable_runtime_selection("worker", RuntimeId::Vibe, false)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(WRITABLE_VIBE_TERMINAL_WORKER_REQUIRED),
        "{error:#}"
    );

    // Non-Worker lifecycle role.
    let mut auditor = base();
    auditor.agent_lifecycle.as_mut().unwrap().role = "auditor".to_string();
    let error = auditor
        .with_writable_runtime_selection("worker", RuntimeId::Vibe, true)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(WRITABLE_VIBE_TERMINAL_WORKER_REQUIRED),
        "{error:#}"
    );

    // ParentAuditor process kind instead of AssignmentChild.
    let mut parent_auditor = base();
    parent_auditor.assignment_process_launch_kind =
        Some(AssignmentProcessLaunchKind::ParentAuditor);
    let error = parent_auditor
        .with_writable_runtime_selection("worker", RuntimeId::Vibe, true)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(WRITABLE_VIBE_TERMINAL_WORKER_REQUIRED),
        "{error:#}"
    );

    // Missing lifecycle binding entirely.
    let error = vibe_command()
        .with_writable_runtime_selection("worker", RuntimeId::Vibe, true)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(WRITABLE_VIBE_TERMINAL_WORKER_REQUIRED),
        "{error:#}"
    );
}

#[test]
fn vibe_worker_selection_precedes_the_process_grant_without_granting_launch() -> Result<()> {
    let mut command = vibe_command().with_runtime_adapter(
        RuntimeId::Vibe,
        RuntimeAdapterConfig::defaults(RuntimeId::Vibe),
    );
    command.agent_lifecycle = Some(ExternalAgentLifecycleIdentity {
        registry_repo: PathBuf::from("/registry"),
        role: "worker".into(),
        run_id: "run".into(),
        task_id: "worker".into(),
        parent: Some("supervisor".into()),
    });
    assert!(command.assignment_process_launch_kind.is_none());
    let command = command.with_writable_runtime_selection("worker", RuntimeId::Vibe, true)?;
    command.selected_writable_capabilities(RuntimeId::Vibe, Some("worker"))?;
    assert!(command
        .verified_writable_capabilities(RuntimeId::Vibe)
        .is_err());
    assert!(!assignment_process_launch_kind_allowed_for_invocation(
        AssignmentProcessLaunchKind::ParentAuditor,
        &command,
    ));
    Ok(())
}

#[test]
fn vibe_read_only_profile_and_missing_selection_are_refused() {
    let mut read_only = ExternalAgentCommand::codex_read_only_consultant(
        "/opt/vibe-venv/bin/vibe",
        "/workspace",
        "/private/prompt.md",
        "/private/events.jsonl",
        "/private/last-message.raw",
        Duration::from_secs(30),
    );
    read_only.invocation = ExternalAgentInvocation::Vibe;
    let error = ExternalProviderProfile::for_command(&read_only, Default::default())
        .err()
        .expect("read-only Vibe refused");
    assert!(
        error
            .to_string()
            .contains("admitted only for the writable execution-phase"),
        "{error:#}"
    );

    let mut writable = vibe_command();
    writable.workspace_access = WorkspaceAccess::ReadWrite;
    let error = ExternalProviderProfile::for_command(&writable, Default::default())
        .err()
        .expect("unbound Vibe refused");
    assert!(
        error
            .to_string()
            .contains("non-delegating terminal Worker evidence"),
        "{error:#}"
    );
}

fn vibe_temp_root(tag: &str) -> (PathBuf, SecureOutputRoot) {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("maco-vibe-test-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("test export root");
    let root = SecureOutputRoot::open_private(&dir).expect("held export root");
    (dir, root)
}

fn write_vibe_export(root: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(root.join("export.json"), bytes).expect("write export.json");
    fs::set_permissions(root.join("export.json"), fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(target_os = "linux")]
fn vibe_output_staging_paths(staging: &ExternalOutputStaging) -> Vec<PathBuf> {
    let vibe = staging.vibe.as_ref().unwrap();
    let mut paths = vec![
        staging.root_path.clone(),
        staging.path().unwrap().to_path_buf(),
        vibe.home.path().to_path_buf(),
        vibe.config.path().to_path_buf(),
        vibe.export.path().to_path_buf(),
    ];
    paths.extend(
        vibe.shell_directories
            .iter()
            .map(|directory| directory.path().to_path_buf()),
    );
    paths
}

#[cfg(target_os = "linux")]
#[test]
fn vibe_output_staging_cleanup_after_verified_quiescence_removes_all_paths() {
    let (dir, _root) = vibe_temp_root("cleanup-verified");
    let workspace = tempfile::tempdir().unwrap();
    let mut staging = ExternalOutputStaging::create_under(&dir, workspace.path()).unwrap();
    staging.stage_vibe_launch(&vibe_command()).unwrap();
    let paths = vibe_output_staging_paths(&staging);
    let vibe = staging.vibe.as_ref().unwrap();
    write_vibe_export(vibe.export.path(), VIBE_VALID_EXPORT.as_bytes());
    for directory in &vibe.shell_directories {
        fs::write(directory.path().join("child-state"), b"fake child state").unwrap();
    }
    staging.preserve_unquiescent = true;
    staging.record_target_quiescence(true);
    assert!(!staging.preserve_unquiescent);
    staging.cleanup().unwrap();
    assert!(staging.cleanup_completed);
    drop(staging);
    for path in paths {
        assert!(
            !path.exists(),
            "staged Vibe path remains: {}",
            path.display()
        );
    }
    fs::remove_dir(&dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn vibe_output_staging_unverified_quiescence_preserves_paths_through_drop() {
    let (dir, _root) = vibe_temp_root("cleanup-unverified");
    let workspace = tempfile::tempdir().unwrap();
    let mut staging = ExternalOutputStaging::create_under(&dir, workspace.path()).unwrap();
    staging.stage_vibe_launch(&vibe_command()).unwrap();
    let paths = vibe_output_staging_paths(&staging);
    staging.preserve_unquiescent = true;
    staging.record_target_quiescence(false);
    assert!(staging.preserve_unquiescent);
    let error = staging
        .cleanup()
        .err()
        .expect("unverified target must retain staging");
    assert!(error.to_string().contains("quiescence"));
    drop(staging);
    for path in paths {
        assert!(
            path.exists(),
            "staged Vibe path was removed: {}",
            path.display()
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

const VIBE_VALID_EXPORT: &str = r#"{
  "outcome": "completed",
  "stop_reason": null,
  "error": null,
  "session_id": "s",
  "usage": {"input_tokens": 11, "output_tokens": 7, "cached_input_tokens": 3, "total_tokens": 18},
  "cost_usd": 0.0,
  "steps": 1,
  "schema_version": 1,
  "vibe_version": "3.1.0",
  "started_at": "t0",
  "ended_at": "t1",
  "limits": {},
  "exit_code": 0
}"#;

#[test]
fn vibe_usage_capture_valid_missing_malformed_and_oversized_export() {
    let (dir, root) = vibe_temp_root("usage");
    // Missing export leaf.
    assert!(vibe::capture_usage(&root).is_err());

    // Valid export: token counts are captured; no cost is derivable.
    write_vibe_export(&dir, VIBE_VALID_EXPORT.as_bytes());
    let usage = vibe::capture_usage(&root).unwrap();
    assert_eq!(usage.input_tokens, 11);
    assert_eq!(usage.output_tokens, 7);
    assert_eq!(usage.cached_input_tokens, 3);
    assert_eq!(usage.total_tokens, 18);

    // Malformed export.
    write_vibe_export(&dir, b"not json at all");
    assert!(vibe::capture_usage(&root).is_err());

    // Oversized export.
    write_vibe_export(&dir, &vec![b'x'; 1024 * 1024 + 1]);
    assert!(vibe::capture_usage(&root).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vibe_replaced_export_leaf_fails_identity_while_reading() {
    let (dir, root) = vibe_temp_root("replaced");
    write_vibe_export(&dir, VIBE_VALID_EXPORT.as_bytes());
    let leaf = root
        .open_existing_leaf(OsStr::new("export.json"))
        .expect("held export leaf");
    // Replace the leaf after it was captured; the held identity must fail closed.
    fs::remove_file(dir.join("export.json")).unwrap();
    write_vibe_export(&dir, VIBE_VALID_EXPORT.as_bytes());
    assert!(leaf.read_bounded(1024 * 1024).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vibe_ndjson_report_capture_and_refusals() {
    let spec = vibe_command();
    // Unsuccessful target: usage of the stream is unavailable, not an error.
    match runtime_adapter_captured_output(&spec, b"anything", b"", false).unwrap() {
        RuntimeAdapterCapturedOutput::Unavailable => {}
        other => panic!("expected unavailable capture, got {other:?}"),
    }
    // Malformed NDJSON cannot silently succeed.
    assert!(runtime_adapter_captured_output(&spec, b"garbage not ndjson", b"", true).is_err());
    // A completed assistant entry yields its final text through the normal
    // staged report publication path.
    let ndjson = concat!(
        "{\"type\":\"message\",\"id\":\"e1\",\"turnId\":\"t1\",\"role\":\"user\",\"generationStatus\":\"completed\",\"content\":[{\"type\":\"text\",\"text\":\"do the work\"}]}\n",
        "{\"type\":\"message\",\"id\":\"e2\",\"turnId\":\"t1\",\"role\":\"assistant\",\"generationStatus\":\"completed\",\"content\":[{\"type\":\"text\",\"text\":\"vibe final answer\"}]}\n"
    );
    match runtime_adapter_captured_output(&spec, ndjson.as_bytes(), b"", true).unwrap() {
        RuntimeAdapterCapturedOutput::Captured(text) => {
            assert_eq!(text, b"vibe final answer".to_vec());
        }
        other => panic!("expected captured vibe report, got {other:?}"),
    }
}

#[test]
fn vibe_stage_writes_fresh_private_config_for_default_model() {
    let (dir, mut root) = vibe_temp_root("stage");
    let mut spec = vibe_command();
    let model = crate::runtime_adapter::vibe::validate_model(Some("mistral-small-latest"))
        .unwrap()
        .to_string();
    spec.model = Some(model.clone());
    let staged_output = dir.join("last-message.raw");
    let staging = vibe::stage(&spec, &mut root, &staged_output).unwrap();
    assert_eq!(staging.evidence.model, model);
    let config_path = staging.home.path().join("config.toml");
    let written = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        sha256_hex(written.as_bytes()),
        staging.evidence.config_sha256
    );
    assert_eq!(
        sha256_hex(
            crate::runtime_adapter::vibe::config_document(&model)
                .unwrap()
                .as_bytes()
        ),
        staging.evidence.config_sha256
    );
    assert!(staging
        .evidence
        .export_dir
        .ends_with("last-message.raw.vibe-export"));
    // The evidence retains the original request binding, never a credential
    // source path.
    assert_eq!(staging.evidence.program, spec.program);
    assert_eq!(staging.evidence.cwd, spec.cwd);
    assert_eq!(staging.evidence.prompt, spec.prompt);
    assert_eq!(
        staging.evidence.output_last_message,
        spec.output_last_message
    );
    assert_eq!(staging.evidence.reasoning_effort, None);
    assert!(staging.evidence.matches(&spec));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vibe_evidence_matches_binds_original_launch_request() {
    let (dir, mut root) = vibe_temp_root("matches");
    let mut spec = vibe_command();
    spec.model = Some("deepseek-v4-1-flash-1017".to_string());
    spec.reasoning_effort = Some("high".to_string());
    let staged_output = dir.join("last-message.raw");
    let staging = vibe::stage(&spec, &mut root, &staged_output).unwrap();
    assert!(staging.evidence.matches(&spec));

    // A changed model no longer matches the retained launch.
    let mut changed_model = spec.clone();
    changed_model.model = Some("zai-glm-5-3".to_string());
    assert!(!staging.evidence.matches(&changed_model));

    // A changed program, cwd, prompt, output leaf, or effort fails closed.
    let mut changed_program = spec.clone();
    changed_program.program = PathBuf::from("/opt/vibe-venv/bin/other-vibe");
    assert!(!staging.evidence.matches(&changed_program));
    let mut changed_cwd = spec.clone();
    changed_cwd.cwd = PathBuf::from("/workspace/other");
    assert!(!staging.evidence.matches(&changed_cwd));
    let mut changed_prompt = spec.clone();
    changed_prompt.prompt = PathBuf::from("/private/other-prompt.md");
    assert!(!staging.evidence.matches(&changed_prompt));
    let mut changed_output = spec.clone();
    changed_output.output_last_message = PathBuf::from("/private/staging/other.raw");
    assert!(!staging.evidence.matches(&changed_output));
    let mut changed_effort = spec.clone();
    changed_effort.reasoning_effort = None;
    assert!(!staging.evidence.matches(&changed_effort));

    // A non-Vibe invocation never matches.
    let mut codex = spec.clone();
    codex.invocation = ExternalAgentInvocation::CodexSupervisor;
    assert!(!staging.evidence.matches(&codex));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vibe_apply_environment_injects_only_the_child_credential() {
    let (dir, mut root) = vibe_temp_root("apply-env");
    let mut spec = vibe_command();
    spec.model = Some("deepseek-v4-1-flash-1017".to_string());
    let staged_output = dir.join("last-message.raw");
    let staging = vibe::stage(&spec, &mut root, &staged_output).unwrap();

    // Exercise the injected path so tests never consult an owner credential source.
    let mut environment = BTreeMap::new();
    vibe::apply_environment_with_credential(&staging, &mut environment, "abc123def456ghi789")
        .unwrap();
    assert_eq!(
        environment.get(vibe::CREDENTIAL_ENV).map(String::as_str),
        Some("abc123def456ghi789")
    );
    assert_eq!(
        environment.get("VIBE_ACTIVE_MODEL").map(String::as_str),
        Some("deepseek-v4-1-flash-1017")
    );
    assert!(environment.contains_key("VIBE_HOME"));
    assert!(environment.contains_key("HOME"));
    assert!(environment.contains_key("TMPDIR"));
    assert!(environment.contains_key("XDG_CONFIG_HOME"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vibe_fake_executable_fixture_assembles_two_models() {
    // Fixture-only assembly: a tiny /bin/sh script stands in for the Vibe
    // binary. It performs no network access and never invokes a real Vibe.
    let fixture_dir = tempfile::tempdir().expect("fixture tempdir");
    let script_path = fixture_dir.path().join("fake-vibe");
    let script = r#"#!/bin/sh
set -eu
umask 077
model=""
output_dir=""
prompt_file=""
workdir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --prompt-file) prompt_file="$2"; shift 2 ;;
    --workdir) workdir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$model" ] || { echo "missing --model" >&2; exit 3; }
[ -n "$output_dir" ] || { echo "missing --output-dir" >&2; exit 3; }
[ -n "$prompt_file" ] || { echo "missing --prompt-file" >&2; exit 3; }
[ -n "$workdir" ] || { echo "missing --workdir" >&2; exit 3; }
[ -f "$prompt_file" ] || { echo "missing prompt file" >&2; exit 3; }
# Only the synthetic child credential is used.
[ -n "${MISTRAL_API_KEY:-}" ] || { echo "missing MISTRAL_API_KEY" >&2; exit 3; }
# The parent redactor must scrub the intentionally echoed synthetic key.
printf '{"type":"message","role":"user","generationStatus":"completed","content":[{"type":"text","text":"credential echo: %s"}]}\n' "$MISTRAL_API_KEY"
echo "credential stderr: $MISTRAL_API_KEY" >&2
[ -d "$output_dir" ] || exit 3
printf '%s\n' '{"type":"message","role":"assistant","generationStatus":"completed","content":[{"type":"text","text":"{\"id\":\"vibe-fixture\",\"status\":\"succeeded\"}"}]}'
printf '%s\n' '{"outcome":"finished","usage":{"input_tokens":11,"output_tokens":7,"cached_input_tokens":3,"total_tokens":18},"cost_usd":0.0}' > "$output_dir/export.json"
"#;
    fs::write(&script_path, script).expect("write fake vibe script");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700)).expect("chmod script");

    let synthetic_key = "abc123def456ghi789";
    for model in ["deepseek-v4-1-flash-1017", "zai-glm-5-3"] {
        let (dir, mut root) = vibe_temp_root("fixture");
        let mut spec = vibe_command();
        spec.program = script_path.clone();
        spec.cwd = fixture_dir.path().to_path_buf();
        spec.prompt = dir.join("prompt.md");
        fs::write(&spec.prompt, "Return the bounded fixture report.").unwrap();
        spec.model = Some(model.to_string());
        spec.reasoning_effort = Some("high".to_string());
        let staged_output = dir.join("last-message.raw");
        spec.output_last_message = staged_output.clone();
        let staging = vibe::stage(&spec, &mut root, &staged_output).unwrap();

        // The immutable adapter render pins the requested model id and safe
        // flags, and never carries the credential.
        let mut config = RuntimeAdapterConfig::defaults(RuntimeId::Vibe);
        config.binary = Some(script_path.clone());
        spec.runtime_adapter = Some(config.clone());
        let argv = runtime_adapter_argv(&spec).unwrap();
        let rendered: Vec<String> = argv
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(rendered.iter().any(|argument| argument == "--model"));
        assert!(
            rendered.iter().any(|argument| argument == model),
            "{rendered:?}"
        );
        assert!(rendered.iter().any(|argument| argument == "--output-dir"));
        assert!(rendered.iter().any(|argument| argument == "--prompt-file"));
        assert!(rendered.iter().any(|argument| argument == "--workdir"));
        assert!(rendered.iter().any(|argument| argument == "--auto-approve"));
        assert!(rendered.iter().any(|argument| argument == "--max-turns"));
        assert!(rendered.iter().any(|argument| argument == "--max-tokens"));
        assert!(rendered.iter().any(|argument| argument == "--time-limit"));
        assert!(rendered.iter().any(|argument| argument == "--trust"));
        assert!(rendered.iter().any(|argument| argument == "--agent"));
        assert!(rendered.iter().any(|argument| argument == "auto-approve"));
        assert!(rendered.iter().any(|argument| argument == "--output"));
        assert!(rendered.iter().any(|argument| argument == "streaming"));
        assert!(rendered
            .iter()
            .any(|argument| argument == "--enabled-tools"));
        for argument in &rendered {
            assert!(!argument.contains(synthetic_key), "{argument}");
            assert!(!argument.contains("MISTRAL_API_KEY"), "{argument}");
            assert!(
                !argument.contains("MACO_VIBE_CREDENTIAL_FILE"),
                "{argument}"
            );
        }

        // Private HOME/XDG/TMPDIR/VIBE_HOME come from the staged environment.
        let mut environment = BTreeMap::new();
        vibe::apply_environment_with_credential(&staging, &mut environment, synthetic_key).unwrap();
        for key in [
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "VIBE_HOME",
        ] {
            let path = Path::new(&environment[key]);
            assert!(path.starts_with(&dir), "{key}");
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700,
                "{key}"
            );
        }
        let config_text = fs::read_to_string(staging.home.path().join("config.toml")).unwrap();
        assert!(config_text.contains(&format!("active_model = \"{model}\"")));
        assert!(config_text.contains("enable_subagents = false"));
        assert_eq!(
            environment.get("VIBE_HOME").map(String::as_str),
            Some(staging.home.path().to_str().unwrap())
        );

        // Spawn the fake executable directly with a cleared environment plus
        // the pure staged map. This is fixture assembly, not production
        // containment: the production path enforces its own confinement.
        let output = std::process::Command::new(&script_path)
            .args(&argv)
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(&environment)
            .output()
            .expect("spawn fake vibe fixture");
        assert!(output.status.success(), "fixture failed: {output:?}");

        // The captured stream is redacted and yields the bounded report text.
        let redactor = CredentialRedactor::from_runtime(&environment, None, None).unwrap();
        let redacted_stdout = redactor.redact_bytes(&output.stdout);
        let redacted_stderr = redactor.redact_bytes(&output.stderr);
        for redacted in [&redacted_stdout, &redacted_stderr] {
            assert!(!redacted
                .windows(synthetic_key.len())
                .any(|window| window == synthetic_key.as_bytes()));
        }
        let report = vibe::capture_report_text(&redacted_stdout).unwrap();
        assert_eq!(
            String::from_utf8(report).unwrap(),
            r#"{"id":"vibe-fixture","status":"succeeded"}"#
        );

        // Cached input is already included in the reported input and total.
        let usage = vibe::capture_usage(&staging.export).unwrap();
        assert_eq!(usage.input_tokens, 11);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.cached_input_tokens, 3);
        assert_eq!(usage.total_tokens, 18);
        let _ = fs::remove_dir_all(&dir);
    }
}
