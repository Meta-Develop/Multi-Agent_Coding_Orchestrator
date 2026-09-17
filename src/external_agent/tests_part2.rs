    #[cfg(unix)]
    #[test]
    fn codex_auth_directory_trust_decisions_reject_writable_ancestors_and_accept_a_safe_resolved_chain(
    ) {
        use CodexAuthDirectoryTrustDecision::{
            Accept as AcceptDirectory, RejectOwnership as RejectDirectoryOwnership,
            RejectWritable,
        };

        let effective_uid = 1000;
        // The selected /home/user/.codex symlink is canonicalized before this
        // production decision helper evaluates its safe owner-controlled target.
        let legitimate_resolved_home_chain = [
            ("/", 0o755, 0),
            ("/home", 0o755, 0),
            ("/home/user", 0o700, effective_uid),
            ("/home/user/.d-app-state", 0o700, effective_uid),
            (
                "/home/user/.d-app-state/.codex",
                0o700,
                effective_uid,
            ),
        ];
        for (ancestor, mode, uid) in legitimate_resolved_home_chain {
            assert_eq!(
                codex_auth_directory_trust_decision(mode, uid, true, effective_uid),
                AcceptDirectory,
                "legitimate resolved Codex-home ancestor must remain trusted: {ancestor}"
            );
        }

        assert_eq!(
            codex_auth_directory_trust_decision(0o1777, 0, true, effective_uid),
            RejectWritable
        );
        assert_eq!(
            codex_auth_directory_trust_decision(0o0777, effective_uid, true, effective_uid),
            RejectWritable
        );
        assert_eq!(
            codex_auth_directory_trust_decision(0o0755, 1001, true, effective_uid),
            RejectDirectoryOwnership
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_auth_file_trust_decisions_preserve_strict_auth_json_invariants() {
        use CodexAuthFileTrustDecision::{
            Accept as AcceptFile, RejectLinkCount, RejectMode, RejectNotRegular,
            RejectOwnership as RejectFileOwnership,
        };

        let effective_uid = 1000;
        assert_eq!(
            codex_auth_file_trust_decision(true, effective_uid, effective_uid, 0o600, 1),
            AcceptFile
        );
        assert_eq!(
            codex_auth_file_trust_decision(false, effective_uid, effective_uid, 0o600, 1),
            RejectNotRegular
        );
        assert_eq!(
            codex_auth_file_trust_decision(true, 1001, effective_uid, 0o600, 1),
            RejectFileOwnership
        );
        assert_eq!(
            codex_auth_file_trust_decision(true, effective_uid, effective_uid, 0o640, 1),
            RejectMode
        );
        assert_eq!(
            codex_auth_file_trust_decision(true, effective_uid, effective_uid, 0o600, 2),
            RejectLinkCount
        );
    }

    #[test]
    fn codex_auth_and_catalog_failure_summaries_name_cause_without_sensitive_detail() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let owner_local_path = temp
            .path()
            .join("owner-local")
            .join("auth.json")
            .display()
            .to_string();
        let credential_fixture = "credential-fixture-secret-value";
        let detail = anyhow::anyhow!(
            "unsafe detail path={owner_local_path} credential={credential_fixture}"
        )
        .context(CodexAuthValidationFailureCause::AuthFileOwnerMismatch);

        let auth_summary = sanitized_codex_auth_validation_summary(&detail);
        assert_eq!(
            auth_summary,
            "codex_auth_preflight_cause=auth_file_owner_mismatch"
        );

        let catalog_failure = codex_runtime_model_catalog_failure(&detail);
        assert_eq!(
            catalog_failure.category,
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
        );
        assert!(catalog_failure
            .summary
            .contains("cause=auth_file_owner_mismatch"));
        let process_error = ProcessRunError::ContainmentUnavailable {
            label: owner_local_path.clone(),
            command: credential_fixture.to_string(),
            source: std::io::Error::other(format!(
                "unsafe process detail path={owner_local_path} credential={credential_fixture}"
            )),
        };
        let process_cause =
            codex_runtime_model_catalog_process_failure_cause(&process_error).to_string();
        assert_eq!(process_cause, "catalog_process_containment_unavailable");
        for summary in [&auth_summary, &catalog_failure.summary, &process_cause] {
            assert!(!summary.contains(&owner_local_path));
            assert!(!summary.contains(credential_fixture));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn catalog_process_root_ignores_caller_workspace_with_dangling_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let caller_workspace = temp.path().join("caller-workspace");
        fs::create_dir(&caller_workspace)?;
        symlink(
            caller_workspace.join("missing-target"),
            caller_workspace.join("dangling"),
        )?;

        let trusted_program_dir = temp.path().join("trusted-program-dir");
        fs::create_dir(&trusted_program_dir)?;
        let canonical_program_dir = fs::canonicalize(&trusted_program_dir)?;
        let resolved_program = canonical_program_dir.join("codex");

        assert_eq!(
            codex_runtime_model_catalog_process_root(&resolved_program)?,
            canonical_program_dir
        );
        assert_ne!(
            codex_runtime_model_catalog_process_root(&resolved_program)?,
            fs::canonicalize(&caller_workspace)?
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn codex_auth_symlink_home_resolved_beneath_root_sticky_temp_is_rejected() -> Result<()> {
        use std::os::unix::{
            fs::{MetadataExt, PermissionsExt, symlink},
        };

        let system_temp = Path::new("/tmp");
        let system_temp_metadata = fs::symlink_metadata(system_temp)?;
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        assert_eq!(
            codex_auth_directory_trust_decision(
                system_temp_metadata.permissions().mode(),
                system_temp_metadata.uid(),
                system_temp_metadata.is_dir(),
                effective_uid,
            ),
            CodexAuthDirectoryTrustDecision::RejectWritable
        );
        assert_ne!(system_temp_metadata.permissions().mode() & 0o002, 0);

        let target_guard = tempfile::tempdir_in(system_temp)?;
        let target = target_guard.path().join("resolved-codex-home");
        fs::create_dir(&target)?;
        let auth = target.join("auth.json");
        let credential_fixture = "synthetic-auth-fixture-only";
        fs::write(&auth, format!(r#"{{"token":"{credential_fixture}"}}"#))?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;

        let selection_guard = tempfile::tempdir_in(system_temp)?;
        let selected = selection_guard.path().join("selected-codex-home");
        symlink(&target, &selected)?;
        assert_eq!(fs::canonicalize(&selected)?, fs::canonicalize(&target)?);

        let error = ValidatedCodexAuth::load_from_home(&selected)
            .expect_err("a Codex home resolved beneath /tmp must be refused");
        assert_eq!(
            error
                .downcast_ref::<CodexAuthValidationFailureCause>()
                .copied(),
            Some(CodexAuthValidationFailureCause::HomeAncestorWritable)
        );
        let rendered = format!("{error:#}");
        assert_eq!(rendered, "auth_home_ancestor_writable");
        assert_eq!(
            sanitized_codex_auth_validation_summary(&error),
            "codex_auth_preflight_cause=auth_home_ancestor_writable"
        );
        assert!(!rendered.contains("/tmp"));
        assert!(!rendered.contains(credential_fixture));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn codex_auth_checks_resolved_home_and_rejects_nonsticky_writable_ancestor() -> Result<()> {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};

        let temp = tempfile::tempdir()?;
        let writable_ancestor = temp.path().join("world-writable-ancestor");
        fs::create_dir(&writable_ancestor)?;
        fs::set_permissions(
            &writable_ancestor,
            fs::Permissions::from_mode(0o777),
        )?;
        let target = writable_ancestor.join("resolved-codex-home");
        fs::create_dir(&target)?;
        let auth = target.join("auth.json");
        fs::write(&auth, br#"{"token":"redacted"}"#)?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let selected = temp.path().join("selected-codex-home");
        symlink(&target, &selected)?;
        assert_eq!(fs::canonicalize(&selected)?, fs::canonicalize(&target)?);

        let error = ValidatedCodexAuth::load_from_home(&selected)
            .expect_err("the resolved writable ancestor must be refused");
        assert_eq!(
            error
                .downcast_ref::<CodexAuthValidationFailureCause>()
                .copied(),
            Some(CodexAuthValidationFailureCause::HomeAncestorWritable)
        );
        assert!(!format!("{error:#}").contains(&temp.path().display().to_string()));
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
    fn explicit_custom_version_preflight_retains_private_probe_stderr_on_failure() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        const MARKER: &str = "MACO_FIXED_VERSION_PROBE_DIAGNOSTIC_MARKER";

        let temp = tempfile::tempdir()?;
        create_mandatory_control_roots(temp.path())?;
        let marker = temp.path().join("actual-target-ran");
        let agent = temp.path().join("custom-codex.sh");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then printf '%s\\n' '{MARKER}' >&2; exit 101; fi\ntouch '{}'\n",
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
        assert!(!report.stdout.target_launch_attempted);
        assert!(report.environment_blocked());
        assert!(report.stdout.text.is_empty());
        assert!(report.stderr.text.is_empty());
        let evidence = report
            .fixed_version_probe_evidence()
            .expect("version preflight probe evidence");
        assert_eq!(evidence.exit_code, Some(101));
        assert!(evidence.stderr.text.contains(MARKER));
        assert_eq!(evidence.executable, EnvironmentExecutable::Codex);
        let expected_category = if evidence.process_tree.is_verified_empty()
            && evidence.side_effects.is_verified()
        {
            EnvironmentFailureCategory::ProbeFailed
        } else {
            EnvironmentFailureCategory::SandboxUnavailable
        };
        assert!(
            report
                .environment_failures()
                .iter()
                .any(|failure| failure.category == expected_category),
            "environment failures: {:?}",
            report.environment_failures()
        );
        let serialized = serde_json::to_string(&report)?;
        assert!(!serialized.contains(MARKER));

        let record = crate::supervise::command_record_from_external(&report, &spec);
        assert!(
            record
                .fixed_version_probe_evidence
                .as_ref()
                .is_some_and(|evidence| evidence.stderr.text.contains(MARKER))
        );
        let record_json = serde_json::to_string(&record)?;
        assert!(record_json.contains(MARKER));
        Ok(())
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

    #[cfg(target_os = "linux")]
    mod held_out_explicit_trusted_codex_binding {
        use super::*;
        use crate::mutation_taxonomy::AssignmentProcessLaunchKind;
        use std::os::unix::fs::{PermissionsExt, symlink};

        struct InjectedTrustedCodexResolution {
            previous: Option<PathBuf>,
            _path: PathBuf,
        }

        impl InjectedTrustedCodexResolution {
            fn install(path: PathBuf) -> Self {
                let previous =
                    replace_injected_trusted_codex_executable_for_test(Some(path.clone()));
                Self { previous, _path: path }
            }
        }

        impl Drop for InjectedTrustedCodexResolution {
            fn drop(&mut self) {
                set_injected_trusted_codex_executable_for_test(self.previous.take());
            }
        }

        struct InjectedCodexAuthHome {
            previous: Option<PathBuf>,
            _home: PathBuf,
            _guard: tempfile::TempDir,
        }

        impl InjectedCodexAuthHome {
            fn install() -> Result<Self> {
                let home_base = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .context("HOME must be set for bounded Codex auth fixture")?;
                let guard = tempfile::tempdir_in(&home_base)
                    .context("create uniquely owned Codex auth home under HOME")?;
                let home = guard.path().join("codex-auth-home");
                fs::create_dir(&home)?;
                fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
                let auth = home.join("auth.json");
                fs::write(
                    &auth,
                    r#"{"token":"synthetic-held-out-auth-fixture-31b"}"#,
                )?;
                fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
                let previous = set_injected_codex_auth_home_for_test(Some(home.clone()));
                Ok(Self {
                    previous,
                    _home: home,
                    _guard: guard,
                })
            }
        }

        impl Drop for InjectedCodexAuthHome {
            fn drop(&mut self) {
                let _ = set_injected_codex_auth_home_for_test(self.previous.take());
            }
        }

        fn write_trusted_codex_fixture(dir: &Path, name: &str, target_marker: &Path) -> PathBuf {
            let path = dir.join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'codex-cli 0.142.3\\n'; exit 0; fi\ntouch '{}'\nexit 0\n",
                    target_marker.display()
                ),
            )
            .expect("write trusted codex fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("chmod trusted codex fixture");
            path
        }

        fn held_out_codex_spec(program: PathBuf, workspace: &Path) -> ExternalAgentCommand {
            let prompt = workspace.join("prompt.txt");
            fs::write(&prompt, "held-out binding probe\n").expect("prompt");
            let incoming = workspace.join("incoming");
            fs::create_dir_all(&incoming).expect("incoming");
            fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).expect("incoming mode");
            ExternalAgentCommand::codex(
                program,
                workspace,
                &prompt,
                incoming.join("events.jsonl"),
                incoming.join("last-message.txt"),
                Duration::from_secs(3),
            )
        }

        fn attach_missing_assignment_child_launch(spec: &mut ExternalAgentCommand) {
            spec.assignment_process_launch_kind = Some(AssignmentProcessLaunchKind::AssignmentChild);
            *spec = spec.clone().with_agent_lifecycle(
                &spec.cwd,
                "worker",
                "held-out-trusted-binding-run",
                "held-out-trusted-binding-assignment",
            );
        }

        fn assert_explicit_custom_strict_offline_refusal(
            report: &ExternalAgentRun,
            target_marker: &Path,
        ) {
            assert!(!target_marker.exists());
            assert!(!report.stdout.target_launch_attempted);
            assert_eq!(report.program_trust, ExternalProgramTrust::ExplicitCustom);
            assert!(
                report.error.as_deref().is_some_and(|error| {
                    error.contains(
                        "explicit custom executables are limited to a strict-offline version diagnostic",
                    )
                }),
                "expected strict-offline explicit-custom refusal: {:?}",
                report.error
            );
            let evidence = report
                .fixed_version_probe_evidence()
                .expect("explicit custom must run the strict-offline version diagnostic");
            assert!(matches!(
                evidence.side_effects,
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::StrictOfflineWorkspace
                )
            ));
        }

        fn assert_verified_external_codex_fixed_version_preflight(report: &ExternalAgentRun) {
            let requirement = codex_environment_requirement();
            assert!(
                report
                    .environment_preflight_results()
                    .iter()
                    .any(|result| {
                        result.requirement == requirement
                            && result.status == EnvironmentPreflightStatus::Satisfied
                            && matches!(
                                result.observation,
                                Some(EnvironmentPreflightObservation::ExecutableVersion {
                                    executable: EnvironmentExecutable::Codex,
                                    ..
                                })
                            )
                    }),
                "trusted held-out executable must satisfy Codex version preflight: {:?}",
                report.environment_preflight_results()
            );
            let evidence = report
                .fixed_version_probe_evidence()
                .expect("verified trusted Codex must record fixed-version probe evidence");
            assert_eq!(evidence.executable, EnvironmentExecutable::Codex);
            assert!(matches!(
                evidence.side_effects,
                SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalCodex
                )
            ));
        }

        #[test]
        fn verified_absolute_trusted_codex_runs_external_codex_version_preflight() -> Result<()> {
            let temp = tempfile::tempdir()?;
            create_mandatory_control_roots(temp.path())?;
            let target_marker = temp.path().join("actual-target-ran");
            let trusted =
                write_trusted_codex_fixture(temp.path(), "trusted-codex", &target_marker);
            let _inject = InjectedTrustedCodexResolution::install(trusted);
            let _auth_home = InjectedCodexAuthHome::install()?;
            let canonical = fs::canonicalize(temp.path().join("trusted-codex"))?;
            let spec = held_out_codex_spec(canonical.clone(), temp.path());
            assert!(spec.program.is_absolute());
            assert_eq!(spec.program, canonical);
            assert!(spec.assignment_process_launch_kind.is_none());
            assert!(spec.assignment_process_launch_grant.is_none());

            let report = run_external_agent(&spec);

            assert_eq!(report.program_trust, ExternalProgramTrust::TrustedSystemCodex);
            assert_eq!(
                report.command.first().map(String::as_str),
                canonical.to_str()
            );
            assert_verified_external_codex_fixed_version_preflight(&report);
            assert!(!target_marker.exists());
            assert!(!report.stdout.target_launch_attempted);
            assert!(
                report.error.as_deref().is_some_and(|error| {
                    error.contains("external executable changed before target release")
                        && error.contains("default Codex executable must be root-owned")
                }),
                "trusted absolute binding must pass preflight then fail trusted root-ownership revalidation: {:?}",
                report.error
            );
            Ok(())
        }

        #[test]
        fn assignment_child_missing_grant_fails_closed_before_preflight_or_target() -> Result<()> {
            let temp = tempfile::tempdir()?;
            create_mandatory_control_roots(temp.path())?;
            let target_marker = temp.path().join("actual-target-ran");
            let trusted =
                write_trusted_codex_fixture(temp.path(), "trusted-codex", &target_marker);
            let _inject = InjectedTrustedCodexResolution::install(trusted);
            let canonical = fs::canonicalize(temp.path().join("trusted-codex"))?;
            let mut spec = held_out_codex_spec(canonical, temp.path());
            attach_missing_assignment_child_launch(&mut spec);

            let report = run_external_agent(&spec);

            assert!(report.fixed_version_probe_evidence().is_none());
            super::assert_assignment_process_launch_refused(
                &report,
                &target_marker,
                crate::mutation_taxonomy::AssignmentProcessLaunchGrantError::MissingGrant,
            );
            Ok(())
        }

        #[test]
        fn mismatched_absolute_executable_stays_explicit_custom_on_verified_runtime() -> Result<()> {
            let temp = tempfile::tempdir()?;
            create_mandatory_control_roots(temp.path())?;
            let target_marker = temp.path().join("actual-target-ran");
            let trusted = write_trusted_codex_fixture(
                temp.path(),
                "trusted-codex",
                &target_marker,
            );
            let other = write_trusted_codex_fixture(temp.path(), "other-codex", &target_marker);
            let _inject = InjectedTrustedCodexResolution::install(trusted);
            let other_canonical = fs::canonicalize(&other)?;
            let spec = held_out_codex_spec(other_canonical, temp.path());

            let report = run_external_agent(&spec);

            assert_explicit_custom_strict_offline_refusal(&report, &target_marker);
            Ok(())
        }

        #[test]
        fn hardlink_alias_path_stays_explicit_custom_without_target_launch() -> Result<()> {
            let temp = tempfile::tempdir()?;
            create_mandatory_control_roots(temp.path())?;
            let target_marker = temp.path().join("actual-target-ran");
            let trusted = write_trusted_codex_fixture(
                temp.path(),
                "trusted-codex",
                &target_marker,
            );
            let alias = temp.path().join("codex-hardlink-alias");
            fs::hard_link(&trusted, &alias)?;
            let _inject = InjectedTrustedCodexResolution::install(trusted);
            let alias_canonical = fs::canonicalize(&alias)?;
            let trusted_canonical = fs::canonicalize(temp.path().join("trusted-codex"))?;
            assert_ne!(alias_canonical, trusted_canonical);
            let spec = held_out_codex_spec(alias_canonical, temp.path());

            let report = run_external_agent(&spec);

            assert_explicit_custom_strict_offline_refusal(&report, &target_marker);
            Ok(())
        }

        /// Exercises `resolve_external_program` symlink rejection for an explicit absolute
        /// executable before trust classification, version preflight, or target release.
        #[test]
        fn explicit_symlink_absolute_path_refuses_before_trust_or_target() -> Result<()> {
            let temp = tempfile::tempdir()?;
            create_mandatory_control_roots(temp.path())?;
            let target_marker = temp.path().join("actual-target-ran");
            let trusted = write_trusted_codex_fixture(
                temp.path(),
                "trusted-codex",
                &target_marker,
            );
            let link = temp.path().join("codex-symlink");
            symlink(&trusted, &link)?;
            let _inject = InjectedTrustedCodexResolution::install(trusted);
            let spec = held_out_codex_spec(link, temp.path());

            let report = run_external_agent(&spec);

            assert!(!target_marker.exists());
            assert!(!report.stdout.target_launch_attempted);
            assert_eq!(report.program_trust, ExternalProgramTrust::ExplicitCustom);
            assert!(
                report
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("may not be a symlink")),
                "symlink explicit executable must fail closed during resolution: {:?}",
                report.error
            );
            assert!(report.fixed_version_probe_evidence().is_none());
            assert!(
                report
                    .environment_preflight_results()
                    .iter()
                    .all(|result| result.status != EnvironmentPreflightStatus::Satisfied),
                "symlink refusal must occur before satisfied Codex version preflight: {:?}",
                report.environment_preflight_results()
            );
            Ok(())
        }
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
