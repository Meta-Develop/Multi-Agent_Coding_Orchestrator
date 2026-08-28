use super::*;

#[test]
fn environment_requirements_default_compatibly_and_aggregate_canonically() {
    let legacy_plan = json!({
        "version": 1,
        "task": "legacy environment defaults",
        "max_depth": 2,
        "max_child_assignments": 1,
        "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["README.md"],
            "worker_assignments": [{
                "id": "worker-a",
                "assigned_paths": ["README.md"]
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&legacy_plan).expect("serialize legacy plan"),
    )
    .expect("legacy plan remains compatible");
    assert!(loaded.plan.assignments[0]
        .environment_requirements
        .is_empty());
    assert!(loaded.plan.assignments[0].worker_assignments[0]
        .environment_requirements
        .is_empty());

    let requirement =
        EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile);
    let mut assignment = loaded.plan.assignments[0].clone();
    assignment.environment_requirements = vec![requirement.clone()];
    assignment.worker_assignments[0].environment_requirements = vec![requirement.clone()];
    assert_eq!(
        canonical_environment_requirements(&assignment)
            .expect("identical cross-worker requirements deduplicate"),
        vec![requirement]
    );

    assignment.environment_requirements = vec![EnvironmentRequirement::network(
        EnvironmentNetworkAccess::Disabled,
    )];
    assignment.worker_assignments[0].environment_requirements =
        vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
    assert!(canonical_environment_requirements(&assignment)
        .expect_err("conflicting aggregate requirements must fail")
        .to_string()
        .contains("conflicting aggregate environment requirements"));
}
#[test]
fn environment_requirement_bounds_and_report_defaults_fail_closed() {
    let oversized = (0..=32)
        .map(|_| EnvironmentRequirement::network(EnvironmentNetworkAccess::Disabled))
        .collect::<Vec<_>>();
    assert!(validate_environment_requirements(&oversized).is_err());

    let assignment = injected_assignment(true);
    let mut legacy =
        serde_json::to_value(injected_child_report(&assignment)).expect("serialize report fixture");
    legacy
        .as_object_mut()
        .expect("orchestrator report object")
        .remove("environment_failures");
    for worker in legacy["worker_reports"]
        .as_array_mut()
        .expect("worker reports")
    {
        worker
            .as_object_mut()
            .expect("worker report object")
            .remove("environment_failures");
    }
    let restored: OrchestratorReviewReport =
        serde_json::from_value(legacy).expect("legacy report remains compatible");
    assert!(restored.environment_failures.is_empty());
    assert!(restored
        .worker_reports
        .iter()
        .all(|worker| worker.environment_failures.is_empty()));
}

#[test]
fn environment_failure_schemas_and_outcomes_are_typed_and_secret_free() {
    for schema in [
        orchestrator_report_schema_value(),
        worker_report_schema_value(),
        auditor_report_schema_value(),
        supervisor_final_report_schema_value(),
    ] {
        assert!(schema["properties"].get("environment_failures").is_some());
    }
    let command_schema = command_run_record_schema_value();
    assert!(command_schema["properties"]
        .get("environment_preflight_results")
        .is_some());
    assert!(command_schema["properties"]
        .get("environment_failures")
        .is_some());

    let marker = "DO_NOT_PERSIST_SECRET_MARKER";
    let mut report = injected_child_report(&injected_assignment(false));
    report.environment_failures.push(EnvironmentFailure {
        category: EnvironmentFailureCategory::MissingCredential,
        requirement: Some(EnvironmentRequirement::configuration(
            EnvironmentConfiguration::CodexAuthFile,
        )),
        summary: marker.to_string(),
        remediation: Vec::new(),
    });
    enforce_orchestrator_environment_failure_outcome(&mut report);
    assert!(!report.accepted);
    assert!(report.rejected);
    assert_eq!(report.status, ReviewStatus::Failed);
    assert!(!serde_json::to_string(&report)
        .expect("serialize sanitized environment failure")
        .contains(marker));
}

#[test]
fn nested_command_environment_failures_are_recursively_sanitized_and_terminal() {
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let mut report = injected_child_report(&assignment);
    let auditor_report = injected_auditor_report(&assignment, &report);
    report.audit_reports.push(auditor_report);

    let orchestrator_marker = "ORCHESTRATOR_COMMAND_SECRET_MARKER_31";
    let worker_marker = "WORKER_COMMAND_SECRET_MARKER_31";
    let auditor_marker = "AUDITOR_COMMAND_SECRET_MARKER_31";
    let command_with_failure =
        |marker: &str, category: EnvironmentFailureCategory| -> CommandRunRecord {
            let mut command = injected_command_record();
            command.environment_failures.push(EnvironmentFailure {
                category,
                requirement: None,
                summary: marker.to_string(),
                remediation: Vec::new(),
            });
            command
        };
    report.commands_run.push(command_with_failure(
        orchestrator_marker,
        EnvironmentFailureCategory::NetworkForbidden,
    ));
    report.worker_reports[0]
        .commands_run
        .push(command_with_failure(
            worker_marker,
            EnvironmentFailureCategory::MissingCredential,
        ));
    report.audit_reports[0]
        .commands_run
        .push(command_with_failure(
            auditor_marker,
            EnvironmentFailureCategory::SandboxUnavailable,
        ));

    let prompt = parent_review_auditor_prompt_with_field_guide(
        ParentReviewAuditorPromptContext {
            plan: &plan,
            assignment: &assignment,
            assignment_metadata: &AssignmentMetadata::new(),
            run_dir: Path::new("/tmp/maco-nested-environment-failure"),
            worktree_path: Path::new("/tmp/maco-nested-environment-failure/worktree"),
            child_report_path: Path::new(
                "/tmp/maco-nested-environment-failure/reports/child-a.json",
            ),
            auditor_report_path: Path::new(
                "/tmp/maco-nested-environment-failure/incoming/auditor.json",
            ),
            schema_path: Path::new("/tmp/maco-nested-environment-failure/schemas/auditor.json"),
            child_report: &report,
        },
        &SupervisorFieldGuidePrompt::empty().expect("empty field guide"),
    )
    .expect("render sanitized parent auditor prompt");
    for marker in [orchestrator_marker, worker_marker, auditor_marker] {
        assert!(!prompt.contains(marker));
    }

    enforce_orchestrator_environment_failure_outcome(&mut report);
    assert_eq!(report.status, ReviewStatus::Failed);
    assert!(!report.accepted);
    assert!(report.rejected);
    assert_eq!(report.commands_run[0].status, ReviewStatus::Failed);
    assert_eq!(report.worker_reports[0].status, ReviewStatus::Failed);
    assert_eq!(
        report.worker_reports[0].commands_run[0].status,
        ReviewStatus::Failed
    );
    assert_eq!(report.audit_reports[0].status, ReviewStatus::Failed);
    assert_eq!(
        report.audit_reports[0].commands_run[0].status,
        ReviewStatus::Failed
    );
    let expected_categories = [
        EnvironmentFailureCategory::MissingCredential,
        EnvironmentFailureCategory::NetworkForbidden,
        EnvironmentFailureCategory::SandboxUnavailable,
    ];
    for category in expected_categories {
        assert!(report
            .environment_failures
            .iter()
            .any(|failure| failure.category == category));
    }
    assert_eq!(report.environment_failures.len(), 3);
    for failure in report
        .environment_failures
        .iter()
        .chain(report.commands_run[0].environment_failures.iter())
        .chain(report.worker_reports[0].environment_failures.iter())
        .chain(
            report.worker_reports[0].commands_run[0]
                .environment_failures
                .iter(),
        )
        .chain(report.audit_reports[0].environment_failures.iter())
        .chain(
            report.audit_reports[0].commands_run[0]
                .environment_failures
                .iter(),
        )
    {
        assert!(failure
            .summary
            .starts_with("environment preflight reported "));
        assert!(!failure.remediation.is_empty());
        assert!(failure
            .remediation
            .iter()
            .all(|remediation| !remediation.guidance.contains("SECRET_MARKER_31")));
    }

    let mut final_report = artifact_test_final_report(
        &RunId::new("nested-environment-failure").expect("valid run id"),
    );
    final_report.orchestrator_reports = vec![report];
    enforce_supervisor_final_environment_failure_outcome(&mut final_report);
    assert!(!final_report.success);
    assert!(!final_report.publishable);
    assert!(!final_report.accepted);
    assert!(final_report.rejected);
    assert_eq!(final_report.status, ReviewStatus::Failed);
    assert_eq!(final_report.environment_failures.len(), 3);
    for category in expected_categories {
        assert!(final_report
            .environment_failures
            .iter()
            .any(|failure| failure.category == category));
    }
    let serialized =
        serde_json::to_string(&final_report).expect("serialize normalized final report");
    for marker in [orchestrator_marker, worker_marker, auditor_marker] {
        assert!(!serialized.contains(marker));
    }

    assert_eq!(
        command_run_record_schema_value()["allOf"][0]["then"]["properties"]["status"]["const"],
        "failed"
    );
    assert_eq!(
        orchestrator_report_schema_value()["allOf"][0]["if"]["anyOf"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
}

#[test]
fn environment_requirements_are_captured_for_child_and_auditor_commands() {
    let temp = tempfile::tempdir().expect("temporary command capture");
    let requirements = vec![
        EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile),
        EnvironmentRequirement::network(EnvironmentNetworkAccess::Disabled),
    ];
    let child = apply_canonical_environment_requirements(
        control_test_command(temp.path(), temp.path()),
        &requirements,
    );
    let auditor = apply_canonical_environment_requirements(
        control_test_command(temp.path(), temp.path())
            .with_workspace_access(WorkspaceAccess::ReadOnly),
        &requirements,
    );

    assert_eq!(child.environment_requirements, requirements);
    assert_eq!(auditor.environment_requirements, requirements);
}

#[test]
fn environment_preflight_refusal_is_typed_terminal_and_not_malformed_or_containment() {
    let assignment = injected_assignment(true);
    let command = control_test_command(Path::new("."), Path::new("."));
    let requirement =
        EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile);
    let marker = "DO_NOT_PERSIST_PREFLIGHT_SECRET_MARKER";
    let failure = EnvironmentFailure {
        category: EnvironmentFailureCategory::MissingCredential,
        requirement: Some(requirement.clone()),
        summary: marker.to_string(),
        remediation: Vec::new(),
    };
    let preflight = EnvironmentPreflightResult {
        requirement,
        status: EnvironmentPreflightStatus::Blocked,
        observation: None,
    };
    let mut run_value = serde_json::to_value(injected_verified_run_without_journals(&command))
        .expect("serialize injected run");
    run_value["exit_code"] = Value::Null;
    run_value["publishable"] = Value::Bool(false);
    run_value["codex_permissions"] = Value::Null;
    run_value["environment_preflight_results"] =
        serde_json::to_value([preflight]).expect("serialize preflight result");
    run_value["environment_failures"] =
        serde_json::to_value([failure]).expect("serialize environment failure");
    run_value["error"] = Value::String("environment preflight blocked the assignment".to_string());
    let run: ExternalAgentRun =
        serde_json::from_value(run_value).expect("restore environment-blocked run");
    assert!(run.environment_blocked());
    assert!(!external_safety_verified(&run, SupervisorRuntime::Codex));
    assert!(external_containment_verified(
        &run,
        SupervisorRuntime::Codex
    ));

    let mut unverified_preflight =
        serde_json::to_value(&run).expect("serialize environment-blocked run");
    unverified_preflight["environment_preflight_process_started"] = Value::Bool(true);
    unverified_preflight["process_tree"] = serde_json::to_value(ProcessTreeEvidence::Unverified(
        ContainmentBackend::SystemdUserService,
    ))
    .expect("serialize unverified preflight process tree");
    unverified_preflight["side_effects"] = serde_json::to_value(
        SideEffectConfinementEvidence::Unverified(SideEffectConfinementProfileKind::ExternalCodex),
    )
    .expect("serialize unverified preflight side effects");
    let unverified_preflight: ExternalAgentRun = serde_json::from_value(unverified_preflight)
        .expect("restore unverified environment preflight");
    assert!(unverified_preflight.environment_blocked());
    assert!(!unverified_preflight.environment_preflight_quiescence_verified());
    assert!(!external_containment_verified(
        &unverified_preflight,
        SupervisorRuntime::Codex
    ));

    let child_base_head = injected_oid("environment-blocked-base");
    let worker_journals = WorkerExecutionJournalEvidenceSet::default();
    let (report, shape_problems) = collect_child_report(ChildReportCollectionContext {
        assignment: &assignment,
        assignment_metadata: &AssignmentMetadata::new(),
        report_path: Path::new("environment-blocked.json"),
        external_run: &run,
        external_command: &command,
        worktree_path: Path::new("."),
        child_base_head: &child_base_head,
        observed_changed_paths: None,
        worker_journals: &worker_journals,
        evidence_only_source: None,
    });

    assert!(shape_problems.is_empty());
    assert!(!should_retry_child_report(&report, &shape_problems, 1, 2));
    assert_eq!(report.status, ReviewStatus::Failed);
    assert!(!report.accepted);
    assert!(report.rejected);
    assert_eq!(report.worker_reports.len(), 1);
    assert!(report
        .worker_reports
        .iter()
        .all(|worker| !worker.environment_failures.is_empty()
            && worker.status == ReviewStatus::Failed
            && !worker.accepted));
    assert!(report.gate_denials.is_empty());
    let findings = finding_messages(&report);
    assert!(findings.contains("environment preflight blocked"));
    assert!(!findings.contains("missing or invalid"));
    assert!(!findings.contains("containment"));
    assert_eq!(report.commands_run.len(), 1);
    assert_eq!(
        report.commands_run[0].environment_preflight_results.len(),
        1
    );
    assert_eq!(report.commands_run[0].environment_failures.len(), 1);
    let aggregate =
        aggregate_environment_failures(&report.commands_run, std::slice::from_ref(&report));
    assert_eq!(aggregate.len(), 1);
    assert!(!serde_json::to_string(&(report, aggregate))
        .expect("serialize environment-blocked evidence")
        .contains(marker));
}

#[cfg(unix)]
#[test]
fn issue32_mandatory_worktree_controls_are_provisioned_without_touching_policy_contents() {
    use std::os::unix::fs::PermissionsExt;

    let (_temp, workspace) = mandatory_control_test_workspace();
    fs::create_dir(workspace.join(".agents")).expect("create existing policy root");
    let policy = workspace.join(".agents/AGENTS.md");
    fs::write(&policy, b"immutable policy fixture\n").expect("write policy fixture");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o444))
        .expect("make policy fixture read-only");
    let git_before = fs::read(workspace.join(".git")).expect("read .git marker before");
    let policy_before = fs::symlink_metadata(&policy).expect("inspect policy before");

    let controls =
        provision_mandatory_worktree_controls(&workspace).expect("provision mandatory controls");
    controls.revalidate().expect("revalidate held controls");

    for relative in MANDATORY_WORKTREE_DIRECTORY_CONTROLS {
        let metadata =
            fs::symlink_metadata(workspace.join(relative)).expect("inspect provisioned control");
        assert!(
            metadata.is_dir(),
            "{relative} was not provisioned as a directory"
        );
        assert!(!metadata.file_type().is_symlink());
    }
    assert_eq!(
        fs::read(workspace.join(".git")).expect("read .git marker after"),
        git_before
    );
    let policy_after = fs::symlink_metadata(&policy).expect("inspect policy after");
    assert_eq!(
        fs::read(&policy).expect("read policy after"),
        b"immutable policy fixture\n"
    );
    assert_eq!(policy_after.mode(), policy_before.mode());
    assert_eq!(policy_after.ino(), policy_before.ino());
}

#[cfg(unix)]
#[test]
fn issue32_mandatory_control_bootstrap_rejects_symlinks_and_identity_replacement() {
    use std::os::unix::fs::symlink;

    let (_temp, workspace) = mandatory_control_test_workspace();
    let target = workspace.join("alias-target");
    fs::create_dir(&target).expect("create symlink target");
    symlink(&target, workspace.join(".codex")).expect("create control symlink");
    let error = provision_mandatory_worktree_controls(&workspace)
        .expect_err("symlink control must fail closed");
    assert!(error.to_string().contains("non-symlink directory"));

    fs::remove_file(workspace.join(".codex")).expect("remove symlink fixture");
    let controls =
        provision_mandatory_worktree_controls(&workspace).expect("provision mandatory controls");
    fs::rename(workspace.join(".agents"), workspace.join(".agents-held"))
        .expect("move held policy root");
    symlink(&target, workspace.join(".agents")).expect("replace policy root with symlink");
    let error = controls
        .revalidate()
        .expect_err("replaced control identity must fail closed");
    assert!(error
        .to_string()
        .contains("mandatory worktree control identity changed"));
}

#[cfg(unix)]
#[test]
fn issue32_child_command_exceptions_are_exactly_assignment_derived_policy_paths() {
    let (temp, workspace) = mandatory_control_test_workspace();
    let artifact_root = temp.path().join("incoming");
    fs::create_dir(&artifact_root).expect("create incoming root");
    provision_mandatory_worktree_controls(&workspace).expect("provision controls");
    fs::create_dir_all(workspace.join(".agents/skills/demo")).expect("create nested policy path");
    fs::write(workspace.join(".agents/skills/demo/SKILL.md"), b"policy\n")
        .expect("write nested policy");
    fs::write(workspace.join("AGENTS.md"), b"root policy\n").expect("write root policy");

    let ordinary = configure_writable_child_command(
        control_test_command(&workspace, &artifact_root),
        &[PathBuf::from("src/lib.rs")],
    )
    .expect("configure ordinary assignment");
    assert_eq!(ordinary.workspace_access, WorkspaceAccess::ReadWrite);
    assert!(ordinary.worktree_control_exceptions.is_empty());

    let policy = configure_writable_child_command(
        control_test_command(&workspace, &artifact_root),
        &[
            PathBuf::from("AGENTS.md"),
            PathBuf::from(".agents/skills/demo/SKILL.md"),
        ],
    )
    .expect("configure exact policy assignment");
    assert_eq!(
        policy.worktree_control_exceptions,
        vec![
            PathBuf::from(".agents/skills/demo/SKILL.md"),
            PathBuf::from("AGENTS.md"),
        ]
    );
    assert!(!policy
        .worktree_control_exceptions
        .iter()
        .any(|path| path == Path::new(".agents")));
}

#[test]
fn issue32_permanent_controls_and_policy_root_are_never_write_exceptions() {
    for forbidden in [
        ".git",
        ".git/config",
        ".maco/state.json",
        ".maco-cache/index",
        ".codex/config.toml",
        ".agents",
    ] {
        let error = assignment_worktree_control_exceptions(&[PathBuf::from(forbidden)])
            .expect_err("permanent control assignment must fail closed");
        assert!(
            error.to_string().contains("read-only") || error.to_string().contains("policy root"),
            "unexpected error for {forbidden}: {error:#}"
        );
    }
    assert!(
        assignment_worktree_control_exceptions(&[PathBuf::from("src/.agents/config")])
            .expect("ordinary nested name is not a protected root")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn issue32_auditor_is_read_only_while_incoming_report_remains_writable() {
    let (temp, workspace) = mandatory_control_test_workspace();
    let artifact_root = temp.path().join("incoming");
    fs::create_dir(&artifact_root).expect("create incoming root");
    provision_mandatory_worktree_controls(&workspace).expect("provision controls");
    let report_path = artifact_root.join("report.json");
    let command =
        configure_read_only_auditor_command(control_test_command(&workspace, &artifact_root))
            .expect("configure read-only auditor");
    assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
    assert!(command.worktree_control_exceptions.is_empty());
    assert_eq!(command.output_last_message, report_path);

    let argv = crate::external_agent::command_argv(&command)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let filesystem = argv
        .iter()
        .find(|argument| argument.starts_with("permissions.maco_external_codex.filesystem="))
        .expect("filesystem permission config");
    assert!(!filesystem.contains("\":workspace_roots\""));
    assert!(filesystem.contains(&format!(
        "{}=\"write\"",
        serde_json::to_string(
            artifact_root
                .to_str()
                .expect("UTF-8 temporary artifact root")
        )
        .expect("quote artifact root")
    )));
}

#[test]
fn issue32_denials_propagate_deduplicate_round_trip_and_default() {
    let temp = tempfile::tempdir().expect("temporary denial fixture");
    let workspace = temp.path().join("workspace");
    let artifact_root = temp.path().join("incoming");
    fs::create_dir_all(&workspace).expect("create denial workspace");
    fs::create_dir_all(&artifact_root).expect("create denial artifact root");
    let command = control_test_command(&workspace, &artifact_root);
    let outer = denial_fixture(
        SandboxDenialBoundary::OuterSystemd,
        "maco_external_codex_outer_systemd_v1",
        None,
        SandboxDenialRetryability::NotRetryable,
    );
    let inner = denial_fixture(
        SandboxDenialBoundary::InnerCodex,
        "maco_external_codex_inner_v1",
        Some("AGENTS.md"),
        SandboxDenialRetryability::RequiresDeclaredException,
    );
    let mut run_value = serde_json::to_value(deterministic_fake_run(&command, Vec::new()))
        .expect("serialize external run fixture");
    run_value
        .as_object_mut()
        .expect("external run object")
        .insert(
            "sandbox_denials".to_string(),
            serde_json::to_value(vec![inner.clone(), outer.clone()])
                .expect("serialize denial fixtures"),
        );
    let run: ExternalAgentRun =
        serde_json::from_value(run_value).expect("deserialize external run fixture");
    let record = command_record_from_external(&run, &command);
    assert_eq!(
        record.sandbox_denials,
        vec![outer.clone(), inner.clone()],
        "command record denial ordering must be deterministic"
    );

    let mut report =
        artifact_test_final_report(&RunId::new("sandbox-denial-round-trip").expect("valid run id"));
    report.commands_run = vec![record.clone(), record.clone()];
    report.sandbox_denials = aggregate_sandbox_denials(&report.commands_run);
    assert_eq!(report.sandbox_denials, vec![outer, inner]);
    let value = serde_json::to_value(&report).expect("serialize supervisor report");
    let decoded: SupervisorFinalReport =
        serde_json::from_value(value.clone()).expect("stable supervisor report round trip");
    assert_eq!(decoded, report);

    let mut old_value = value;
    old_value
        .as_object_mut()
        .expect("supervisor report object")
        .remove("sandbox_denials");
    for command in old_value["commands_run"]
        .as_array_mut()
        .expect("command array")
    {
        command
            .as_object_mut()
            .expect("command object")
            .remove("sandbox_denials");
    }
    let old: SupervisorFinalReport =
        serde_json::from_value(old_value).expect("old report JSON remains compatible");
    assert!(old.sandbox_denials.is_empty());
    assert!(old
        .commands_run
        .iter()
        .all(|record| record.sandbox_denials.is_empty()));
    assert!(command_run_record_schema_value()["properties"]
        .get("sandbox_denials")
        .is_some());
    assert!(!command_run_record_schema_value()["required"]
        .as_array()
        .expect("required fields")
        .iter()
        .any(|field| field == "sandbox_denials"));
}

#[test]
fn issue32_unsafe_denial_paths_do_not_serialize_absolute_host_paths() {
    let unsafe_path = "/home/operator/private/control";
    let denials = sandbox_denials_for_report(&[denial_fixture(
        SandboxDenialBoundary::InnerCodex,
        "maco_external_codex_inner_v1",
        Some(unsafe_path),
        SandboxDenialRetryability::RequiresDeclaredException,
    )]);
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].path, None);
    let error =
        serde_json::to_string(&denials).expect_err("sanitized invalid evidence must not serialize");
    assert!(!error.to_string().contains(unsafe_path));
}

#[test]
fn concurrency_policy_parses_auto_and_positive_limits_with_auto_default() {
    assert_eq!(
        "auto".parse::<SupervisorConcurrencyPolicy>(),
        Ok(SupervisorConcurrencyPolicy::Auto)
    );
    assert_eq!(
        "1".parse::<SupervisorConcurrencyPolicy>(),
        Ok(SupervisorConcurrencyPolicy::Fixed(
            NonZeroUsize::new(1).expect("one is non-zero")
        ))
    );
    assert_eq!(
        "17".parse::<SupervisorConcurrencyPolicy>(),
        Ok(SupervisorConcurrencyPolicy::Fixed(
            NonZeroUsize::new(17).expect("seventeen is non-zero")
        ))
    );
    assert_eq!(
        SupervisorConcurrencyPolicy::default(),
        SupervisorConcurrencyPolicy::Auto
    );
    for invalid in ["0", "Auto", "-1", "many"] {
        assert!(
            invalid.parse::<SupervisorConcurrencyPolicy>().is_err(),
            "unexpected valid policy: {invalid}"
        );
    }
}

#[test]
fn concurrency_policy_auto_is_independent_of_cpu_parallelism() {
    let capacity = HostProcessCapacity::from_parallelism(
        NonZeroUsize::new(13).expect("test capacity is non-zero"),
    );
    assert_eq!(
        SupervisorConcurrencyPolicy::Auto.resolve(capacity),
        4,
        "network-bound auto admission must not silently equal CPU parallelism"
    );
    assert_eq!(
        SupervisorConcurrencyPolicy::Fixed(NonZeroUsize::new(1).expect("serial limit is non-zero"))
            .resolve(capacity),
        1,
        "explicit one must remain the exact serial opt-out"
    );
}

#[test]
fn concurrency_policy_auto_uses_conservative_network_default() {
    assert_eq!(
        SupervisorConcurrencyPolicy::Auto.resolve(HostProcessCapacity::measured()),
        4,
        "supervise admission must remain independent of containment CPU slots"
    );
}

#[test]
fn external_containment_gate_accepts_only_verified_empty_evidence() {
    assert!(
        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
            .is_verified_empty()
    );
    assert!(
        !ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
            .is_verified_empty()
    );
    assert!(
        !ProcessTreeEvidence::Unverified(ContainmentBackend::WindowsJobObject).is_verified_empty()
    );
}
