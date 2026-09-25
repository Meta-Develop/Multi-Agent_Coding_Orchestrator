//! Authored terminal research: its own wire contract and read-only launch.
use super::*;

pub(super) fn validate_researcher_assignment(assignment: &OrchestratorAssignment) -> Result<()> {
    if assignment.role_category != Some(RoleCategory::ReadOnlyResearcher)
        || !assignment.worker_assignments.is_empty()
        || assignment.licensed_breakage.is_some()
    {
        bail!("researcher '{}' requires read_only_researcher authority, no delegation and no licensed breakage", assignment.id);
    }
    if assignment
        .runtime
        .is_some_and(|runtime| runtime != SupervisorRuntime::Codex)
    {
        bail!("researcher currently requires the Codex strict Linux read-only runtime");
    }
    Ok(())
}

pub(super) fn configure_researcher_command(
    command: ExternalAgentCommand,
    runtime: SupervisorRuntime,
) -> Result<ExternalAgentCommand> {
    if !cfg!(target_os = "linux") || runtime != SupervisorRuntime::Codex {
        bail!("researcher requires the Codex strict Linux read-only runtime");
    }
    if !command.worktree_control_exceptions.is_empty() {
        bail!("researcher cannot receive worktree control exceptions");
    }
    if command
        .agent_lifecycle
        .as_ref()
        .is_none_or(|identity| identity.role != "researcher")
    {
        bail!("researcher launch requires its own non-delegating lifecycle identity");
    }
    Ok(command.with_workspace_access(WorkspaceAccess::ReadOnly))
}

#[derive(Deserialize)]
struct ResearcherReport {
    #[serde(flatten)]
    report: OrchestratorReviewReport,
    read_only: bool,
    no_further_delegation: bool,
}

pub(super) fn read_researcher_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let contents = contents.context("missing descriptor-held researcher report")?;
    let parsed: ParsedReport<ResearcherReport> = parse_report_json(std::str::from_utf8(contents)?)
        .with_context(|| format!("invalid researcher report {}", display_path.display()))?;
    let report = parsed.report.report;
    if report.role != AgentRole::Researcher
        || !parsed.report.read_only
        || !parsed.report.no_further_delegation
        || !report.files_changed.is_empty()
        || !report.worker_reports.is_empty()
        || !report.audit_reports.is_empty()
        || !report.decomposition_completions.is_empty()
    {
        bail!("researcher report must attest read-only, non-delegating, zero-diff execution");
    }
    if report.status == ReviewStatus::Succeeded
        && (!report.commands_run.iter().any(|command| {
            command.status == ReviewStatus::Succeeded
                && command.exit_code == Some(0)
                && !command.timed_out
        }) || report.validation_results.is_empty()
            || report
                .validation_results
                .iter()
                .any(|result| result.status != ReviewStatus::Succeeded))
    {
        bail!("successful researcher report requires inspection commands and validation evidence");
    }
    Ok(ParsedReport {
        report,
        recovered: parsed.recovered,
    })
}

pub(super) fn enforce_researcher_zero_diff(report: &mut OrchestratorReviewReport) {
    if report.role == AgentRole::Researcher && !report.files_changed.is_empty() {
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "read-only researcher changed the observed candidate".to_string(),
            paths: report.files_changed.clone(),
        });
    }
}

pub(super) fn researcher_report_schema_value() -> Value {
    let mut schema = orchestrator_report_schema_value();
    schema["title"] = json!("ResearcherReport");
    schema["properties"]["role"] = json!({"type": "string", "const": "researcher"});
    for key in ["read_only", "no_further_delegation"] {
        schema["properties"][key] = json!({"type": "boolean", "const": true});
        schema["required"]
            .as_array_mut()
            .expect("report required fields")
            .push(json!(key));
    }
    for key in [
        "files_changed",
        "worker_reports",
        "audit_reports",
        "decomposition_completions",
    ] {
        schema["properties"][key]["maxItems"] = json!(0);
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authored_plan() -> Value {
        json!({
            "version": 1, "task": "inspect API without modifications", "max_depth": 3,
            "max_child_assignments": 2,
            "role_models": {"researcher": {"model": FRONTIER_PROFILE_MODEL, "reasoning_effort": "medium"}},
            "assignments": [{"id": "planner", "phase": "planning", "assigned_paths": ["src"],
                "child_assignments": [{"id": "research", "phase": "execution", "role": "researcher",
                    "role_category": "read_only_researcher", "runtime": "codex", "assigned_paths": ["src"]}]}]
        })
    }

    fn evidence() -> Value {
        json!({
            "id": "research", "role": "researcher", "read_only": true, "no_further_delegation": true,
            "assigned_paths": ["src"], "files_changed": [], "worker_reports": [], "audit_reports": [],
            "decomposition_completions": [], "accepted": true, "rejected": false, "status": "succeeded",
            "commands_run": [{"command": ["rg", "API", "src"], "cwd": ".", "exit_code": 0,
                "status": "succeeded", "timeout_seconds": 10, "duration_ms": 1, "timed_out": false}],
            "validation_results": [{"name": "API inspection", "command": ["rg", "API", "src"], "status": "succeeded"}]
        })
    }

    #[test]
    fn authored_researcher_round_trips_schedule_authority_and_model() -> Result<()> {
        let loaded = parse_supervisor_plan_with_consultant(&authored_plan().to_string())?;
        let assignment = &loaded.plan.assignments[1];
        assert_eq!(assignment.role, AgentRole::Researcher);
        assert_eq!(
            assignment.effective_role_category(),
            RoleCategory::ReadOnlyResearcher
        );
        assert!(assignment.worker_assignments.is_empty());
        assert_eq!(
            loaded.plan_metadata.assignment_schedule[1]
                .parent_assignment_id
                .as_deref(),
            Some("planner")
        );
        let normalized = supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )?;
        let reparsed = parse_supervisor_plan_with_consultant(&normalized.to_string())?;
        assert_eq!(reparsed.plan.assignments, loaded.plan.assignments);
        assert_eq!(
            reparsed.plan_metadata.assignment_schedule,
            loaded.plan_metadata.assignment_schedule
        );
        assert_eq!(
            effective_role_model_selection(&loaded.plan, AgentRole::Researcher)
                .model
                .as_deref(),
            Some(FRONTIER_PROFILE_MODEL)
        );
        assert_eq!(
            model_policy::role_default_phase(AgentRole::Researcher),
            Some(OrchestrationPhase::Planning)
        );
        assert_eq!(
            role_minimum_model_capability(AgentRole::Researcher),
            ModelCapabilityClass::GeneralJudgment
        );
        Ok(())
    }

    #[test]
    fn authored_researcher_refuses_delegation_wrong_authority_and_runtime() {
        for (key, value) in [
            ("role_category", json!("non_delegating_terminal_worker")),
            ("runtime", json!("fake")),
            ("runtime", json!("grok")),
            ("mechanical_duty", json!("run_preselected_command")),
            (
                "worker_assignments",
                json!([{"id": "nested", "role": "worker", "assigned_paths": ["src"]}]),
            ),
            (
                "child_assignments",
                json!([{"id": "nested", "assigned_paths": ["src"]}]),
            ),
        ] {
            let mut plan = authored_plan();
            plan["assignments"][0]["child_assignments"][0][key] = value;
            assert!(
                parse_supervisor_plan_with_consultant(&plan.to_string()).is_err(),
                "accepted {key}"
            );
        }
    }

    #[test]
    fn researcher_report_requires_attestations_zero_diff_and_evidence() -> Result<()> {
        let path = Path::new("researcher-report.json");
        let valid = evidence();
        let parsed = read_researcher_report(Some(valid.to_string().as_bytes()), path)?;
        assert_eq!(parsed.report.role, AgentRole::Researcher);
        for (key, value) in [
            ("read_only", json!(false)),
            ("no_further_delegation", json!(false)),
            ("role", json!("worker")),
            ("files_changed", json!(["src/lib.rs"])),
            ("commands_run", json!([])),
            ("validation_results", json!([])),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(
                read_researcher_report(Some(invalid.to_string().as_bytes()), path).is_err(),
                "accepted {key}"
            );
        }
        for key in ["read_only", "no_further_delegation"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(read_researcher_report(Some(missing.to_string().as_bytes()), path).is_err());
        }
        assert!(read_researcher_report(None, path).is_err());
        Ok(())
    }

    #[test]
    fn researcher_observed_changes_fail_even_within_claimed_scope() -> Result<()> {
        let mut report =
            read_researcher_report(Some(evidence().to_string().as_bytes()), Path::new("report"))?
                .report;
        enforce_researcher_zero_diff(&mut report);
        assert!(!report_failed(&report));
        report.files_changed.push(PathBuf::from("src/lib.rs"));
        enforce_researcher_zero_diff(&mut report);
        assert!(report_failed(&report));
        assert!(report.rejected);
        Ok(())
    }

    #[test]
    fn researcher_zero_diff_still_requires_parent_audit() -> Result<()> {
        let loaded = parse_supervisor_plan_with_consultant(&authored_plan().to_string())?;
        let report =
            read_researcher_report(Some(evidence().to_string().as_bytes()), Path::new("report"))?
                .report;
        assert!(parent_auditor_required(
            &loaded.plan.assignments[1],
            &report
        ));
        Ok(())
    }

    #[test]
    fn researcher_schema_agrees_with_parser_and_rejects_write_claims() -> Result<()> {
        let parsed =
            read_researcher_report(Some(evidence().to_string().as_bytes()), Path::new("report"))?;
        let mut wire = serde_json::to_value(parsed.report)?;
        wire["read_only"] = json!(true);
        wire["no_further_delegation"] = json!(true);
        let mut compiler = boon::Compiler::new();
        compiler.set_default_draft(boon::Draft::V2020_12);
        let schema_id = "https://example.invalid/researcher-report";
        compiler
            .add_resource(schema_id, researcher_report_schema_value())
            .unwrap();
        let mut schemas = boon::Schemas::new();
        let index = compiler.compile(schema_id, &mut schemas).unwrap();
        schemas.validate(&wire, index).unwrap();
        wire["files_changed"] = json!(["src/lib.rs"]);
        assert!(schemas.validate(&wire, index).is_err());
        assert!(
            read_researcher_report(Some(wire.to_string().as_bytes()), Path::new("report")).is_err()
        );
        codex_response_format_schema(researcher_report_schema_value())?;
        Ok(())
    }

    #[test]
    fn researcher_launch_is_read_only_and_non_delegating() -> Result<()> {
        let command = || {
            ExternalAgentCommand::codex(
                "codex",
                ".",
                "prompt",
                "events",
                "report",
                Duration::from_secs(10),
            )
            .with_agent_lifecycle(".", "researcher", "research-run", "research")
        };
        assert!(configure_researcher_command(command(), SupervisorRuntime::Fake).is_err());
        let configured = configure_researcher_command(command(), SupervisorRuntime::Codex);
        if cfg!(target_os = "linux") {
            let configured = configured?;
            assert_eq!(configured.workspace_access, WorkspaceAccess::ReadOnly);
            assert!(configured.worktree_control_exceptions.is_empty());
            let argv = crate::external_agent::command_argv(&configured);
            assert!(argv
                .windows(2)
                .any(|pair| pair == [OsStr::new("--disable"), OsStr::new("multi_agent")]));
        } else {
            assert!(configured.is_err());
        }
        Ok(())
    }

    // Integration owner supplies the reporting.rs whitelist. Keep this regression
    // active so an unintegrated branch cannot falsely claim end-to-end support.
    #[test]
    fn researcher_process_usage_preserves_distinct_role() -> Result<()> {
        let plan = parse_supervisor_plan_with_consultant(&authored_plan().to_string())?.plan;
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 2,
            total_tokens: 12,
        };
        let aggregation = role_usage_report(
            &plan,
            vec![RoleUsageSample {
                role: AgentRole::Researcher,
                lens_id: None,
                model: Some(FRONTIER_PROFILE_MODEL.to_string()),
                usage,
            }],
        )?;
        assert!(aggregation.reports.contains_key(&AgentRole::Researcher));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn researcher_strict_linux_boundary_refuses_workspace_writes() -> Result<()> {
        const CHILD_ENV: &str = "MACO_TEST_RESEARCHER_READ_ONLY_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert_eq!(fs::read_to_string("source.txt")?, "inspection input");
            assert!(fs::write("source.txt", "corrupted").is_err());
            assert!(fs::write("created.txt", "unauthorized").is_err());
            assert!(fs::create_dir("nested").is_err());
            return Ok(());
        }
        skip_without_containment!(ok);
        let workspace = tempfile::tempdir()?;
        fs::write(workspace.path().join("source.txt"), "inspection input")?;
        let command = configure_researcher_command(
            ExternalAgentCommand::codex(
                "codex",
                workspace.path(),
                workspace.path().join("prompt"),
                workspace.path().join("events"),
                workspace.path().join("report"),
                Duration::from_secs(10),
            )
            .with_agent_lifecycle(
                workspace.path(),
                "researcher",
                "research-run",
                "research",
            ),
            SupervisorRuntime::Codex,
        )?;
        assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
        let binary = std::env::current_exe()?;
        let profile = crate::process_runner::ExternalCodexProfile::read_only(&command.cwd)
            .with_visible_read_only_file(&binary);
        let result = run_process(ProcessSpec::direct(
            "researcher hostile write probe", &binary,
            ["--exact", "supervise::researcher::tests::researcher_strict_linux_boundary_refuses_workspace_writes"],
            &command.cwd, 4096,
        ).with_environment(EnvironmentMode::InheritAndSet(BTreeMap::from([(CHILD_ENV.to_string(), "1".to_string())])))
            .with_stdin(StdinMode::Null).with_timeout(Some(Duration::from_secs(30)))
            .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)))?;
        assert!(
            result.status.is_some_and(|status| status.success()),
            "{result:?}"
        );
        assert!(result.safety_evidence_verified());
        assert_eq!(
            fs::read_to_string(workspace.path().join("source.txt"))?,
            "inspection input"
        );
        assert!(!workspace.path().join("created.txt").exists());
        Ok(())
    }
}
