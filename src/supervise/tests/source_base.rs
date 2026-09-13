#[cfg(target_os = "linux")]
use super::*;

#[cfg(target_os = "linux")]
#[test]
fn authenticated_source_head_binds_real_child_base_at_admission() {
    skip_without_containment!();
    for scenario in ["different_primary", "equal_head", "changed_after_gate"] {
        let (temp, repo) = injected_repository();
        let primary_a = current_head_oid(&repo).expect("initial primary head");
        fs::write(repo.join("README.md"), "authenticated PR head B\n")
            .expect("write source head fixture");
        commit_injected_repository(&repo, "source head B");
        let source_b = current_head_oid(&repo).expect("source head B");
        let expected = source_b;
        if scenario == "different_primary" {
            run_injected_git(&repo, &["reset", "--hard", &primary_a.to_string()]);
        }
        let assignment = injected_assignment(false);
        let plan = injected_plan(assignment.clone(), 0);
        let plan_file = temp.path().join("source-base-plan.json");
        fs::write(
            &plan_file,
            serde_json::to_vec_pretty(&plan).expect("serialize supervisor plan"),
        )
        .expect("write supervisor plan");
        let run_id = RunId::new(format!("source-base-{}", scenario.replace('_', "-")))
            .expect("scenario run id");
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file,
            run_id: run_id.clone(),
            parent_node: None,
            codex_bin: PathBuf::from("unused-injected-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(injected_machine_global_retention(temp.path())),
        };
        let source_dispatch_started = AtomicBool::new(false);
        let cancellation_observed = AtomicBool::new(false);
        let mut before_dispatch = |_plan: &SupervisorPlan| {
            if scenario == "changed_after_gate" {
                fs::write(repo.join("README.md"), "primary head C\n")
                    .expect("write concurrent primary change");
                commit_injected_repository(&repo, "primary head C after admission");
            }
            Ok(None)
        };
        let mut invocations = 0_usize;
        let mut runner = |command: &ExternalAgentCommand, _cancel: &ProcessCancellation| {
            invocations += 1;
            assert_eq!(
                current_head_oid(&command.cwd).expect("actual child execution head"),
                expected,
                "model dispatch must execute from authenticated source head"
            );
            if command
                .output_last_message
                .to_string_lossy()
                .contains("review-auditor")
            {
                let child = injected_child_report(&assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
            } else {
                fs::write(command.cwd.join("README.md"), "child candidate\n")
                    .expect("write injected candidate");
                let mut child = injected_child_report(&assignment);
                child.files_changed = vec![PathBuf::from("README.md")];
                write_injected_json(&command.output_last_message, &child);
            }
            injected_verified_run(command)
        };
        let cascade = run_supervisor_plan_file_cascade_with_runner_and_gate_for_autopilot(
            options,
            &run_id,
            None,
            &cancellation_observed,
            AutopilotSourceDispatchBinding {
                started: &source_dispatch_started,
                expected_head: Some(expected),
            },
            &mut before_dispatch,
            &mut runner,
        )
        .expect("finalize bound source supervisor run");
        if scenario == "equal_head" {
            assert!(
                invocations > 0,
                "equal source/base must reach supervised runner"
            );
            assert!(cascade
                .source_report
                .gate_denials
                .iter()
                .all(|denial| denial.context.owner != "source_head_not_execution_base"));
        } else {
            assert_eq!(invocations, 0, "{scenario} dispatched a model");
            assert!(!cascade.source_report.success);
            assert!(cascade.source_report.commands_run.is_empty());
            assert!(cascade.source_report.gate_denials.iter().any(|denial| {
                denial.context.owner == "source_head_not_execution_base"
                    && denial.context.source == GateCheckSource::ValidationBinding
                    && matches!(
                        denial.reason,
                        GateDenialReason::MergeRemediation {
                            blocker: GateApplyBlocker::StaleBase
                        }
                    )
            }));
            assert!(!cascade.generated_follow_up_dispatch_performed());
        }
    }
}
