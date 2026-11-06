use super::*;

pub(super) fn run(
    case: &str,
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    template: &ExternalAgentRun,
    workers: &Mutex<Vec<WorkerReport>>,
    journal_worktree: Option<&Path>,
) -> Result<ExternalAgentRun> {
    let case = case.strip_prefix("managed-cycle-process-").unwrap();
    let identity = command.agent_lifecycle.as_ref().unwrap();
    assert!(command.codex_native_delegation_is_disabled());
    let mode;
    let report;
    let mut payload = json!({"case":case});
    if identity.task_id != "parent" {
        mode = "worker";
        report = serde_json::from_slice(template.output_last_message().unwrap())?;
        assert_eq!(command.worker_journal_artifacts.len(), 1);
        payload["journal"] = json!(command.worker_journal_artifacts[0].path);
        if case.starts_with("isolated-") {
            payload["journal_head"] = json!(current_head_oid(&command.cwd)?.to_string());
            if let Some(worktree) = journal_worktree {
                let binding = crate::safe_state::DirectoryBindingGuard::bind(worktree)?;
                payload["journal_binding"] = json!({
                    "worktree": worktree, "worktree_identity": binding.identity(),
                });
            }
        }
        payload["edit"] = json!(if identity.task_id == "worker" {
            "pub mod other;\npub fn first() -> u32 { 40 }\n"
        } else {
            "pub fn second() -> u32 { crate::first() + 2 }\n"
        });
    } else if command.codex_managed_worker_requests_enabled() {
        mode = "initial";
        assert!(command.worker_journal_artifacts.is_empty());
        report = json!({"version":1,"outcome":"yield_workers","run_id":identity.run_id,
            "parent_id":"parent","parent_attempt":1,"requests":[
                {"request_id":"r1","worker_id":"worker"},
                {"request_id":"r2","worker_id":"worker-two"}]});
    } else {
        mode = "final";
        assert!(command.codex_managed_readonly_continuation_enabled());
        assert!(command.worker_journal_artifacts.is_empty());
        let mut parent: OrchestratorReviewReport =
            serde_json::from_slice(template.output_last_message().unwrap())?;
        parent.worker_reports = workers.lock().unwrap().clone();
        parent.worker_reports.sort_by(|a, b| a.id.cmp(&b.id));
        parent.files_changed = vec!["src/lib.rs".into(), "src/other.rs".into()];
        if case == "isolated-misreported-paths" {
            parent.files_changed.clear();
        }
        parent.remaining_risk = "offline managed process fixture".into();
        parent.audit_reports.clear();
        parent.review_lens_aggregate = None;
        if case.ends_with("rejected-review") {
            parent.accepted = false;
            parent.rejected = true;
            parent.status = ReviewStatus::Failed;
        }
        if case == "isolated-collector-rejected" {
            parent.gate_denials.push(GateDenial::new(
                "self-authored-fixture",
                GateDenialReason::ClaimConflict,
                crate::gate_denial::VerifiedGateContext::new(
                    "parent",
                    crate::gate_denial::GateCheckSource::ClaimAcquisition,
                    ["src/lib.rs"],
                )?,
            )?);
            assert!(!report_failed(&parent));
        }
        let mut turn = super::parent_continuation_response::final_turn_for_test(command, &parent);
        match case {
            "forged-report" => turn["worker_report_refs"][0]["assignment_id"] = json!("foreign"),
            "isolated-wrong-digest" => {
                turn["worker_report_refs"][0]["capture_sha256"] = json!("0".repeat(64))
            }
            "isolated-swapped-references" => turn["worker_report_refs"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1),
            "isolated-missing-reference" => {
                turn["worker_report_refs"].as_array_mut().unwrap().pop();
            }
            "isolated-extra-reference" => {
                let extra = turn["worker_report_refs"][0].clone();
                turn["worker_report_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(extra);
            }
            "isolated-duplicate-reference" => {
                turn["worker_report_refs"][1] = turn["worker_report_refs"][0].clone()
            }
            "isolated-parent-payload" => {
                parent.worker_reports[0].commands_run[0].stdout = "parent substitution".into();
                turn["report"]["worker_reports"] = json!(parent.worker_reports);
            }
            _ => {}
        }
        report = json!({"version":2,"run_id":identity.run_id,"parent_id":"parent",
            "source_parent_attempt":1,"parent_attempt":2,"completed_worker_ids":["worker","worker-two"],
            "turn":turn});
    }
    payload["mode"] = json!(mode);
    payload["report"] = report;
    let run = crate::external_agent::managed_parent_fixture::run(command, cancellation, payload)?;
    assert!(run.scratch_quiescence_verified());
    assert!(run.stdout.target_launch_attempted);
    assert!(run.authenticated_app_server_evidence().is_some(), "{run:?}");
    if mode == "initial" && !matches!(case, "forged-identity" | "widened-request") {
        assert!(run.publishable, "{run:?}");
    }
    if mode == "final" && case == "isolated-tampered" {
        let worker = workers
            .lock()
            .unwrap()
            .iter()
            .find(|worker| worker.id == "worker")
            .context("fixture Worker report")?
            .commands_run
            .first()
            .context("fixture Worker command")?
            .cwd
            .clone();
        fs::write(worker.join("src/lib.rs"), "tampered after capture\n")?;
    }
    if mode == "final"
        && matches!(
            case,
            "isolated-worker-import-failure" | "isolated-parent-import-failure"
        )
    {
        let workspace = if case == "isolated-parent-import-failure" {
            command.cwd.clone()
        } else {
            workers
                .lock()
                .unwrap()
                .iter()
                .find(|worker| worker.id == "worker-two")
                .context("fixture second Worker")?
                .commands_run[0]
                .cwd
                .clone()
        };
        let boundary = crate::external_agent::bind_existing_managed_child_git_boundary(&workspace)?;
        // A real Git lock makes a later materialization fail without changing
        // the source snapshot or invalidating the verified process capture.
        fs::write(
            boundary.private_git_dir().join("index.lock"),
            b"fixture lock",
        )?;
    }
    if mode == "worker" {
        if case == "cancel-active-worker" && identity.task_id == "worker" {
            assert!(cancellation.is_cancelled());
            assert!(!run.publishable);
            assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
            return Ok(run);
        }
        assert!(run.publishable, "{run:?}");
        workers.lock().unwrap().push(serde_json::from_slice(
            run.output_last_message().context("fixture Worker report")?,
        )?);
        if case == "cancel-after-first" && identity.task_id == "worker" {
            cancellation.cancel();
        }
    }
    Ok(run)
}

pub(super) fn exercise(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    prepared: Box<PreparedChildAttempt<'_>>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    let case = case.strip_prefix("managed-cycle-process-").unwrap();
    // The fixture hand-builds the parent preflight. Mirror the production
    // preflight's pending token so terminal cleanup can detect double releases.
    outcome.claim_tokens.push(preflight.claim.token);
    let schemas = &context.dirs.schemas;
    if case == "isolated-initial-import-failure" {
        let destination = context
            .run_dir
            .join(&prepared.attempt_artifacts.raw_report_relative);
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(destination)?;
    }
    let result = super::managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        context,
        outcome,
        preflight,
        context.options.run_id.as_str(),
        1,
        prepared,
        &context.budget_policy,
        1,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
    );
    let observed = calls.lock().unwrap().clone();
    let budget = context.budget_ledger.report()?;
    assert_eq!(budget.active_reservations, 0);
    assert_eq!(budget.reserved.tokens, 0);
    if !matches!(
        case,
        "isolated-tampered" | "isolated-worker-import-failure" | "isolated-parent-import-failure"
    ) {
        assert_eq!(
            context.sync_store.snapshot()?,
            vec![preflight.claim.clone()]
        );
        assert!(
            outcome.release_errors.is_empty(),
            "{:?}",
            outcome.release_errors
        );
        assert_eq!(outcome.claim_tokens, vec![preflight.claim.token]);
        assert_eq!(
            planned_claim_releases(context.sync_store, &outcome.claim_tokens)?,
            vec![preflight.claim.clone()]
        );
    }
    context.manager.verify_write_execution_lease(
        &preflight.assignment.id,
        preflight.worktree_write_lease.as_ref().unwrap(),
    )?;
    assert_eq!(
        fs::read_to_string(context.repo.join("src/lib.rs"))?,
        "pub fn selected() {}\n"
    );
    match case {
        "isolated-initial-import-failure" => {
            let error = result.err().context("initial evidence refusal accepted")?;
            assert!(
                format!("{error:#}").contains("initial parent evidence import failed"),
                "{error:#}"
            );
            assert_eq!(
                crate::external_agent::bind_existing_managed_child_git_boundary(
                    &preflight.worktree.path
                )?
                .revalidate()?,
                preflight.child_base_head,
                "initial evidence refusal advanced the parent private ref"
            );
            assert_eq!(
                observed,
                ["parent"],
                "Workers dispatched before initial evidence import"
            );
            assert!(!outcome.authority_requires_quarantine());
            assert!(outcome.released_claims.is_empty());
            assert!(context
                .manager
                .list_managed_verified()?
                .iter()
                .all(|record| record.name != "worker" && record.name != "worker-two"));
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
        }
        "forged-identity" | "widened-request" => {
            assert!(result.is_err(), "invalid request accepted");
            assert_eq!(observed, ["parent"]);
        }
        "cancel-after-first" | "cancel-active-worker" => {
            assert!(result.is_err(), "cancelled cycle accepted");
            assert_eq!(observed, ["parent", "worker"]);
        }
        "widened-worker" => {
            let error = result.err().context("widened Worker edit accepted")?;
            assert!(
                format!("{error:#}").contains("outside its authored scope"),
                "{error:#}"
            );
            assert_eq!(observed, ["parent", "worker"]);
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
        }
        "isolated-wrong-digest"
        | "isolated-swapped-references"
        | "isolated-missing-reference"
        | "isolated-extra-reference"
        | "isolated-duplicate-reference"
        | "isolated-parent-payload" => {
            let error = format!(
                "{:#}",
                result.err().context("invalid Worker reference accepted")?
            );
            let expected = match case {
                "isolated-wrong-digest" => "digest mismatch",
                "isolated-swapped-references" => "in authored order",
                "isolated-missing-reference" | "isolated-extra-reference" => "expected 2",
                "isolated-duplicate-reference" => "duplicates Worker",
                "isolated-parent-payload" => "must omit worker_reports",
                _ => unreachable!(),
            };
            assert!(error.contains(expected), "{error}");
            assert_eq!(observed.len(), 4);
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(outcome.released_claims.len(), 2);
        }
        "forged-report" => {
            assert!(result.is_err(), "forged report accepted");
            assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
        }
        "isolated-rejected-review"
        | "isolated-collector-rejected"
        | "isolated-journal-sibling"
        | "isolated-journal-parent"
        | "isolated-journal-identity"
        | "isolated-journal-base" => {
            if case != "isolated-rejected-review" {
                let collected = result?;
                assert!(report_failed(&collected.attempt_report));
                let expected = if case == "isolated-collector-rejected" {
                    "self-assert supervisor-owned gate correction evidence"
                } else {
                    "worker 'worker' journal observation is not bound to the supervisor's assigned worktree identity and base HEAD"
                };
                assert!(
                    collected
                        .attempt_report
                        .findings
                        .iter()
                        .any(|finding| { finding.message.contains(expected) }),
                    "{:?}",
                    collected.attempt_report.findings
                );
                if case.starts_with("isolated-journal-") {
                    let reports = &collected.attempt_report.worker_reports;
                    assert_eq!(reports[0].id, "worker");
                    assert_eq!(reports[0].status, ReviewStatus::Failed);
                    assert_eq!(reports[1].id, "worker-two");
                    assert_eq!(reports[1].status, ReviewStatus::Succeeded);
                    assert!(!collected.attempt_report.findings.iter().any(|finding| {
                        finding
                            .message
                            .contains("worker 'worker-two' journal observation is not bound")
                    }));
                }
            } else {
                assert!(
                    format!("{:#}", result.err().context("rejected parent integrated")?)
                        .contains("integration is not authorized")
                );
            }
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/other.rs"))?,
                "pub fn other() {}\n"
            );
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                crate::external_agent::bind_existing_managed_child_git_boundary(
                    &preflight.worktree.path,
                )?
                .revalidate()?,
                preflight.child_base_head,
                "rejected parent private commit materialized"
            );
            assert_eq!(outcome.released_claims.len(), 2);
            for worker in ["worker", "worker-two"] {
                let path = context
                    .manager
                    .list_managed_verified()?
                    .into_iter()
                    .find(|record| record.name == worker)
                    .context("fixture Worker worktree")?
                    .path;
                assert_eq!(
                    current_head_oid(&path)?,
                    preflight.child_base_head,
                    "rejected Worker commit materialized"
                );
                assert_eq!(
                    crate::external_agent::bind_existing_managed_child_git_boundary(&path)?
                        .revalidate()?,
                    preflight.child_base_head,
                    "rejected Worker private commit materialized"
                );
            }
            assert!(
                !super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&budget)
                )
            );
        }
        "isolated-tampered" => {
            assert!(result.is_err(), "tampered candidate accepted");
            assert!(outcome.external_containment_failed);
            assert!(
                !outcome.usage_incomplete,
                "tamper regression must reach the settled final capture"
            );
            assert!(outcome
                .release_errors
                .iter()
                .all(|error| !error.contains("not active")));
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                context.sync_store.snapshot()?.len(),
                3,
                "drift must retain authority"
            );
        }
        "isolated-worker-import-failure" | "isolated-parent-import-failure" => {
            assert!(
                result.is_err(),
                "post-materialization refusal dropped its recovery owner"
            );
            assert!(outcome.external_containment_failed);
            assert!(!outcome.usage_incomplete);
            assert_eq!(outcome.released_claims.len(), 2);
            assert_eq!(
                context.sync_store.snapshot()?,
                vec![preflight.claim.clone()]
            );
            assert_eq!(outcome.claim_tokens, vec![preflight.claim.token]);
            assert!(
                outcome
                    .release_errors
                    .iter()
                    .any(|error| error.contains("Worker materialization started")),
                "{:?}",
                outcome.release_errors
            );
            assert!(outcome
                .release_errors
                .iter()
                .all(|error| !error.contains("not active")));
            assert!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?
                    .contains("pub fn first() -> u32 { 40 }")
            );
            assert!(
                fs::read_to_string(preflight.worktree.path.join("src/other.rs"))?
                    .contains("pub fn second() -> u32 { crate::first() + 2 }")
            );
            assert_eq!(
                crate::external_agent::bind_existing_managed_child_git_boundary(
                    &preflight.worktree.path
                )?
                .revalidate()?,
                preflight.child_base_head
            );
            for worker in ["worker", "worker-two"] {
                let path = context
                    .manager
                    .list_managed_verified()?
                    .into_iter()
                    .find(|record| record.name == worker)
                    .context("fixture Worker")?
                    .path;
                let head = crate::external_agent::bind_existing_managed_child_git_boundary(&path)?
                    .revalidate()?;
                assert_eq!(
                    head == preflight.child_base_head,
                    case == "isolated-worker-import-failure" && worker == "worker-two"
                );
                assert!(
                    context
                        .manager
                        .acquire_write_execution_lease(worker)
                        .is_err(),
                    "post-materialization refusal released the Worker lease"
                );
            }
            assert!(
                preflight.issue_nested_turn(1).is_err(),
                "spent turn replayed"
            );
        }
        "isolated-overlap" => {
            assert!(result.is_err(), "overlapping candidate accepted");
            assert!(!observed.iter().skip(1).any(|id| id == "parent"));
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
        }
        "happy"
        | "lost-response"
        | "rejected-review"
        | "isolated-happy"
        | "isolated-observed-journals"
        | "isolated-masked-rustup"
        | "isolated-misreported-paths"
        | "isolated-long-output" => {
            let collected = result?;
            assert!(
                collected.report_shape_problems.is_empty(),
                "{:?}",
                collected.report_shape_problems
            );
            assert!(collected.attempt_containment_verified);
            if case == "isolated-long-output" {
                for report in &collected.attempt_report.worker_reports {
                    let bytes = with_supervisor_artifacts(context.artifacts, |writer, _| {
                        writer.read_authenticated(
                            &PathBuf::from("evidence/incoming").join(format!("{}.json", report.id)),
                            MAX_SUPERVISOR_REPORT_BYTES,
                        )
                    })?;
                    let captured =
                        read_worker_report(Some(&bytes), Path::new("worker.json"))?.report;
                    assert_eq!(
                        *report, captured,
                        "accepted Worker report differs from the capture"
                    );
                    assert_eq!(
                        report.commands_run[0].stdout,
                        "captured Worker output\n".repeat(768)
                    );
                }
                let final_bytes = with_supervisor_artifacts(context.artifacts, |writer, _| {
                    writer.read_authenticated(
                        &collected.attempt_artifacts.raw_report_relative,
                        MAX_SUPERVISOR_REPORT_BYTES,
                    )
                })?;
                assert!(!String::from_utf8(final_bytes)?.contains("captured Worker output"));
            }
            if case == "isolated-misreported-paths" {
                assert_eq!(
                    collected.attempt_report.files_changed,
                    vec![PathBuf::from("src/lib.rs"), PathBuf::from("src/other.rs")]
                );
                assert!(collected
                    .attempt_report
                    .findings
                    .iter()
                    .any(|finding| finding.message.contains("using supervisor-inspected paths")));
            }
            if case.starts_with("isolated-") {
                assert_eq!(observed.len(), 4);
                assert_eq!(observed.first().unwrap(), "parent");
                assert_eq!(observed.last().unwrap(), "parent");
                let mut workers = observed[1..3].to_vec();
                workers.sort();
                assert_eq!(workers, ["worker", "worker-two"]);
            } else {
                assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            }
            assert_eq!(
                report_failed(&collected.attempt_report),
                case == "rejected-review",
                "{:?}",
                collected.attempt_report.findings
            );
            assert_eq!(collected._worker_journal_evidence.len(), 2);
            let candidate = fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?;
            assert!(candidate.contains("pub fn first() -> u32 { 40 }"));
            let second = fs::read_to_string(preflight.worktree.path.join("src/other.rs"))?;
            assert!(second.contains("pub fn second() -> u32 { crate::first() + 2 }"));
            assert_eq!(budget.consumed.tokens, 56);
            let worker_charges = budget
                .charges
                .iter()
                .filter(|charge| charge.role == AgentRole::Worker)
                .collect::<Vec<_>>();
            assert_eq!(worker_charges.len(), 2);
            assert_ne!(
                worker_charges[0].reservation_id,
                worker_charges[1].reservation_id
            );
            assert!(worker_charges.iter().all(|charge| charge.tokens == 14));
            assert!(!outcome.usage_incomplete);
            if case.starts_with("isolated-") {
                assert_combined_review_handoff(context, preflight, &collected)?;
                assert_eq!(outcome.released_claims.len(), 2);
                assert!(
                    !super::super::scheduler::nested_workers_lack_observed_usage(
                        context.plan,
                        Some(&budget)
                    )
                );
                let mut unverified = budget.clone();
                unverified
                    .dispatch_bindings
                    .iter_mut()
                    .filter(|b| b.invocation.assignment_id == "worker-two")
                    .for_each(|b| b.invocation_verified = false);
                assert!(super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&unverified)
                ));
                let mut missing = budget.clone();
                missing
                    .dispatch_bindings
                    .retain(|b| b.invocation.assignment_id != "worker-two");
                assert!(super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&missing)
                ));
                let combined = collected
                    .attempt_report
                    .validation_results
                    .iter()
                    .find(|v| v.name == "combined check")
                    .context("final parent did not run combined check")?;
                assert_eq!(combined.status, ReviewStatus::Succeeded);
            }
            assert!(
                preflight.issue_nested_turn(1).is_err(),
                "spent turn replayed"
            );
            if case == "rejected-review" {
                assert_eq!(
                    current_head_oid(&preflight.worktree.path)?,
                    preflight.child_base_head
                );
            }
        }
        _ => bail!("unknown contained parent fixture case"),
    }
    Ok(())
}

fn assert_combined_review_handoff(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    collected: &CollectedChildAttempt<'_>,
) -> Result<()> {
    let mut report = collected.attempt_report.clone();
    let candidate = super::review_handoff::capture_candidate(context, preflight, &mut report, 2)?;
    let expected_paths = vec![PathBuf::from("src/lib.rs"), PathBuf::from("src/other.rs")];
    assert_eq!(candidate.changed_paths, expected_paths);
    let transcript_path = &collected.attempt_artifacts.raw_stdout_relative;
    let (transcript, patch, manifest) =
        with_supervisor_artifacts(context.artifacts, |writer, _| {
            Ok((
                read_authenticated_review_transcript(writer, transcript_path)?,
                String::from_utf8(writer.read_authenticated(
                    Path::new("reports/parent.candidate.patch"),
                    REVIEW_LENS_REQUEST_LIMIT_BYTES,
                )?)?,
                serde_json::from_slice::<Value>(&writer.read_authenticated(
                    Path::new("reports/parent.candidate.json"),
                    MAX_SUPERVISOR_REPORT_BYTES,
                )?)?,
            ))
        })?;
    assert_eq!(manifest["changed_paths"], json!(expected_paths));
    let exact = crate::merge::capture_exact_base_worktree_with_write_lease(
        context.repo,
        &preflight.assignment.id,
        &preflight.assignment.assigned_paths,
        preflight.worktree_write_lease.as_ref().unwrap(),
        preflight.child_base_head,
    )?;
    assert_eq!(
        manifest["candidate_tree"],
        json!(exact.snapshot_tree.to_string())
    );
    assert!(patch.contains("+pub fn first() -> u32 { 40 }"));
    assert!(patch.contains("+pub fn second() -> u32 { crate::first() + 2 }"));
    let mut bindings = supervisor_review_lens_binding_material(
        &preflight.assignment,
        &report,
        Some(&candidate),
        None,
    )?;
    bindings.validation_bindings["worker_execution_evidence"] =
        with_supervisor_artifacts(context.artifacts, |writer, _| {
            super::review_handoff::worker_evidence(writer, &collected._worker_journal_evidence)
        })?;
    let output = serde_json::to_string(&report)?;
    let sources = crate::review::BoundedReviewLensRequestSources {
        child_transcript: &transcript,
        authoritative_transcript_path: transcript_path,
        diff: &patch,
        output_report: &output,
        bindings: &bindings,
    };
    assert_eq!(context.plan.review_lenses.len(), 3);
    for lens in &context.plan.review_lenses {
        let request = crate::review::build_bounded_review_lens_request(lens, sources)?;
        use crate::review::ReviewLensScopedInformation;
        match request.information {
            ReviewLensScopedInformation::BoundedFullChildTranscript {
                diff,
                output_report,
                bindings: received,
                ..
            } => {
                assert_eq!(diff, patch);
                assert_eq!(output_report, output);
                assert_eq!(received, bindings);
            }
            ReviewLensScopedInformation::DiffOnly { diff } => assert_eq!(diff, patch),
            ReviewLensScopedInformation::OutputReportOnly { output_report } => {
                assert_eq!(output_report, output);
            }
            other => bail!("unexpected review handoff: {other:?}"),
        }
    }
    Ok(())
}

#[test]
fn managed_parent_process_two_workers_edit_and_bind_observed_journals() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-happy")
}

#[test]
fn managed_parent_process_duplicate_receipt_executes_each_worker_once() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-lost-response")
}

#[test]
fn managed_parent_process_refuses_forged_identity_and_widened_request() -> Result<()> {
    for case in ["forged-identity", "widened-request"] {
        super::nested_driver_tests::driver_fixture(&format!("managed-cycle-process-{case}"))?;
    }
    Ok(())
}

#[test]
fn managed_parent_process_cancellation_prevents_second_worker() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-cancel-after-first")
}

#[test]
fn managed_parent_process_cancellation_drains_active_worker_and_descendant() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-cancel-active-worker")
}

#[test]
fn managed_parent_process_refuses_substituted_worker_report() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-forged-report")
}

#[test]
fn managed_parent_process_refuses_worker_edits_outside_authored_scope() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-widened-worker")
}

#[test]
fn managed_parent_process_rejected_parent_review_cannot_accept_workers() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-rejected-review")
}

#[test]
fn managed_parent_process_isolated_final_sees_combined_candidate_and_complete_diagnostics(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-happy")
}

#[test]
fn managed_parent_process_isolated_observed_journals_reach_all_review_scopes() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-observed-journals")
}

#[test]
fn managed_parent_process_isolated_refuses_journal_bound_to_sibling_or_parent() -> Result<()> {
    for binding in ["sibling", "parent"] {
        super::nested_driver_tests::driver_fixture(&format!(
            "managed-cycle-process-isolated-journal-{binding}"
        ))?;
    }
    Ok(())
}

#[test]
fn managed_parent_process_isolated_refuses_wrong_journal_identity_or_base() -> Result<()> {
    for binding in ["identity", "base"] {
        super::nested_driver_tests::driver_fixture(&format!(
            "managed-cycle-process-isolated-journal-{binding}"
        ))?;
    }
    Ok(())
}

#[test]
fn managed_parent_process_isolated_combined_check_survives_masked_rustup_shim() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-masked-rustup")
}

#[test]
fn managed_parent_process_isolated_rejection_discards_tentative_candidate() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-rejected-review")
}

#[test]
fn managed_parent_process_isolated_collector_rejection_discards_without_worker_commits(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-collector-rejected")
}

#[test]
fn managed_parent_process_isolated_refuses_post_capture_tampering() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-tampered")
}

#[test]
fn managed_parent_process_isolated_refuses_overlapping_candidate_paths() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-overlap")
}

#[test]
fn managed_parent_process_isolated_uses_corrected_final_report_paths() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-misreported-paths")
}

#[test]
fn managed_parent_process_isolated_worker_import_failure_retains_recovery() -> Result<()> {
    super::nested_driver_tests::driver_fixture(
        "managed-cycle-process-isolated-worker-import-failure",
    )
}

#[test]
fn managed_parent_process_isolated_parent_import_rejection_retains_recovery() -> Result<()> {
    super::nested_driver_tests::driver_fixture(
        "managed-cycle-process-isolated-parent-import-failure",
    )
}

#[test]
fn managed_parent_process_isolated_initial_evidence_refusal_precedes_worker_dispatch() -> Result<()>
{
    super::nested_driver_tests::driver_fixture(
        "managed-cycle-process-isolated-initial-import-failure",
    )
}

#[test]
fn managed_parent_process_isolated_long_worker_output_reaches_acceptance_intact() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-long-output")
}

#[test]
fn managed_parent_process_isolated_refuses_invalid_capture_references_and_parent_payloads(
) -> Result<()> {
    for case in [
        "wrong-digest",
        "swapped-references",
        "missing-reference",
        "extra-reference",
        "duplicate-reference",
        "parent-payload",
    ] {
        super::nested_driver_tests::driver_fixture(&format!(
            "managed-cycle-process-isolated-{case}"
        ))?;
    }
    Ok(())
}
