//! Consumer-level tests for the two-phase inbox PR repair flow (#90).

use super::super::review_loop::{
    DispositionDecision, FrozenReviewSnapshot, RequiredCheck, ReviewLoopPhase, ReviewLoopPolicy,
    ReviewLoopState, TrustedActorBinding, TrustedActorIdentity, TrustedActorRole,
};
use super::super::review_loop_entry::{
    compact_independent_auditor_selection, independent_auditor_stable_id,
    select_critical_independent_auditor,
};
use super::super::review_policy_input::BoundReviewPolicy;
use super::super::review_repair_evidence::{
    RepairDispositionAuditorFeedbackVerdict, RepairDispositionAuditorOutput,
};
use super::super::{
    DuplicateDetectionResult, GithubCheckSummary, GithubPrCandidate, GithubPrSourceTrust,
    GithubReviewFeedbackSummary, InboxActionPolicy, InboxConfig, InboxItem, InboxItemKind,
    InboxPermissionMode, InboxSourceProvider, InboxSourceSnapshotBinding,
    IndependentAuditRunnerResult, PrivacyScanResult,
};
use super::*;
use crate::artifacts::{
    state_auth::sha256_hex, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily,
};
use crate::autopilot::{
    AutopilotArtifactPaths, AutopilotAttemptSummary, AutopilotCheckStatus, AutopilotFinalReport,
    AutopilotForgeMode, AutopilotPlanSummary, AutopilotProfile, AutopilotProfileBindingReport,
    AutopilotProfileBindingStatus, AutopilotPublishMode, AutopilotReportsCreated,
    AutopilotRunStatus, AutopilotSafetyReport, AutopilotValidationStatus,
    AutopilotValidationSummary,
};
use crate::llm::RedactionSummary;
use crate::merge::{
    candidate_validation_binding, raw_candidate_snapshot_diff, CandidateValidationBinding,
    ValidationReport, ValidationStatus,
};
use crate::optimizer::merge_authority::{
    AgentIdentity, LensDecision, LensVerdict, MergeActor, ProducerFingerprint, SessionId,
};
use crate::orchestrator::RunId;
use crate::publication;
use crate::publication::forge_transport::{
    FakeForgeTransport, ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus, ForgeItem,
    ForgeItemKind, ForgeObservation, ForgeObservationRequest, ForgeRepository, ForgeReview,
    ForgeReviewState, ForgeTimestamp, ProviderObjectId, ProviderObjectKind,
    PullRequestReviewSnapshot, ReportedActorKind,
};
use crate::publication::pr_original_update::OriginalPrUpdateReceipt;
use crate::review::ReviewerMode;
use crate::safe_state::SafeRoot;
use crate::supervise::{
    AgentRole, AutonomyKpiReport, ReviewStatus, SupervisorFinalReport, SupervisorRunLifecycle,
    SupervisorRuntime,
};
use crate::worktree::{WorktreeCreateOptions, WorktreeManager};
use anyhow::{bail, Context, Result};
use git2::{Oid, Repository, Signature};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;

fn init_git_abc_candidate() -> (TempDir, Oid, Oid, Oid, CandidateValidationBinding, String) {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init");
    let repo = Repository::open(&repo_path).expect("open");
    let sig = Signature::now("maco test", "maco-test@example.invalid").expect("sig");
    fs::write(repo_path.join("base.txt"), "base\n").expect("write base");
    let mut index = repo.index().expect("index");
    index.add_path(Path::new("base.txt")).expect("add");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let pr_base = repo
        .commit(Some("refs/heads/main"), &sig, &sig, "pr base A", &tree, &[])
        .expect("commit A");
    fs::write(repo_path.join("base.txt"), "pr head\n").expect("write B");
    index = repo.index().expect("index");
    index.add_path(Path::new("base.txt")).expect("add");
    index.write().expect("write");
    let head_tree_id = index.write_tree().expect("tree");
    let head_tree = repo.find_tree(head_tree_id).expect("find tree");
    let pr_base_commit = repo.find_commit(pr_base).expect("A");
    let prior_head = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "pr head B",
            &head_tree,
            &[&pr_base_commit],
        )
        .expect("commit B");
    fs::write(repo_path.join("base.txt"), "repaired\n").expect("write C");
    index = repo.index().expect("index");
    index.add_path(Path::new("base.txt")).expect("add");
    index.write().expect("write");
    let repair_tree_id = index.write_tree().expect("tree");
    let repair_tree = repo.find_tree(repair_tree_id).expect("find tree");
    let prior_head_commit = repo.find_commit(prior_head).expect("B");
    let candidate = repo
        .commit(
            Some("HEAD"),
            &sig,
            &sig,
            "repair C",
            &repair_tree,
            &[&prior_head_commit],
        )
        .expect("commit C");
    let record = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "repair-agent".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("worktree");
    let raw_diff =
        raw_candidate_snapshot_diff(&repo, &record.path, prior_head, candidate).expect("diff");
    let binding = candidate_validation_binding(
        &crate::merge::WorktreeMergeMetadata {
            agent_id: "repair-agent".to_string(),
            worktree_path: record.path.clone(),
            branch: record.branch.clone(),
            primary_repo_root: repo_path.clone(),
            primary_head: Some(prior_head.to_string()),
            agent_head: Some(candidate.to_string()),
            merge_base: Some(prior_head.to_string()),
            base_matches_primary: Some(false),
        },
        &raw_diff,
    )
    .expect("binding");
    (temp, pr_base, prior_head, candidate, binding, record.branch)
}

fn passed_report(name: &str) -> ValidationReport {
    ValidationReport {
        name: name.to_string(),
        status: ValidationStatus::Passed,
        message: None,
        paths: vec![PathBuf::from("base.txt")],
    }
}

fn failed_report(name: &str) -> ValidationReport {
    ValidationReport {
        name: name.to_string(),
        status: ValidationStatus::Failed,
        message: Some("earlier attempt failed".to_string()),
        paths: vec![PathBuf::from("base.txt")],
    }
}

fn skipped_report(name: &str) -> ValidationReport {
    ValidationReport {
        name: name.to_string(),
        status: ValidationStatus::Skipped,
        message: None,
        paths: vec![PathBuf::from("base.txt")],
    }
}

fn assert_validation_refused_cause(store: RepairValidationEvidenceStore, cause: &str) {
    let error = validation_bundle_for_final_candidate(&store)
        .expect_err("incomplete validation evidence must refuse");
    assert!(
        error.to_string().contains(cause),
        "expected cause {cause:?} in {error}"
    );
}

#[test]
fn validation_bundle_refuses_empty_or_incomplete_reports_and_retains_all_passed() {
    let (_temp, _a, prior_head, candidate, binding, _branch) = init_git_abc_candidate();
    assert_ne!(prior_head, candidate);
    assert_validation_refused_cause(
        RepairValidationEvidenceStore {
            candidate_binding: binding.clone(),
            reports: Vec::new(),
        },
        "empty report set",
    );
    assert_validation_refused_cause(
        RepairValidationEvidenceStore {
            candidate_binding: binding.clone(),
            reports: vec![failed_report("unit")],
        },
        "non-passed report 'unit'",
    );
    assert_validation_refused_cause(
        RepairValidationEvidenceStore {
            candidate_binding: binding.clone(),
            reports: vec![passed_report("unit"), failed_report("ci")],
        },
        "non-passed report 'ci'",
    );
    assert_validation_refused_cause(
        RepairValidationEvidenceStore {
            candidate_binding: binding.clone(),
            reports: vec![passed_report("unit"), skipped_report("lint")],
        },
        "non-passed report 'lint'",
    );
    let passed_reports = vec![passed_report("unit"), passed_report("lint")];
    let bound = validation_bundle_for_final_candidate(&RepairValidationEvidenceStore {
        candidate_binding: binding.clone(),
        reports: passed_reports.clone(),
    })
    .expect("all-passed evidence");
    assert_eq!(bound.binding(), &binding);
    let bound_reports = bound.evidence().reports();
    assert_eq!(bound_reports.len(), passed_reports.len());
    assert!(bound_reports
        .iter()
        .all(|report| report.status == ValidationStatus::Passed));
    assert!(passed_reports.iter().all(|report| {
        bound_reports
            .iter()
            .any(|bound_report| bound_report.name == report.name)
    }));
}

#[test]
fn repair_producer_fingerprint_matches_authenticated_execution_record() {
    let (temp, _a, prior_head, candidate, binding, _branch) = init_git_abc_candidate();
    let execution = RepairProducerExecutionRecord {
        agent_id: "repair-agent".to_string(),
        supervisor_run_id: "sup-run".to_string(),
        child_autopilot_run_id: "auto-child".to_string(),
        model_label: "codex".to_string(),
    };
    let producer =
        repair_producer_fingerprint(temp.path().join("repo").as_path(), &binding, &execution)
            .expect("producer");
    assert_eq!(producer.actor.agent.stable_id, "repair-agent");
    assert_eq!(producer.actor.session.id, "auto-child");
    assert_eq!(producer.actor.model_label, "codex");
    assert!(!producer.commit_authors.is_empty());
    let wrong = ProducerFingerprint {
        actor: MergeActor {
            agent: AgentIdentity {
                stable_id: "other-agent".to_string(),
            },
            session: SessionId {
                id: "auto-child".to_string(),
            },
            model_label: "codex".to_string(),
        },
        commit_authors: producer.commit_authors.clone(),
        commit_committers: producer.commit_committers.clone(),
    };
    assert_ne!(producer, wrong);
    assert_eq!(
        binding.primary_head.as_deref(),
        Some(prior_head.to_string().as_str())
    );
    assert_eq!(
        binding.merge_base.as_deref(),
        Some(prior_head.to_string().as_str())
    );
    assert_eq!(
        binding.agent_head.as_deref(),
        Some(candidate.to_string().as_str())
    );
}

fn test_update_receipt(
    candidate_oid: &str,
    binding: CandidateValidationBinding,
) -> OriginalPrUpdateReceipt {
    let repository = ForgeRepository::new(
        "github",
        "github.example/acme/repo",
        ProviderObjectId::new("github", ProviderObjectKind::Repository, "R_test").expect("repo id"),
    )
    .expect("repository");
    OriginalPrUpdateReceipt {
        version: 1,
        repository,
        pull_request_number: 90,
        pull_request_id: ProviderObjectId::new("github", ProviderObjectKind::Item, "PR_90")
            .expect("pr id"),
        remote_ref: "refs/heads/main".to_string(),
        previous_oid: "b".repeat(40),
        updated_oid: candidate_oid.to_string(),
        grant_raw_sha256: "c".repeat(64),
        candidate_binding: binding,
        validation_sha256: "d".repeat(64),
    }
}

#[test]
fn pending_admission_journal_append_is_idempotent_for_same_digest() {
    let (temp, pr_base, prior_head, candidate, binding, branch) = init_git_abc_candidate();
    let repo = temp.path().join("repo");
    let execution = RepairProducerExecutionRecord {
        agent_id: "repair-agent".to_string(),
        supervisor_run_id: "sup-run".to_string(),
        child_autopilot_run_id: "auto-child".to_string(),
        model_label: "codex".to_string(),
    };
    let producer = repair_producer_fingerprint(&repo, &binding, &execution).expect("producer");
    let run_id = RunId::new("repair-idempotent-pending").expect("run id");
    let mut pending = PendingRepairBinding {
        version: PENDING_FORMAT_VERSION,
        inbox_run_id: run_id.as_str().to_string(),
        item_index: 1,
        autopilot_run_id: "auto-1".to_string(),
        review_policy_file: PathBuf::from("/tmp/unused-policy.json"),
        provider_repository_id: "node:sha256:test-repo".to_string(),
        pr_number: 90,
        source_snapshot_sha256: "0".repeat(64),
        raw_policy_sha256: "1".repeat(64),
        policy_sha256: "2".repeat(64),
        prior_state_sha256: "3".repeat(64),
        prior_snapshot_sha256: "4".repeat(64),
        prior_head_oid: prior_head.to_string(),
        prior_base_oid: pr_base.to_string(),
        candidate_binding: binding,
        from_branch: branch,
        repair_producer: producer,
        verified_proof_sha256: "5".repeat(64),
        validation_evidence_sha256: "6".repeat(64),
        pending_admission_digest: String::new(),
        repair_execution: execution,
    };
    pending.pending_admission_digest = pending_binding_digest(&pending).expect("digest");
    persist_pending_binding(&repo, &pending).expect("first persist");
    persist_pending_binding(&repo, &pending).expect("second persist");
    let authenticator = repository_auth_writer(&repo)
        .expect("auth")
        .into_authenticator()
        .expect("authenticator");
    let journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&pending.provider_repository_id, pending.pr_number).expect("id"),
    )
    .expect("journal");
    let pending_records = journal
        .records()
        .iter()
        .filter(|record| record.phase == PHASE_PENDING)
        .count();
    assert_eq!(pending_records, 1);
    assert_ne!(pr_base, prior_head);
    assert_ne!(prior_head, candidate);
}

#[test]
fn resume_replays_completed_transition_without_second_update() {
    let (temp, pr_base, prior_head, candidate, binding, branch) = init_git_abc_candidate();
    let repo = temp.path().join("repo");
    let run_id = RunId::new("repair-replay-complete").expect("run id");
    let execution = RepairProducerExecutionRecord {
        agent_id: "repair-agent".to_string(),
        supervisor_run_id: "sup-run".to_string(),
        child_autopilot_run_id: "auto-child".to_string(),
        model_label: "codex".to_string(),
    };
    let producer = repair_producer_fingerprint(&repo, &binding, &execution).expect("producer");
    let mut pending = PendingRepairBinding {
        version: PENDING_FORMAT_VERSION,
        inbox_run_id: run_id.as_str().to_string(),
        item_index: 1,
        autopilot_run_id: "auto-1".to_string(),
        review_policy_file: PathBuf::from("/tmp/unused-policy.json"),
        provider_repository_id: "node:sha256:test-repo".to_string(),
        pr_number: 90,
        source_snapshot_sha256: "0".repeat(64),
        raw_policy_sha256: "1".repeat(64),
        policy_sha256: "2".repeat(64),
        prior_state_sha256: "3".repeat(64),
        prior_snapshot_sha256: "4".repeat(64),
        prior_head_oid: prior_head.to_string(),
        prior_base_oid: pr_base.to_string(),
        candidate_binding: binding,
        from_branch: branch,
        repair_producer: producer,
        verified_proof_sha256: "5".repeat(64),
        validation_evidence_sha256: "6".repeat(64),
        pending_admission_digest: String::new(),
        repair_execution: execution,
    };
    pending.pending_admission_digest = pending_binding_digest(&pending).expect("digest");
    persist_pending_binding(&repo, &pending).expect("persist pending");
    let receipt = test_update_receipt(&candidate.to_string(), pending.candidate_binding.clone());
    record_update_receipt(&repo, &pending, &receipt).expect("record update");
    record_advanced(&repo, &pending, "9".repeat(64), "2026-08-16T02:00:00Z")
        .expect("record advanced");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "repair-test",
    )
    .expect("writer");
    super::super::write_private_artifact_json(&mut writer, "item-1-pending-repair.json", &pending)
        .expect("artifact");
    super::super::write_private_artifact_json(
        &mut writer,
        "final-report.json",
        &serde_json::json!({"success": true, "run_id": run_id.as_str()}),
    )
    .expect("final report");
    writer
        .finalize("final-report.json", false)
        .expect("finalize");
    let apply_calls = AtomicUsize::new(0);
    let mut apply = |_opts: crate::publication::pr_original_update::PrOriginalUpdateOptions,
                     _evidence: crate::merge::ValidationEvidenceBundle| {
        apply_calls.fetch_add(1, Ordering::SeqCst);
        Ok(receipt.clone())
    };
    let mut observe = |_repo: &Path, _policy: &BoundReviewPolicy, _pr: u64, _head: &str| {
        panic!("observe must not run for completed replay");
    };
    let report = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
    .expect("resume replay");
    assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.status, "replayed_source_bound_completion");
    assert_eq!(
        report.updated_head_oid.as_deref(),
        Some(candidate.to_string().as_str())
    );
}

fn hashed_id(kind: ProviderObjectKind, raw: &[u8]) -> ProviderObjectId {
    ProviderObjectId::new("github", kind, format!("node:sha256:{}", sha256_hex(raw)))
        .expect("hashed github id")
}

fn local_source_revalidator(repo: &Path, item: &InboxItem) -> Result<()> {
    item.source_snapshot.validate()?;
    let git = Repository::open(repo).context("open source repo")?;
    let origin = git.find_remote("origin").context("origin remote")?;
    let url = origin.url().context("origin url")?;
    let (host, selector) = publication::canonical_github_source_repository(url)?;
    if host != item.source_snapshot.repository_host()
        || selector != item.source_snapshot.repository_selector()
    {
        bail!("source selector does not match canonical origin");
    }
    let common = SafeRoot::open_existing(git.commondir()).context("bind common dir")?;
    let identity = publication::external_source_repository_identity(
        common.identity().device,
        common.identity().file,
    );
    if identity != item.source_snapshot.repository_identity() {
        bail!("source identity does not match local repository");
    }
    Ok(())
}

fn captured_audit_runner(
    raw: &[u8],
) -> impl FnMut(&crate::external_agent::ExternalAgentCommand) -> IndependentAuditRunnerResult + '_ {
    let report_sha256 = sha256_hex(raw);
    let raw = raw.to_vec();
    move |_command| IndependentAuditRunnerResult {
        raw_output: Some(raw.clone()),
        report_sha256: Some(report_sha256.clone()),
        exit_code: Some(0),
        duration_ms: 1,
        timed_out: false,
        safely_executed: true,
        publishable: true,
        succeeded: true,
        scratch_quiescence_verified: true,
        error: None,
    }
}

fn counting_audit_runner<'a>(
    raw: &'a [u8],
    calls: &'a AtomicUsize,
) -> impl FnMut(&crate::external_agent::ExternalAgentCommand) -> IndependentAuditRunnerResult + 'a {
    let mut inner = captured_audit_runner(raw);
    move |command| {
        calls.fetch_add(1, Ordering::SeqCst);
        inner(command)
    }
}

fn accepted_auditor_output(
    task: &super::super::review_repair_evidence::RepairDispositionAuditTask,
    model: &str,
) -> RepairDispositionAuditorOutput {
    RepairDispositionAuditorOutput {
        version: 1,
        task_digest_sha256: task.task_digest_sha256.clone(),
        prior_snapshot_sha256: task.prior_snapshot_sha256.clone(),
        prior_head_oid: task.prior_head_oid.clone(),
        candidate_binding: task.candidate_binding.clone(),
        feedback: task
            .feedback_inventory
            .iter()
            .map(|item| RepairDispositionAuditorFeedbackVerdict {
                feedback: item.identity.clone(),
                decision: DispositionDecision::Addressed,
                rationale: "independently verified in candidate diff".to_string(),
            })
            .collect(),
        accepted: true,
        lenses: vec![
            LensVerdict {
                lens_id: "diff".to_string(),
                model_label: model.to_string(),
                framing: "adversarial-diff".to_string(),
                information_scope: "diff-only".to_string(),
                decision: LensDecision::Accept,
            },
            LensVerdict {
                lens_id: "feedback".to_string(),
                model_label: model.to_string(),
                framing: "feedback-map".to_string(),
                information_scope: "feedback-only".to_string(),
                decision: LensDecision::Accept,
            },
        ],
        summary: "accepted exact repair candidate".to_string(),
        no_further_delegation: true,
        read_only: true,
    }
}

fn supervisor_report(run_id: &RunId, repo: &Path) -> SupervisorFinalReport {
    SupervisorFinalReport {
        version: 1,
        run_id: run_id.clone(),
        role: AgentRole::Supervisor,
        repo: repo.to_path_buf(),
        plan_file: PathBuf::from("plan.json"),
        run_dir: PathBuf::from(".maco/supervise/runs").join(run_id.as_str()),
        runtime: SupervisorRuntime::Fake,
        publishable: true,
        success: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        run_lifecycle: SupervisorRunLifecycle::Finalized,
        evidence_only_reaudit: None,
        assigned_paths: vec![PathBuf::from("base.txt")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: Vec::new(),
        semantic_intent_tokens: Vec::new(),
        role_economics_profile: None,
        run_budget: None,
        role_usage: Default::default(),
        review_lens_usage: Vec::new(),
        review_lens_total_usage: None,
        review_lens_total_cost_usd: None,
        total_usage: None,
        total_cost_usd: None,
        usage_complete: false,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        sandbox_denials: Vec::new(),
        gate_denials: Vec::new(),
        pre_action_review_metrics: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        autonomy_kpis: AutonomyKpiReport::default(),
        files_changed: vec![PathBuf::from("base.txt")],
        validation_results: Vec::new(),
        findings: Vec::new(),
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        generated_follow_up_tasks: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        breaker_trip: None,
        orchestrator_reports: Vec::new(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        remaining_risk: "none".to_string(),
        next_safe_action: "none".to_string(),
        executable: None,
    }
}

fn autopilot_report(
    repo: &Path,
    run_id: &RunId,
    agent_id: &str,
    binding: CandidateValidationBinding,
    reports: Vec<ValidationReport>,
) -> AutopilotFinalReport {
    AutopilotFinalReport {
        version: 1,
        run_id: run_id.clone(),
        status: AutopilotRunStatus::Succeeded,
        success: true,
        attempt_count: 1,
        repair_attempts_used: 0,
        max_repair_attempts: 3,
        artifacts: AutopilotArtifactPaths {
            plan: PathBuf::from("plan.json"),
            supervisor_report: PathBuf::from("supervisor.json"),
            pr_report: PathBuf::from("pr.json"),
            review_report: PathBuf::from("review.json"),
            final_report: PathBuf::from("final.json"),
        },
        reports_created: AutopilotReportsCreated {
            plan: true,
            supervisor_report: true,
            pr_report: false,
            review_report: false,
            final_report: true,
        },
        plan: AutopilotPlanSummary {
            title: "repair".to_string(),
            assigned_paths: vec![PathBuf::from("base.txt")],
            path_proposal: Default::default(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            forge_mode: AutopilotForgeMode::Fake,
            reviewer_mode: ReviewerMode::Fake,
            publish_mode: AutopilotPublishMode::DraftOnly,
        },
        profile_binding: AutopilotProfileBindingReport {
            version: 1,
            status: AutopilotProfileBindingStatus::NotDispatched,
            configuration_status: AutopilotProfileBindingStatus::NotDispatched,
            requested: AutopilotProfile::default(),
            effective: None,
            execution: None,
            failure: None,
        },
        safety: AutopilotSafetyReport {
            refused: false,
            gate_denials: Vec::new(),
        },
        authority_plan: None,
        gate_denials: Vec::new(),
        supervisor: Some(supervisor_report(run_id, repo)),
        primary_worktree_untouched: true,
        validation: AutopilotValidationSummary {
            status: AutopilotValidationStatus::Passed,
            reports: reports.clone(),
        },
        pr: None,
        review: None,
        attempts: vec![AutopilotAttemptSummary {
            attempt: 1,
            supervisor_run_id: "sup-run".to_string(),
            agent_id: agent_id.to_string(),
            supervisor_status: "succeeded".to_string(),
            validation_status: AutopilotValidationStatus::Passed,
            pr_status: None,
            review_status: None,
            blocking_findings: 0,
            prepared_candidate_binding: Some(binding),
            reviewed_candidate: None,
            publication_authorized: false,
            publication_attempted: false,
            publication_effect_observed: false,
            prepublication_stage: "prepared".to_string(),
            repair_reason: None,
        }],
        ci_reaction_supported: false,
        check_status: AutopilotCheckStatus {
            ci_reaction_supported: false,
            state: "not_supported".to_string(),
            details: "unused".to_string(),
        },
        auto_merge_requested: false,
        auto_merge_performed: false,
        generated_follow_up_dispatch_performed: false,
        next_action: "await original PR update grant".to_string(),
    }
}

fn freeze_snapshot(
    item: ForgeItem,
    human: &ForgeActor,
    check_actor: &ForgeActor,
    head: &str,
    observed_at: &str,
    review_state: ForgeReviewState,
) -> FrozenReviewSnapshot {
    let observed_at = ForgeTimestamp::new(observed_at).expect("timestamp");
    let snapshot = PullRequestReviewSnapshot::new(
        item.clone(),
        observed_at.clone(),
        vec![ForgeReview::new(
            hashed_id(ProviderObjectKind::Review, b"REV_block"),
            human.clone(),
            review_state,
            "please fix",
            observed_at.clone(),
            head,
        )
        .expect("review")],
        Vec::new(),
        vec![ForgeCheck::new(
            hashed_id(ProviderObjectKind::Check, b"CHECK_ci"),
            check_actor.clone(),
            "ci",
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
            head,
            observed_at.clone(),
        )
        .expect("check")],
    )
    .expect("snapshot");
    let mut transport = FakeForgeTransport::new();
    transport
        .register_observation(
            ForgeObservationRequest::pull_request_review_snapshot(item.clone()).expect("request"),
            ForgeObservation::PullRequestReviewSnapshot(snapshot),
        )
        .expect("register");
    FrozenReviewSnapshot::observe(&transport, &item, &observed_at).expect("freeze")
}

struct CompleteRepairFixture {
    _temp: TempDir,
    repo: PathBuf,
    policy_file: PathBuf,
    bound: BoundReviewPolicy,
    item: InboxItem,
    state: ReviewLoopState,
    binding: CandidateValidationBinding,
    prior_head: Oid,
    candidate: Oid,
    from_branch: String,
    report: AutopilotFinalReport,
    captured_audit: Vec<u8>,
    catalog_models: BTreeSet<String>,
    human: ForgeActor,
    check_actor: ForgeActor,
    forge_repository: ForgeRepository,
    collection_c: ForgeTimestamp,
}

#[cfg(unix)]
fn complete_abc_fixture() -> CompleteRepairFixture {
    let (temp, pr_base, prior_head, candidate, binding, from_branch) = init_git_abc_candidate();
    let repo = temp.path().join("repo");
    git2::Repository::open(&repo)
        .expect("open")
        .remote("origin", "https://github.com/example/project.git")
        .expect("origin");
    let forge_repository = ForgeRepository::new(
        "github",
        "github.com/example/project",
        hashed_id(ProviderObjectKind::Repository, b"R_actual"),
    )
    .expect("repository");
    let human = ForgeActor::new(
        "github",
        hashed_id(ProviderObjectKind::Actor, b"U_reviewer"),
        "reviewer",
        ReportedActorKind::Human,
    )
    .expect("human");
    let check_actor = ForgeActor::new(
        "github",
        hashed_id(ProviderObjectKind::Actor, b"B_ci"),
        "ci-bot",
        ReportedActorKind::Bot,
    )
    .expect("bot");
    let policy = ReviewLoopPolicy::new(
        vec![
            TrustedActorBinding::new(
                TrustedActorIdentity::new(
                    human.provider_actor_id().clone(),
                    human.canonical_handle(),
                    human.reported_kind(),
                )
                .expect("human identity"),
                TrustedActorRole::HumanBlocking,
            )
            .expect("human binding"),
            TrustedActorBinding::new(
                TrustedActorIdentity::new(
                    check_actor.provider_actor_id().clone(),
                    check_actor.canonical_handle(),
                    check_actor.reported_kind(),
                )
                .expect("bot identity"),
                TrustedActorRole::BotAdvisory,
            )
            .expect("bot binding"),
        ],
        vec![RequiredCheck::new(
            "ci",
            vec![TrustedActorIdentity::new(
                check_actor.provider_actor_id().clone(),
                check_actor.canonical_handle(),
                check_actor.reported_kind(),
            )
            .expect("check identity")],
        )
        .expect("required check")],
        1,
        3,
    )
    .expect("policy");
    let policy_file = fs::canonicalize(temp.path())
        .expect("canonicalize")
        .join("review-policy.json");
    fs::write(
        &policy_file,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "repository": forge_repository,
            "policy": policy,
        }))
        .expect("encode policy"),
    )
    .expect("write policy");
    let bound =
        BoundReviewPolicy::load(&repo, &InboxConfig::default(), &policy_file).expect("bind policy");
    let git = Repository::open(&repo).expect("open for identity");
    let common = SafeRoot::open_existing(git.commondir()).expect("common");
    let identity = publication::external_source_repository_identity(
        common.identity().device,
        common.identity().file,
    );
    let item = InboxItem {
        item_id: "pr-90".to_string(),
        source_key: "github_pr:90".to_string(),
        source_snapshot: InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "github.com",
            "github.com/example/project",
            identity,
            90,
            "2026-08-16T02:00:00Z",
            "OPEN",
            prior_head.to_string(),
            pr_base.to_string(),
            "3".repeat(64),
            "4".repeat(64),
        )
        .expect("source snapshot"),
        kind: InboxItemKind::PullRequest,
        title: "needs repair".to_string(),
        url: Some("https://github.com/example/project/pull/90".to_string()),
        issue: None,
        pull_request: Some(GithubPrCandidate {
            number: 90,
            title: "needs repair".to_string(),
            url: Some("https://github.com/example/project/pull/90".to_string()),
            author: Some("repair-agent".to_string()),
            labels: Vec::new(),
            updated_at: Some("2026-08-16T02:00:00Z".to_string()),
            head_ref: Some("repair-branch".to_string()),
            base_ref: Some("main".to_string()),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            head_repository: Some("example/project".to_string()),
            changed_files: vec![PathBuf::from("base.txt")],
            checks: vec![GithubCheckSummary {
                name: "ci".to_string(),
                status: Some("completed".to_string()),
                conclusion: Some("success".to_string()),
                details_url: None,
                summary: "ok".to_string(),
            }],
            review_feedback: GithubReviewFeedbackSummary {
                review_decision: Some("CHANGES_REQUESTED".to_string()),
                requested_changes: true,
                unresolved_thread_count: Some(1),
                reviewer_logins: vec!["reviewer".to_string()],
                summaries: vec!["please fix".to_string()],
            },
            body_summary: String::new(),
            body_truncated: false,
        }),
        privacy: PrivacyScanResult {
            safe: true,
            reasons: Vec::new(),
            redactions: RedactionSummary::default(),
            body_summary: String::new(),
            body_truncated: false,
        },
        duplicate: DuplicateDetectionResult {
            duplicate: false,
            key: "github_pr:90".to_string(),
            matched_run_id: None,
            reason: None,
        },
        selected: true,
        skip_reason: None,
    };
    let forge_item = ForgeItem::new(
        forge_repository.clone(),
        ForgeItemKind::PullRequest,
        90,
        hashed_id(ProviderObjectKind::Item, b"PR_90"),
        item.source_snapshot.action_revision_digest().to_string(),
        Some(prior_head.to_string()),
        Some(pr_base.to_string()),
    )
    .expect("forge item");
    let frozen_b = freeze_snapshot(
        forge_item,
        &human,
        &check_actor,
        &prior_head.to_string(),
        "2026-08-16T02:00:00Z",
        ForgeReviewState::ChangesRequested,
    );
    let collection_b = ForgeTimestamp::new("2026-08-16T02:00:00Z").expect("collection b");
    let state = super::super::review_state_journal::observe(
        &repo,
        &frozen_b,
        bound.policy(),
        &collection_b,
    )
    .expect("observe B");
    assert_eq!(state.phase(), ReviewLoopPhase::Active);
    let reports = vec![passed_report("unit"), passed_report("lint")];
    let auto_run = RunId::new("auto-repair-child").expect("auto run");
    let report = autopilot_report(&repo, &auto_run, "repair-agent", binding.clone(), reports);
    let task = super::super::build_repair_disposition_audit_task(
        &repo,
        &state,
        bound.policy(),
        binding.clone(),
    )
    .expect("build audit task independently");
    let catalog_models = ["gpt-5.6-sol".to_string()].into_iter().collect();
    let selection = compact_independent_auditor_selection(
        &select_critical_independent_auditor(&catalog_models).expect("select"),
    )
    .expect("compact selection");
    let captured_audit = serde_json::to_vec(&accepted_auditor_output(&task, &selection.model))
        .expect("capture audit");
    let collection_c = ForgeTimestamp::new("2026-08-16T03:00:00Z").expect("collection c");
    let _ = pr_base;
    CompleteRepairFixture {
        _temp: temp,
        repo,
        policy_file,
        bound,
        item,
        state,
        binding,
        prior_head,
        candidate,
        from_branch,
        report,
        captured_audit,
        catalog_models,
        human,
        check_actor,
        forge_repository,
        collection_c,
    }
}

#[cfg(unix)]
fn snapshot_c(fixture: &CompleteRepairFixture) -> FrozenReviewSnapshot {
    let forge_item = ForgeItem::new(
        fixture.forge_repository.clone(),
        ForgeItemKind::PullRequest,
        90,
        hashed_id(ProviderObjectKind::Item, b"PR_90"),
        fixture
            .item
            .source_snapshot
            .action_revision_digest()
            .to_string(),
        Some(fixture.candidate.to_string()),
        fixture.item.source_snapshot.base_oid().map(str::to_string),
    )
    .expect("forge item C");
    freeze_snapshot(
        forge_item,
        &fixture.human,
        &fixture.check_actor,
        &fixture.candidate.to_string(),
        "2026-08-16T02:30:00Z",
        ForgeReviewState::ChangesRequested,
    )
}

#[cfg(unix)]
fn persist_parent_artifacts(
    writer: &mut ArtifactRunWriter,
    fixture: &CompleteRepairFixture,
    run_id: &RunId,
) {
    super::super::write_private_artifact_json(writer, "item-1-review-state.json", &fixture.state)
        .expect("review state");
    super::super::write_private_artifact_json(
        writer,
        "selected-items.json",
        &vec![fixture.item.clone()],
    )
    .expect("selected items");
    super::super::write_private_artifact_json(
        writer,
        "final-report.json",
        &serde_json::json!({"success": true, "run_id": run_id.as_str()}),
    )
    .expect("final report");
}

#[cfg(unix)]
fn run_phase1(fixture: &CompleteRepairFixture, run_id: &RunId) -> RepairConsumerOutcome {
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&fixture.captured_audit);
    let outcome = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &fixture.report,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("phase1");
    persist_parent_artifacts(&mut writer, fixture, run_id);
    writer
        .finalize("final-report.json", false)
        .expect("finalize");
    outcome
}

#[cfg(unix)]
fn grant_update_and_observe<'a>(
    fixture: &'a CompleteRepairFixture,
    apply_calls: &'a AtomicUsize,
    observe_calls: &'a AtomicUsize,
) -> (
    Box<super::ApplyOriginalUpdateFn<'a>>,
    Box<super::PostUpdateObservationFn<'a>>,
) {
    let receipt = test_update_receipt(&fixture.candidate.to_string(), fixture.binding.clone());
    let snapshot = snapshot_c(fixture);
    let apply = move |_opts: crate::publication::pr_original_update::PrOriginalUpdateOptions,
                      _evidence: crate::merge::ValidationEvidenceBundle| {
        apply_calls.fetch_add(1, Ordering::SeqCst);
        Ok(receipt.clone())
    };
    let collection_c = fixture.collection_c.clone();
    let expected_head = fixture.candidate.to_string();
    let observe = move |_repo: &Path, _policy: &BoundReviewPolicy, _pr: u64, head: &str| {
        observe_calls.fetch_add(1, Ordering::SeqCst);
        if head != expected_head {
            bail!("incomplete observation: head is not candidate C");
        }
        Ok((snapshot.clone(), collection_c.clone()))
    };
    (Box::new(apply), Box::new(observe))
}

#[cfg(unix)]
fn clone_authenticated_run_with_mixed_validation(
    fixture: &CompleteRepairFixture,
    source_run: &RunId,
    dest_run: &RunId,
    mixed: &RepairValidationEvidenceStore,
) {
    let reader = ArtifactRunReader::open(&fixture.repo, RunArtifactFamily::Inbox, source_run)
        .expect("open source run");
    let mut pending: PendingRepairBinding = serde_json::from_slice(
        &reader
            .read("item-1-pending-repair.json")
            .expect("read pending"),
    )
    .expect("decode pending");
    pending.inbox_run_id = dest_run.as_str().to_string();
    pending.validation_evidence_sha256 =
        sha256_hex(&serde_json::to_vec(mixed).expect("serialize mixed store"));
    pending.pending_admission_digest = String::new();
    pending.pending_admission_digest = pending_binding_digest(&pending).expect("digest");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        dest_run.clone(),
        "inbox-repair",
    )
    .expect("reserve dest run");
    for name in [
        "item-1-repair-disposition-audit-task.json",
        "item-1-repair-disposition-audit-selection.json",
        "item-1-repair-disposition-audit-launch.json",
        "item-1-repair-disposition-audit-output.json",
        "item-1-repair-verified-dispositions.json",
        "item-1-review-state.json",
        "selected-items.json",
        "final-report.json",
    ] {
        let bytes = reader.read(name).expect("copy artifact");
        writer
            .write_bytes(
                name,
                &bytes,
                crate::artifacts::ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write copied artifact");
    }
    super::super::write_private_artifact_json(
        &mut writer,
        "item-1-repair-validation-evidence.json",
        mixed,
    )
    .expect("write mixed store");
    super::super::write_private_artifact_json(&mut writer, "item-1-pending-repair.json", &pending)
        .expect("write pending");
    persist_pending_binding(&fixture.repo, &pending).expect("persist mixed pending");
    writer
        .finalize("final-report.json", false)
        .expect("finalize dest");
}

#[cfg(unix)]
#[test]
fn production_phase1_then_resume_advances_authenticated_c() {
    let fixture = complete_abc_fixture();
    assert_ne!(
        fixture.item.source_snapshot.base_oid().unwrap(),
        fixture.prior_head.to_string()
    );
    assert_ne!(fixture.prior_head, fixture.candidate);
    assert_eq!(
        fixture.binding.primary_head.as_deref(),
        Some(fixture.prior_head.to_string().as_str())
    );
    assert_eq!(
        fixture.binding.merge_base.as_deref(),
        Some(fixture.prior_head.to_string().as_str())
    );
    let run_id = RunId::new("repair-full-bc").expect("run");
    let phase1 = run_phase1(&fixture, &run_id);
    match phase1 {
        RepairConsumerOutcome::AwaitingGrant {
            candidate_head,
            prior_head,
            resume_command,
            from_branch,
        } => {
            assert_eq!(candidate_head, fixture.candidate.to_string());
            assert_eq!(prior_head, fixture.prior_head.to_string());
            assert_eq!(from_branch, fixture.from_branch);
            assert!(resume_command.contains("resume-repair"));
            assert!(!resume_command.contains("comment"));
        }
        other => panic!("expected awaiting grant, got {other:?}"),
    }
    let loaded = super::load_selected_item(&fixture.repo, &run_id, 1).expect("selected items");
    assert_eq!(loaded.item_id, fixture.item.item_id);
    let apply_calls = AtomicUsize::new(0);
    let observe_calls = AtomicUsize::new(0);
    let (mut apply, mut observe) = grant_update_and_observe(&fixture, &apply_calls, &observe_calls);
    let report = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id: run_id.clone(),
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
    .expect("resume");
    assert!(report.success);
    assert_eq!(report.status, "advanced");
    assert_eq!(
        report.updated_head_oid.as_deref(),
        Some(fixture.candidate.to_string().as_str())
    );
    assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
    assert_eq!(observe_calls.load(Ordering::SeqCst), 1);
    let apply_again = AtomicUsize::new(0);
    let observe_again = AtomicUsize::new(0);
    let (mut apply2, mut observe2) =
        grant_update_and_observe(&fixture, &apply_again, &observe_again);
    let replay = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply2,
            observe_post_update: &mut observe2,
        },
    )
    .expect("completed replay");
    assert_eq!(apply_again.load(Ordering::SeqCst), 0);
    assert_eq!(observe_again.load(Ordering::SeqCst), 0);
    assert_eq!(replay.status, "replayed_source_bound_completion");
}

#[cfg(unix)]
#[test]
fn phase1_is_idempotent_and_does_not_rerun_repair() {
    let fixture = complete_abc_fixture();
    let run_id = RunId::new("repair-idempotent-phase1").expect("run");
    let first = run_phase1(&fixture, &run_id);
    assert!(matches!(first, RepairConsumerOutcome::AwaitingGrant { .. }));
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        RunId::new("repair-idempotent-phase1-repeat").expect("run"),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&fixture.captured_audit);
    let second = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &fixture.report,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("repeat phase1");
    assert!(matches!(
        second,
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
}

#[cfg(unix)]
#[test]
fn phase1_passed_overall_with_skipped_report_refuses_before_auditor() {
    let fixture = complete_abc_fixture();
    let mut mixed = fixture.report.clone();
    assert_eq!(mixed.validation.status, AutopilotValidationStatus::Passed);
    mixed.validation.reports = vec![passed_report("unit"), skipped_report("lint")];
    let run_id = RunId::new("repair-mixed-skipped-phase1").expect("run");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let audit_calls = AtomicUsize::new(0);
    let mut runner = counting_audit_runner(&fixture.captured_audit, &audit_calls);
    let outcome = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &mixed,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("phase1 mixed");
    match outcome {
        RepairConsumerOutcome::Refused { kind, message } => {
            assert_eq!(kind, "review_repair_validation_refused");
            assert!(
                message.contains("non-passed report 'lint'"),
                "unexpected refusal {message}"
            );
        }
        other => panic!("expected validation refusal, got {other:?}"),
    }
    assert_eq!(audit_calls.load(Ordering::SeqCst), 0);
    assert!(super::find_existing_pending_admission(
        &fixture.repo,
        fixture
            .bound
            .repository()
            .provider_repository_id()
            .stable_id(),
        fixture.item.source_snapshot.number(),
        run_id.as_str(),
        1,
    )
    .expect("lookup pending")
    .is_none());
}

#[cfg(unix)]
#[test]
fn phase2_loaded_mixed_validation_store_refuses_before_update() {
    let fixture = complete_abc_fixture();
    let source_run = RunId::new("repair-mixed-phase2-source").expect("source run");
    assert!(matches!(
        run_phase1(&fixture, &source_run),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let dest_run = RunId::new("repair-mixed-phase2-dest").expect("dest run");
    let mixed = RepairValidationEvidenceStore {
        candidate_binding: fixture.binding.clone(),
        reports: vec![passed_report("unit"), skipped_report("lint")],
    };
    clone_authenticated_run_with_mixed_validation(&fixture, &source_run, &dest_run, &mixed);
    let apply_calls = AtomicUsize::new(0);
    let observe_calls = AtomicUsize::new(0);
    let (mut apply, mut observe) = grant_update_and_observe(&fixture, &apply_calls, &observe_calls);
    let refused = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id: dest_run,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
    .expect_err("mixed store must refuse before update");
    assert!(
        refused.to_string().contains("non-passed report 'lint'"),
        "unexpected phase2 error {refused}"
    );
    assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observe_calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[test]
fn resume_interruption_after_update_replays_receipt_then_advances() {
    let fixture = complete_abc_fixture();
    let run_id = RunId::new("repair-interrupt-update").expect("run");
    assert!(matches!(
        run_phase1(&fixture, &run_id),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let pending = super::load_pending_artifact(&fixture.repo, &run_id, 1).expect("pending");
    let receipt = test_update_receipt(&fixture.candidate.to_string(), fixture.binding.clone());
    super::record_update_receipt(&fixture.repo, &pending, &receipt).expect("record update");
    let apply_calls = AtomicUsize::new(0);
    let observe_calls = AtomicUsize::new(0);
    let (mut apply, mut observe) = grant_update_and_observe(&fixture, &apply_calls, &observe_calls);
    let report = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
    .expect("resume after update");
    assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observe_calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.status, "advanced");
}

#[cfg(unix)]
#[test]
fn resume_interruption_after_advance_replays_exact_watermark() {
    let fixture = complete_abc_fixture();
    let run_id = RunId::new("repair-interrupt-advance").expect("run");
    assert!(matches!(
        run_phase1(&fixture, &run_id),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let apply_calls = AtomicUsize::new(0);
    let observe_calls = AtomicUsize::new(0);
    let (mut apply, mut observe) = grant_update_and_observe(&fixture, &apply_calls, &observe_calls);
    resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id: run_id.clone(),
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
    .expect("first resume");
    let apply_again = AtomicUsize::new(0);
    let observe_again = AtomicUsize::new(0);
    let (mut apply2, mut observe2) =
        grant_update_and_observe(&fixture, &apply_again, &observe_again);
    let replay = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply2,
            observe_post_update: &mut observe2,
        },
    )
    .expect("replay after advance");
    assert_eq!(apply_again.load(Ordering::SeqCst), 0);
    assert_eq!(observe_again.load(Ordering::SeqCst), 0);
    assert_eq!(replay.status, "replayed_source_bound_completion");
}

#[cfg(unix)]
#[test]
fn parameterized_refusals_do_not_fabricate_passed_evidence_or_identities() {
    let fixture = complete_abc_fixture();

    let mut wrong_producer_report = fixture.report.clone();
    wrong_producer_report.attempts[0].agent_id = independent_auditor_stable_id().to_string();
    let run_id = RunId::new("repair-wrong-producer").expect("run");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&fixture.captured_audit);
    let wrong_producer = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &wrong_producer_report,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("wrong producer");
    assert!(matches!(
        wrong_producer,
        RepairConsumerOutcome::Refused { kind, .. } if kind.contains("repair")
    ));

    let mut failed_audit = accepted_auditor_output(
        &super::super::build_repair_disposition_audit_task(
            &fixture.repo,
            &fixture.state,
            fixture.bound.policy(),
            fixture.binding.clone(),
        )
        .expect("task"),
        "gpt-5.6-sol",
    );
    failed_audit.accepted = false;
    failed_audit.lenses[0].decision = LensDecision::Reject;
    failed_audit.lenses[1].decision = LensDecision::Reject;
    let captured_fail = serde_json::to_vec(&failed_audit).expect("failed audit");
    let run_id = RunId::new("repair-failed-audit").expect("run");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&captured_fail);
    let refused_audit = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &fixture.report,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("failed audit");
    assert!(matches!(
        refused_audit,
        RepairConsumerOutcome::Refused { kind, .. } if kind.contains("audit")
    ));

    let ready_snapshot = freeze_snapshot(
        ForgeItem::new(
            fixture.forge_repository.clone(),
            ForgeItemKind::PullRequest,
            90,
            hashed_id(ProviderObjectKind::Item, b"PR_90"),
            fixture
                .item
                .source_snapshot
                .action_revision_digest()
                .to_string(),
            Some(fixture.prior_head.to_string()),
            fixture.item.source_snapshot.base_oid().map(str::to_string),
        )
        .expect("ready item"),
        &fixture.human,
        &fixture.check_actor,
        &fixture.prior_head.to_string(),
        "2026-08-16T02:00:00Z",
        ForgeReviewState::Approved,
    );
    let ready_state = ReviewLoopState::new(
        fixture.bound.policy().clone(),
        ready_snapshot,
        &ForgeTimestamp::new("2026-08-16T02:00:00Z").expect("ready ts"),
    )
    .expect("ready/exhausted terminal state");
    assert_ne!(ready_state.phase(), ReviewLoopPhase::Active);
    let run_id = RunId::new("repair-exhausted-phase").expect("run");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&fixture.captured_audit);
    let exhausted = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &ready_state,
            autopilot_report: &fixture.report,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("exhausted/terminal phase");
    assert!(matches!(exhausted, RepairConsumerOutcome::NotApplicable));

    let mut no_pass = fixture.report.clone();
    no_pass.validation.reports = vec![failed_report("unit")];
    no_pass.attempts[0].validation_status = AutopilotValidationStatus::Failed;
    no_pass.attempts[0].prepared_candidate_binding = None;
    let run_id = RunId::new("repair-no-candidate").expect("run");
    let mut writer = ArtifactRunWriter::reserve(
        &fixture.repo,
        RunArtifactFamily::Inbox,
        run_id.clone(),
        "inbox-repair",
    )
    .expect("writer");
    let mut runner = captured_audit_runner(&fixture.captured_audit);
    let missing_candidate = process_bounded_pr_repair_after_autopilot_with_runner(
        RepairConsumerInput {
            writer: &mut writer,
            repo: &fixture.repo,
            run_id: &run_id,
            item_index: 1,
            item: &fixture.item,
            policy: &fixture.bound,
            policy_file: &fixture.policy_file,
            state: &fixture.state,
            autopilot_report: &no_pass,
            action_policy: InboxActionPolicy::Fake,
            permission_mode: InboxPermissionMode::Fake,
            codex_bin: Some(PathBuf::from("/fake/codex")),
            machine_global: None,
        },
        &mut runner,
        Some(&fixture.catalog_models),
        local_source_revalidator,
    )
    .expect("missing candidate");
    assert!(matches!(
        missing_candidate,
        RepairConsumerOutcome::Refused { kind, .. } if kind.contains("candidate")
    ));

    let run_id = RunId::new("repair-tamper").expect("run");
    assert!(matches!(
        run_phase1(&fixture, &run_id),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let reader_dir = fixture.repo.join(".maco/inbox/runs").join(run_id.as_str());
    let pending_path = reader_dir.join("item-1-pending-repair.json");
    if pending_path.exists() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&pending_path).expect("read pending")).expect("json");
        value["verified_proof_sha256"] = serde_json::json!("e".repeat(64));
        fs::write(&pending_path, serde_json::to_vec(&value).expect("write")).expect("tamper");
    }
    let apply_calls = AtomicUsize::new(0);
    let observe_calls = AtomicUsize::new(0);
    let (mut apply, mut observe) = grant_update_and_observe(&fixture, &apply_calls, &observe_calls);
    let tampered = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    );
    assert!(tampered.is_err() || apply_calls.load(Ordering::SeqCst) == 0);

    let run_id = RunId::new("repair-stale-head").expect("run");
    assert!(matches!(
        run_phase1(&fixture, &run_id),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let apply_calls = AtomicUsize::new(0);
    let mut apply = |_opts: crate::publication::pr_original_update::PrOriginalUpdateOptions,
                     _evidence: crate::merge::ValidationEvidenceBundle| {
        apply_calls.fetch_add(1, Ordering::SeqCst);
        Ok(test_update_receipt(
            &fixture.candidate.to_string(),
            fixture.binding.clone(),
        ))
    };
    let mut observe = |_repo: &Path, _policy: &BoundReviewPolicy, _pr: u64, _head: &str| {
        bail!("stale or incomplete provider state")
    };
    let stale = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    );
    assert!(stale.is_err());

    let run_id = RunId::new("repair-wrong-receipt").expect("run");
    assert!(matches!(
        run_phase1(&fixture, &run_id),
        RepairConsumerOutcome::AwaitingGrant { .. }
    ));
    let apply_calls = AtomicUsize::new(0);
    let mut apply = |_opts: crate::publication::pr_original_update::PrOriginalUpdateOptions,
                     _evidence: crate::merge::ValidationEvidenceBundle| {
        apply_calls.fetch_add(1, Ordering::SeqCst);
        Ok(test_update_receipt(
            &fixture.prior_head.to_string(),
            fixture.binding.clone(),
        ))
    };
    let mut observe = |_repo: &Path, _policy: &BoundReviewPolicy, _pr: u64, _head: &str| {
        panic!("observe must not run for wrong candidate receipt")
    };
    let wrong_receipt = resume_inbox_repair_with_services(
        InboxResumeRepairOptions {
            repo: fixture.repo.clone(),
            run_id,
            item_index: 1,
            grant_file: PathBuf::from("/tmp/grant.json"),
        },
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    );
    assert!(wrong_receipt.is_err());
}
