//! Two-phase inbox PR repair consumer (#90).

use super::review_loop::{FrozenReviewSnapshot, ReviewLoopPhase, ReviewLoopState};
use super::review_loop_entry::InboxIndependentAuditorSelectionEvidence;
use super::review_policy_input::BoundReviewPolicy;
use super::review_state_journal;
use super::{
    build_repair_disposition_audit_task, repair_disposition_auditor_actor,
    repair_disposition_auditor_prompt, verify_repair_disposition_audit_capture,
    RepairDispositionAuditLaunchRecord, RepairDispositionAuditTask, VerifiedRepairDispositions,
};
use super::{
    launch_inbox_read_only_independent_auditor, pr_needs_repair, revalidate_inbox_item_source,
    verified_independent_audit_runner, write_private_artifact_json, ArtifactRunWriter,
    ExternalAgentCommand, InboxActionPolicy, InboxItem, InboxItemKind, InboxPermissionMode,
    InboxReadOnlyAuditorLaunchInput, InboxSourceProvider,
};
use crate::artifacts::{
    repository_auth_writer, state_auth::sha256_hex, ArtifactRunReader, RunArtifactFamily,
};
use crate::autopilot::{AutopilotFinalReport, AutopilotValidationStatus};
use crate::merge::{
    CandidateValidationBinding, ValidationEvidenceBundle, ValidationReport, ValidationStatus,
};
use crate::optimizer::merge_authority::{
    assess_independence, AgentIdentity, MergeActor, ProducerFingerprint, SessionId,
};
use crate::orchestrator::RunId;
use crate::publication::forge_transport::ForgeTimestamp;
use crate::publication::pr_original_update::{OriginalPrUpdateReceipt, PrOriginalUpdateOptions};
use crate::state_journal::{AuthenticatedStateJournal, CheckpointJournalSpec, JournalSpec};
use crate::worktree::WorktreeManager;
use anyhow::{bail, Context, Result};
use git2::{Commit, Oid, Repository};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const PENDING_FORMAT_VERSION: u32 = 1;
const PHASE_PENDING: &str = "pending_repair_admitted";
const PHASE_UPDATE: &str = "pending_repair_update_receipt";
const PHASE_OBSERVATION: &str = "pending_repair_post_update_observation";
const PHASE_ADVANCED: &str = "pending_repair_advanced";
const KEY_DOMAIN: &[u8] = b"MACO\0inbox-pr-repair-pending-key\0v1\0";

enum PendingRepairJournalSpec {}

impl JournalSpec for PendingRepairJournalSpec {
    const FORMAT_VERSION: u32 = PENDING_FORMAT_VERSION;
    const NAMESPACE: &'static str = "inbox_pr_repair_pending";
    const ROOT_NAME: &'static str = "inbox-pr-repair-pending-v1";
    const ROOT_LOCK_NAME: &'static str = ".inbox-pr-repair-pending.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".repair-pending.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: crate::artifacts::state_auth::AuthenticationDomain =
        crate::artifacts::state_auth::AuthenticationDomain::new(
            b"MACO\0inbox-pr-repair-pending-record\0v1\0",
        );
    const HEAD_DOMAIN: crate::artifacts::state_auth::AuthenticationDomain =
        crate::artifacts::state_auth::AuthenticationDomain::new(
            b"MACO\0inbox-pr-repair-pending-head\0v1\0",
        );
    const MAX_RECORDS: usize = 32;
    const MAX_RECORD_BYTES: u64 = <CheckpointJournalSpec as JournalSpec>::MAX_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = Self::MAX_RECORD_BYTES * Self::MAX_RECORDS as u64;
    const MAX_PHASE_BYTES: usize = <CheckpointJournalSpec as JournalSpec>::MAX_PHASE_BYTES;
    const MAX_SUBJECT_BYTES: usize = <CheckpointJournalSpec as JournalSpec>::MAX_SUBJECT_BYTES;
    const MAX_INSTANCE_ID_BYTES: usize = 64;
}

type PendingRepairJournal = AuthenticatedStateJournal<PendingRepairJournalSpec>;
type ApplyOriginalUpdateFn<'a> = dyn FnMut(PrOriginalUpdateOptions, ValidationEvidenceBundle) -> Result<OriginalPrUpdateReceipt>
    + 'a;
type PostUpdateObservationFn<'a> = dyn FnMut(&Path, &BoundReviewPolicy, u64, &str) -> Result<(FrozenReviewSnapshot, ForgeTimestamp)>
    + 'a;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRepairBinding {
    version: u32,
    inbox_run_id: String,
    item_index: usize,
    autopilot_run_id: String,
    review_policy_file: PathBuf,
    provider_repository_id: String,
    pr_number: u64,
    source_snapshot_sha256: String,
    raw_policy_sha256: String,
    policy_sha256: String,
    prior_state_sha256: String,
    prior_snapshot_sha256: String,
    prior_head_oid: String,
    prior_base_oid: String,
    candidate_binding: CandidateValidationBinding,
    from_branch: String,
    repair_producer: ProducerFingerprint,
    verified_proof_sha256: String,
    validation_evidence_sha256: String,
    pending_admission_digest: String,
    repair_execution: RepairProducerExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairProducerExecutionRecord {
    agent_id: String,
    supervisor_run_id: String,
    child_autopilot_run_id: String,
    model_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairValidationEvidenceStore {
    candidate_binding: CandidateValidationBinding,
    reports: Vec<ValidationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRepairUpdateReceipt {
    version: u32,
    receipt: OriginalPrUpdateReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRepairObservationRecord {
    version: u32,
    collection_started_at: String,
    snapshot_sha256: String,
    expected_head_oid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRepairAdvancedRecord {
    version: u32,
    advanced_state_sha256: String,
    collection_started_at: String,
    source_bound_completion: bool,
}

/// Production resume dependencies (update + post-update observation).
pub(crate) struct RepairResumeServices<'a> {
    pub apply_original_update: &'a mut ApplyOriginalUpdateFn<'a>,
    pub observe_post_update: &'a mut PostUpdateObservationFn<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxResumeRepairOptions {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub item_index: usize,
    pub grant_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxResumeRepairReport {
    pub success: bool,
    pub status: String,
    pub prior_state_sha256: String,
    pub updated_head_oid: Option<String>,
    pub next_action: String,
}

#[derive(Debug)]
pub(super) enum RepairConsumerOutcome {
    NotApplicable,
    Refused {
        kind: String,
        message: String,
    },
    AwaitingGrant {
        from_branch: String,
        candidate_head: String,
        prior_head: String,
        resume_command: String,
    },
}

pub(super) struct RepairConsumerInput<'a> {
    pub writer: &'a mut ArtifactRunWriter,
    pub repo: &'a Path,
    pub run_id: &'a RunId,
    pub item_index: usize,
    pub item: &'a InboxItem,
    pub policy: &'a BoundReviewPolicy,
    pub policy_file: &'a Path,
    pub state: &'a ReviewLoopState,
    pub autopilot_report: &'a AutopilotFinalReport,
    pub action_policy: InboxActionPolicy,
    pub permission_mode: InboxPermissionMode,
    pub codex_bin: Option<PathBuf>,
    pub machine_global: Option<super::InboxMachineGlobalInput>,
}

pub(super) fn process_bounded_pr_repair_after_autopilot(
    input: RepairConsumerInput<'_>,
) -> Result<RepairConsumerOutcome> {
    process_bounded_pr_repair_after_autopilot_with_runner(
        input,
        verified_independent_audit_runner,
        None,
        revalidate_inbox_item_source,
    )
}

pub(super) fn process_bounded_pr_repair_after_autopilot_with_runner<F, R>(
    input: RepairConsumerInput<'_>,
    mut external_runner: F,
    catalog_models_override: Option<&BTreeSet<String>>,
    mut source_revalidator: R,
) -> Result<RepairConsumerOutcome>
where
    F: FnMut(&ExternalAgentCommand) -> super::IndependentAuditRunnerResult,
    R: FnMut(&Path, &InboxItem) -> Result<()>,
{
    if input.item.kind != InboxItemKind::PullRequest
        || input.item.source_snapshot.provider() != InboxSourceProvider::Github
        || !input
            .item
            .pull_request
            .as_ref()
            .is_some_and(pr_needs_repair)
        || input.state.phase() != ReviewLoopPhase::Active
        || !input.autopilot_report.success
    {
        return Ok(RepairConsumerOutcome::NotApplicable);
    }
    source_revalidator(input.repo, input.item)
        .context("PR repair consumer source drifted after autopilot")?;
    let candidate = match select_final_prepared_candidate(input.repo, input.autopilot_report) {
        Ok(candidate) => candidate,
        Err(error) => {
            return Ok(RepairConsumerOutcome::Refused {
                kind: "review_repair_candidate_refused".to_string(),
                message: error.to_string(),
            });
        }
    };
    let validation_store = RepairValidationEvidenceStore {
        candidate_binding: candidate.binding.clone(),
        reports: input.autopilot_report.validation.reports.clone(),
    };
    if let Err(error) = validation_bundle_for_final_candidate(&validation_store) {
        return Ok(RepairConsumerOutcome::Refused {
            kind: "review_repair_validation_refused".to_string(),
            message: error.to_string(),
        });
    }
    let producer =
        match repair_producer_fingerprint(input.repo, &candidate.binding, &candidate.execution) {
            Ok(producer) => producer,
            Err(error) => {
                return Ok(RepairConsumerOutcome::Refused {
                    kind: "review_repair_producer_refused".to_string(),
                    message: error.to_string(),
                });
            }
        };
    let task = match build_repair_disposition_audit_task(
        input.repo,
        input.state,
        input.policy.policy(),
        candidate.binding.clone(),
    ) {
        Ok(task) => task,
        Err(error) => {
            return Ok(RepairConsumerOutcome::Refused {
                kind: "review_repair_audit_task_refused".to_string(),
                message: error.to_string(),
            });
        }
    };
    let launched = match launch_inbox_read_only_independent_auditor(
        InboxReadOnlyAuditorLaunchInput {
            repo: input.repo,
            run_id: input.run_id,
            item_index: input.item_index,
            action_policy: input.action_policy,
            permission_mode: input.permission_mode,
            codex_bin: input.codex_bin.as_deref(),
            machine_global: input.machine_global.as_ref(),
            catalog_models_override,
        },
        |selection| {
            repair_disposition_auditor_prompt(&task, selection).map_err(|error| error.to_string())
        },
        &mut |command| external_runner(command),
    ) {
        Ok(launched) => launched,
        Err(message) => {
            return Ok(RepairConsumerOutcome::Refused {
                kind: "review_repair_disposition_audit_refused".to_string(),
                message,
            });
        }
    };
    let auditor = repair_disposition_auditor_actor(
        &launched.launch.auditor_session_id,
        &launched.selection.model,
    );
    if !assess_independence(&producer, &auditor).independent {
        return Ok(RepairConsumerOutcome::Refused {
            kind: "review_repair_disposition_audit_refused".to_string(),
            message: "repair producer and independent auditor are not independent".to_string(),
        });
    }
    let launch_record = RepairDispositionAuditLaunchRecord {
        task,
        selection: launched.selection.clone(),
        launch: launched.launch,
        raw_report_json: launched.raw_report_json,
    };
    let verified = match verify_repair_disposition_audit_capture(
        input.repo,
        input.state,
        input.policy.policy(),
        &launch_record,
        auditor,
        &producer,
    ) {
        Ok(verified) => verified,
        Err(blocker) => {
            return Ok(RepairConsumerOutcome::Refused {
                kind: "review_repair_disposition_audit_refused".to_string(),
                message: format!("{blocker:?}"),
            });
        }
    };
    let validation_evidence_sha256 = sha256_hex(
        &serde_json::to_vec(&validation_store).context("serialize validation evidence store")?,
    );
    write_private_artifact_json(
        input.writer,
        format!(
            "item-{}-repair-disposition-audit-task.json",
            input.item_index
        ),
        &launch_record.task,
    )?;
    write_private_artifact_json(
        input.writer,
        format!(
            "item-{}-repair-disposition-audit-selection.json",
            input.item_index
        ),
        &launch_record.selection,
    )?;
    write_private_artifact_json(
        input.writer,
        format!(
            "item-{}-repair-disposition-audit-launch.json",
            input.item_index
        ),
        &launch_record.launch,
    )?;
    input.writer.write_bytes(
        format!(
            "item-{}-repair-disposition-audit-output.json",
            input.item_index
        ),
        &launch_record.raw_report_json,
        crate::artifacts::ArtifactFileDisposition::PrivateEvidence,
    )?;
    write_private_artifact_json(
        input.writer,
        format!("item-{}-repair-validation-evidence.json", input.item_index),
        &validation_store,
    )?;
    write_private_artifact_json(
        input.writer,
        format!(
            "item-{}-repair-verified-dispositions.json",
            input.item_index
        ),
        &proof_summary(&verified),
    )?;
    let mut binding = PendingRepairBinding {
        version: PENDING_FORMAT_VERSION,
        inbox_run_id: input.run_id.as_str().to_string(),
        item_index: input.item_index,
        autopilot_run_id: input.autopilot_report.run_id.as_str().to_string(),
        review_policy_file: input.policy_file.to_path_buf(),
        provider_repository_id: input
            .policy
            .repository()
            .provider_repository_id()
            .stable_id()
            .to_string(),
        pr_number: input.item.source_snapshot.number(),
        source_snapshot_sha256: source_snapshot_sha256(input.item)?,
        raw_policy_sha256: sha256_hex(input.policy.raw()),
        policy_sha256: input.policy.policy().canonical_sha256()?,
        prior_state_sha256: verified.prior_state_sha256().to_string(),
        prior_snapshot_sha256: verified.prior_snapshot_sha256().to_string(),
        prior_head_oid: verified.prior_head_oid().to_string(),
        prior_base_oid: verified.prior_base_oid().to_string(),
        candidate_binding: verified.candidate_binding().clone(),
        from_branch: candidate.from_branch,
        repair_producer: producer,
        verified_proof_sha256: verified.proof_sha256().to_string(),
        validation_evidence_sha256,
        pending_admission_digest: String::new(),
        repair_execution: candidate.execution,
    };
    binding.pending_admission_digest = pending_binding_digest(&binding)?;
    if let Some(existing) = find_existing_pending_admission(
        input.repo,
        &binding.provider_repository_id,
        binding.pr_number,
        &binding.inbox_run_id,
        binding.item_index,
    )? {
        if existing.pending_admission_digest != binding.pending_admission_digest {
            return Ok(RepairConsumerOutcome::Refused {
                kind: "review_repair_pending_conflict".to_string(),
                message:
                    "a semantically different pending repair admission is already durable for this inbox item"
                        .to_string(),
            });
        }
        return Ok(RepairConsumerOutcome::AwaitingGrant {
            from_branch: existing.from_branch.clone(),
            candidate_head: existing
                .candidate_binding
                .agent_head
                .clone()
                .unwrap_or_default(),
            prior_head: existing.prior_head_oid.clone(),
            resume_command: format!(
                "maco inbox resume-repair --repo {} --run-id {} --item-index {} --grant <operator-grant.json>",
                input.repo.display(),
                input.run_id.as_str(),
                input.item_index
            ),
        });
    }
    persist_pending_binding(input.repo, &binding)?;
    write_private_artifact_json(
        input.writer,
        format!("item-{}-pending-repair.json", input.item_index),
        &binding,
    )?;
    let candidate_head = binding
        .candidate_binding
        .agent_head
        .clone()
        .unwrap_or_default();
    let resume_command = format!(
        "maco inbox resume-repair --repo {} --run-id {} --item-index {} --grant <operator-grant.json>",
        input.repo.display(),
        input.run_id.as_str(),
        input.item_index
    );
    Ok(RepairConsumerOutcome::AwaitingGrant {
        from_branch: binding.from_branch.clone(),
        candidate_head,
        prior_head: binding.prior_head_oid.clone(),
        resume_command,
    })
}

pub fn resume_inbox_repair(options: InboxResumeRepairOptions) -> Result<InboxResumeRepairReport> {
    let mut apply = |opts: PrOriginalUpdateOptions, evidence: ValidationEvidenceBundle| {
        crate::publication::pr_original_update::update_existing(opts, evidence)
    };
    let mut observe = |repo: &Path, policy: &BoundReviewPolicy, pr_number: u64, head: &str| {
        observe_post_update_snapshot(repo, policy, pr_number, head)
    };
    resume_inbox_repair_with_services(
        options,
        &mut RepairResumeServices {
            apply_original_update: &mut apply,
            observe_post_update: &mut observe,
        },
    )
}

pub(crate) fn resume_inbox_repair_with_services(
    options: InboxResumeRepairOptions,
    services: &mut RepairResumeServices<'_>,
) -> Result<InboxResumeRepairReport> {
    let binding = load_pending_artifact(&options.repo, &options.run_id, options.item_index)?;
    if !options.grant_file.is_absolute() {
        bail!("operator grant path must be absolute and outside the repository");
    }
    if let Some(report) = replay_completed_transition(&options.repo, &binding)? {
        return Ok(report);
    }
    let selected = load_selected_item(&options.repo, &options.run_id, options.item_index)?;
    if selected.source_snapshot.number() != binding.pr_number {
        bail!("pending repair selected item does not match pending PR number");
    }
    revalidate_local_candidate(&options.repo, &binding)?;
    let policy = reload_policy(&options.repo, &binding)?;
    let state = reload_review_state(&options.repo, &binding)?;
    let launch_record = load_launch_record(&options.repo, &options.run_id, options.item_index)?;
    let verified = verify_capture(&options.repo, &state, &policy, &launch_record, &binding)?;
    let validation_evidence = load_validation_evidence(&options.repo, &binding)?;
    let receipt = if let Some(receipt) = replay_update_receipt(&options.repo, &binding)? {
        receipt
    } else {
        let receipt = (services.apply_original_update)(
            PrOriginalUpdateOptions {
                repo: options.repo.clone(),
                from_branch: binding.from_branch.clone(),
                grant_file: options.grant_file,
            },
            validation_evidence.evidence().clone(),
        )?;
        record_update_receipt(&options.repo, &binding, &receipt)?;
        receipt
    };
    finish_after_update_with_services(
        &options.repo,
        &binding,
        &policy,
        &state,
        &verified,
        receipt,
        services,
    )
}

fn finish_after_update_with_services(
    repo: &Path,
    binding: &PendingRepairBinding,
    policy: &BoundReviewPolicy,
    _state: &ReviewLoopState,
    verified: &VerifiedRepairDispositions,
    receipt: OriginalPrUpdateReceipt,
    services: &mut RepairResumeServices<'_>,
) -> Result<InboxResumeRepairReport> {
    let expected_head = binding
        .candidate_binding
        .agent_head
        .as_deref()
        .context("pending repair omitted candidate head")?;
    if receipt.updated_oid != expected_head {
        bail!("original PR update receipt head does not match pending repair candidate");
    }
    let (snapshot, collection_started_at, replayed_observation) =
        if let Some(observation) = replay_post_update_observation(repo, binding)? {
            let snapshot = load_post_update_snapshot_artifact(repo, binding)?;
            let collection_started_at = ForgeTimestamp::new(&observation.collection_started_at)
                .context("replay post-update observation collection timestamp")?;
            (snapshot, collection_started_at, true)
        } else {
            let (snapshot, collection_started_at) =
                (services.observe_post_update)(repo, policy, binding.pr_number, expected_head)?;
            persist_post_update_observation(
                repo,
                binding,
                &snapshot,
                &collection_started_at,
                expected_head,
            )?;
            (snapshot, collection_started_at, false)
        };
    let advanced = review_state_journal::advance_with_verified_dispositions(
        repo,
        binding.prior_state_sha256.as_str(),
        &snapshot,
        policy.policy(),
        &collection_started_at,
        verified.dispositions(),
    )?;
    record_advanced(
        repo,
        binding,
        advanced.state_sha256().to_string(),
        collection_started_at.as_str(),
    )?;
    Ok(InboxResumeRepairReport {
        success: true,
        status: if replayed_observation {
            "replayed_source_bound_completion".to_string()
        } else {
            "advanced".to_string()
        },
        prior_state_sha256: binding.prior_state_sha256.clone(),
        updated_head_oid: Some(receipt.updated_oid.clone()),
        next_action:
            "source-bound repair transition is durable; readiness and merge authority remain independently recomputed"
                .to_string(),
    })
}

struct SelectedRepairCandidate {
    binding: CandidateValidationBinding,
    from_branch: String,
    execution: RepairProducerExecutionRecord,
}

fn select_final_prepared_candidate(
    repo: &Path,
    report: &AutopilotFinalReport,
) -> Result<SelectedRepairCandidate> {
    let mut bindings = Vec::new();
    for attempt in &report.attempts {
        if attempt.validation_status != AutopilotValidationStatus::Passed {
            continue;
        }
        if let Some(binding) = &attempt.prepared_candidate_binding {
            bindings.push((attempt, binding.clone()));
        }
    }
    if bindings.is_empty() {
        bail!("autopilot produced no passed exact validation binding for a repair candidate");
    }
    let unique: BTreeSet<_> = bindings.iter().map(|(_, b)| b.diff_oid.clone()).collect();
    if unique.len() != 1 {
        bail!("autopilot produced ambiguous repair candidate validation bindings");
    }
    let (attempt, binding) = bindings
        .last()
        .context("repair candidate list disappeared")?;
    let from_branch = WorktreeManager::new(repo)
        .get_managed_verified(&attempt.agent_id)
        .with_context(|| format!("repair worktree for agent {}", attempt.agent_id))?
        .branch;
    let execution = repair_execution_record(report, attempt)?;
    Ok(SelectedRepairCandidate {
        binding: binding.clone(),
        from_branch,
        execution,
    })
}

fn repair_execution_record(
    report: &AutopilotFinalReport,
    attempt: &crate::autopilot::AutopilotAttemptSummary,
) -> Result<RepairProducerExecutionRecord> {
    report
        .supervisor
        .as_ref()
        .context("repair producer execution requires supervisor final report")?;
    if attempt.supervisor_run_id.trim().is_empty() {
        bail!("repair producer execution requires supervisor_run_id");
    }
    if attempt.agent_id.trim().is_empty() {
        bail!("repair producer execution requires agent_id");
    }
    let model_label = report
        .supervisor
        .as_ref()
        .map(|supervisor| supervisor.runtime.as_str())
        .context("repair producer execution requires supervisor runtime")?;
    if model_label.trim().is_empty() {
        bail!("repair producer execution requires model label");
    }
    Ok(RepairProducerExecutionRecord {
        agent_id: attempt.agent_id.clone(),
        supervisor_run_id: attempt.supervisor_run_id.clone(),
        child_autopilot_run_id: report.run_id.as_str().to_string(),
        model_label: model_label.to_string(),
    })
}

fn repair_producer_fingerprint(
    repo: &Path,
    binding: &CandidateValidationBinding,
    execution: &RepairProducerExecutionRecord,
) -> Result<ProducerFingerprint> {
    let merge_base = binding
        .merge_base
        .as_deref()
        .context("repair binding omitted merge_base")?;
    let agent_head = binding
        .agent_head
        .as_deref()
        .context("repair binding omitted agent_head")?;
    let (authors, committers) = commit_provenance(repo, merge_base, agent_head)?;
    Ok(ProducerFingerprint {
        actor: MergeActor {
            agent: AgentIdentity {
                stable_id: execution.agent_id.clone(),
            },
            session: SessionId {
                id: execution.child_autopilot_run_id.clone(),
            },
            model_label: execution.model_label.clone(),
        },
        commit_authors: authors,
        commit_committers: committers,
    })
}

fn commit_provenance(
    repo: &Path,
    merge_base: &str,
    agent_head: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let repository = Repository::open(repo).context("open repository for repair provenance")?;
    let base_oid = Oid::from_str(merge_base).context("parse merge_base")?;
    let head_oid = Oid::from_str(agent_head).context("parse agent_head")?;
    let mut authors = BTreeSet::new();
    let mut committers = BTreeSet::new();
    let mut cursor = repository
        .find_commit(head_oid)
        .context("find candidate head")?;
    while cursor.id() != base_oid {
        push_commit_identity(&cursor, &mut authors, &mut committers)?;
        if cursor.parent_count() == 0 {
            break;
        }
        cursor = cursor.parent(0).context("walk repair commit chain")?;
    }
    if authors.is_empty() || committers.is_empty() {
        bail!("repair candidate commit chain omitted author or committer provenance");
    }
    Ok((
        authors.into_iter().collect(),
        committers.into_iter().collect(),
    ))
}

fn push_commit_identity(
    commit: &Commit,
    authors: &mut BTreeSet<String>,
    committers: &mut BTreeSet<String>,
) -> Result<()> {
    let author_sig = commit.author();
    let author = author_sig
        .name()
        .ok()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("repair candidate commit omitted author name")?
        .to_string();
    let committer_sig = commit.committer();
    let committer = committer_sig
        .name()
        .ok()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .context("repair candidate commit omitted committer name")?
        .to_string();
    authors.insert(author);
    committers.insert(committer);
    Ok(())
}

fn validation_bundle_for_final_candidate(
    store: &RepairValidationEvidenceStore,
) -> Result<crate::merge::BoundValidationEvidenceBundle> {
    if store.reports.is_empty() {
        bail!("repair validation evidence has an empty report set");
    }
    if let Some(report) = store
        .reports
        .iter()
        .find(|report| report.status != ValidationStatus::Passed)
    {
        bail!(
            "repair validation evidence contains non-passed report '{}'",
            report.name
        );
    }
    ValidationEvidenceBundle::bound_to(store.candidate_binding.clone(), store.reports.clone())
}

fn pending_binding_digest(binding: &PendingRepairBinding) -> Result<String> {
    let mut wire = binding.clone();
    wire.pending_admission_digest = String::new();
    Ok(sha256_hex(
        &serde_json::to_vec(&wire).context("serialize pending repair binding for digest")?,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRepairObservationPayload {
    record: PendingRepairObservationRecord,
    snapshot: serde_json::Value,
}

fn find_existing_pending_admission(
    repo: &Path,
    provider_repository_id: &str,
    pr_number: u64,
    inbox_run_id: &str,
    item_index: usize,
) -> Result<Option<PendingRepairBinding>> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair lookup authentication")?;
    let instance_id = pending_instance_id(provider_repository_id, pr_number)?;
    let state_root = authenticator.state_root();
    if !state_root.direct_child_exists(PendingRepairJournalSpec::ROOT_NAME)? {
        return Ok(None);
    }
    let journal_root = crate::safe_state::SafeRoot::open_existing(
        state_root.path().join(PendingRepairJournalSpec::ROOT_NAME),
    )
    .context("open existing pending repair journal root")?;
    if !journal_root.direct_child_exists(&instance_id)? {
        return Ok(None);
    }
    let journal = PendingRepairJournal::open_instance(authenticator, &instance_id)
        .context("open pending repair journal for lookup")?;
    for record in journal.records().iter().rev() {
        if record.phase != PHASE_PENDING {
            continue;
        }
        let binding: PendingRepairBinding =
            serde_json::from_value(record.payload.clone()).context("decode pending binding")?;
        if binding.inbox_run_id == inbox_run_id && binding.item_index == item_index {
            return Ok(Some(binding));
        }
    }
    Ok(None)
}

fn replay_completed_transition(
    repo: &Path,
    binding: &PendingRepairBinding,
) -> Result<Option<InboxResumeRepairReport>> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair completion replay authentication")?;
    let journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for completion replay")?;
    let mut advanced: Option<PendingRepairAdvancedRecord> = None;
    let mut receipt: Option<OriginalPrUpdateReceipt> = None;
    for record in journal.records().iter() {
        if record.phase == PHASE_UPDATE
            && record.subject.as_deref() == Some(binding.inbox_run_id.as_str())
        {
            let stored: PendingRepairUpdateReceipt =
                serde_json::from_value(record.payload.clone()).context("decode update receipt")?;
            receipt = Some(stored.receipt);
        }
        if record.phase == PHASE_ADVANCED
            && record.subject.as_deref() == Some(binding.inbox_run_id.as_str())
        {
            advanced = Some(
                serde_json::from_value(record.payload.clone()).context("decode advanced record")?,
            );
        }
    }
    let Some(advanced) = advanced else {
        return Ok(None);
    };
    let receipt = receipt.context("completed pending-repair transition missing update receipt")?;
    if !advanced.source_bound_completion {
        bail!("pending repair advanced record is not source-bound");
    }
    let expected_head = binding
        .candidate_binding
        .agent_head
        .as_deref()
        .context("pending repair omitted candidate head")?;
    if receipt.updated_oid != expected_head {
        bail!("durable pending-repair completion receipt head mismatch");
    }
    Ok(Some(InboxResumeRepairReport {
        success: true,
        status: "replayed_source_bound_completion".to_string(),
        prior_state_sha256: binding.prior_state_sha256.clone(),
        updated_head_oid: Some(receipt.updated_oid.clone()),
        next_action:
            "source-bound repair transition is durable; readiness and merge authority remain independently recomputed"
                .to_string(),
    }))
}

fn replay_post_update_observation(
    repo: &Path,
    binding: &PendingRepairBinding,
) -> Result<Option<PendingRepairObservationRecord>> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair observation replay authentication")?;
    let journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for observation replay")?;
    for record in journal.records().iter().rev() {
        if record.phase == PHASE_OBSERVATION
            && record.subject.as_deref() == Some(binding.inbox_run_id.as_str())
        {
            let payload: PendingRepairObservationPayload =
                serde_json::from_value(record.payload.clone())
                    .context("decode post-update observation payload")?;
            if payload.record.version != PENDING_FORMAT_VERSION {
                bail!("unsupported post-update observation record version");
            }
            return Ok(Some(payload.record));
        }
    }
    Ok(None)
}

fn load_post_update_snapshot_artifact(
    repo: &Path,
    binding: &PendingRepairBinding,
) -> Result<FrozenReviewSnapshot> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair snapshot replay authentication")?;
    let journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for snapshot replay")?;
    for record in journal.records().iter().rev() {
        if record.phase == PHASE_OBSERVATION
            && record.subject.as_deref() == Some(binding.inbox_run_id.as_str())
        {
            let payload: PendingRepairObservationPayload =
                serde_json::from_value(record.payload.clone())
                    .context("decode post-update observation payload")?;
            return restore_frozen_snapshot(
                &payload.snapshot,
                &ForgeTimestamp::new(&payload.record.collection_started_at)
                    .context("restore post-update observation collection timestamp")?,
            );
        }
    }
    bail!("post-update authenticated observation is missing from the pending repair journal");
}

fn restore_frozen_snapshot(
    snapshot: &serde_json::Value,
    trusted_not_after: &ForgeTimestamp,
) -> Result<FrozenReviewSnapshot> {
    let encoded =
        serde_json::to_vec(snapshot).context("serialize persisted post-update snapshot")?;
    FrozenReviewSnapshot::restore_json(&encoded, trusted_not_after)
        .context("restore persisted post-update authenticated snapshot")
}

fn persist_post_update_observation(
    repo: &Path,
    binding: &PendingRepairBinding,
    snapshot: &FrozenReviewSnapshot,
    collection_started_at: &ForgeTimestamp,
    expected_head: &str,
) -> Result<()> {
    if snapshot.item().head_oid() != Some(expected_head) {
        bail!("post-update observation snapshot head does not match repair candidate");
    }
    let record = PendingRepairObservationRecord {
        version: PENDING_FORMAT_VERSION,
        collection_started_at: collection_started_at.as_str().to_string(),
        snapshot_sha256: snapshot.canonical_sha256().to_string(),
        expected_head_oid: expected_head.to_string(),
    };
    if record.snapshot_sha256 != snapshot.canonical_sha256() {
        bail!("post-update observation digest mismatch");
    }
    let payload = PendingRepairObservationPayload {
        record,
        snapshot: serde_json::to_value(snapshot)
            .context("serialize post-update authenticated snapshot")?,
    };
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair observation authentication")?;
    let mut journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for observation persist")?;
    journal
        .append(
            PHASE_OBSERVATION,
            Some(binding.inbox_run_id.as_str()),
            &payload,
        )
        .context("persist post-update authenticated observation before review advance")?;
    Ok(())
}

fn proof_summary(verified: &VerifiedRepairDispositions) -> serde_json::Value {
    serde_json::json!({
        "proof_sha256": verified.proof_sha256(),
        "task_digest_sha256": verified.task_digest_sha256(),
        "prior_state_sha256": verified.prior_state_sha256(),
        "disposition_count": verified.dispositions().len(),
    })
}

fn source_snapshot_sha256(item: &InboxItem) -> Result<String> {
    Ok(sha256_hex(
        &serde_json::to_vec(&item.source_snapshot).context("serialize inbox source snapshot")?,
    ))
}

fn pending_instance_id(provider_repository_id: &str, pr_number: u64) -> Result<String> {
    #[derive(Serialize)]
    struct Key<'a> {
        provider_repository_id: &'a str,
        pr_number: u64,
    }
    let mut bytes = KEY_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(&Key {
        provider_repository_id,
        pr_number,
    })?);
    Ok(sha256_hex(&bytes))
}

fn persist_pending_binding(repo: &Path, binding: &PendingRepairBinding) -> Result<()> {
    if find_existing_pending_admission(
        repo,
        &binding.provider_repository_id,
        binding.pr_number,
        &binding.inbox_run_id,
        binding.item_index,
    )?
    .is_some_and(|existing| existing.pending_admission_digest == binding.pending_admission_digest)
    {
        return Ok(());
    }
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair authentication")?;
    let mut journal = PendingRepairJournal::open_or_initialize(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal")?;
    journal
        .append(PHASE_PENDING, Some(binding.inbox_run_id.as_str()), binding)
        .context("persist pending repair binding")?;
    Ok(())
}

fn read_artifact_json<T: serde::de::DeserializeOwned>(
    reader: &ArtifactRunReader,
    relative: &str,
) -> Result<T> {
    let bytes = reader
        .read(relative)
        .with_context(|| format!("read artifact {relative}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse artifact {relative}"))
}

fn load_pending_artifact(
    repo: &Path,
    run_id: &RunId,
    item_index: usize,
) -> Result<PendingRepairBinding> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, run_id)?;
    let binding: PendingRepairBinding =
        read_artifact_json(&reader, &format!("item-{item_index}-pending-repair.json"))?;
    if binding.inbox_run_id != run_id.as_str() || binding.item_index != item_index {
        bail!("pending repair artifact does not match the requested inbox item");
    }
    Ok(binding)
}

fn revalidate_local_candidate(repo: &Path, binding: &PendingRepairBinding) -> Result<()> {
    let record = WorktreeManager::new(repo)
        .get_managed_verified(&binding.candidate_binding.agent_id)
        .with_context(|| {
            format!(
                "repair candidate worktree for agent {}",
                binding.candidate_binding.agent_id
            )
        })?;
    if record.branch != binding.from_branch {
        bail!("pending repair from_branch does not match the managed worktree branch");
    }
    Ok(())
}

fn load_selected_item(repo: &Path, run_id: &RunId, item_index: usize) -> Result<InboxItem> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, run_id)?;
    let items: Vec<InboxItem> = read_artifact_json(&reader, "selected-items.json")?;
    let zero_index = item_index
        .checked_sub(1)
        .context("inbox item index must be positive")?;
    items
        .get(zero_index)
        .cloned()
        .context("selected inbox item disappeared from run artifacts")
}

fn reload_policy(repo: &Path, binding: &PendingRepairBinding) -> Result<BoundReviewPolicy> {
    let config = super::load_config(repo)?;
    BoundReviewPolicy::load(repo, &config.config, &binding.review_policy_file)
}

fn reload_review_state(repo: &Path, binding: &PendingRepairBinding) -> Result<ReviewLoopState> {
    let run_id = RunId::new(&binding.inbox_run_id)?;
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, &run_id)?;
    let encoded = reader
        .read(format!("item-{}-review-state.json", binding.item_index))
        .context("read pending repair review-state artifact")?;
    let trusted_not_after = ForgeTimestamp::new(crate::orchestration_event::format_rfc3339_utc(
        SystemTime::now(),
    )?)?;
    let state = ReviewLoopState::restore_json(&encoded, &trusted_not_after)
        .context("restore authenticated review-loop state from durable artifacts")?;
    if state.state_sha256() != binding.prior_state_sha256 {
        bail!("pending repair prior review state no longer matches durable artifacts");
    }
    if state.policy_sha256() != binding.policy_sha256 {
        bail!("pending repair policy digest no longer matches review-loop state");
    }
    Ok(state)
}

fn load_launch_record(
    repo: &Path,
    run_id: &RunId,
    item_index: usize,
) -> Result<RepairDispositionAuditLaunchRecord> {
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, run_id)?;
    let task: RepairDispositionAuditTask = read_artifact_json(
        &reader,
        &format!("item-{item_index}-repair-disposition-audit-task.json"),
    )?;
    let selection: InboxIndependentAuditorSelectionEvidence = read_artifact_json(
        &reader,
        &format!("item-{item_index}-repair-disposition-audit-selection.json"),
    )?;
    let launch: super::review_loop_entry::InboxIndependentAuditLaunchEvidence = read_artifact_json(
        &reader,
        &format!("item-{item_index}-repair-disposition-audit-launch.json"),
    )?;
    let raw = reader.read(format!(
        "item-{item_index}-repair-disposition-audit-output.json"
    ))?;
    Ok(RepairDispositionAuditLaunchRecord {
        task,
        selection,
        launch,
        raw_report_json: raw,
    })
}

fn verify_capture(
    repo: &Path,
    state: &ReviewLoopState,
    policy: &BoundReviewPolicy,
    launch_record: &RepairDispositionAuditLaunchRecord,
    binding: &PendingRepairBinding,
) -> Result<VerifiedRepairDispositions> {
    let auditor = repair_disposition_auditor_actor(
        &launch_record.launch.auditor_session_id,
        &launch_record.selection.model,
    );
    let verified = verify_repair_disposition_audit_capture(
        repo,
        state,
        policy.policy(),
        launch_record,
        auditor,
        &binding.repair_producer,
    )
    .map_err(|blocker| anyhow::anyhow!("{blocker:?}"))?;
    if verified.proof_sha256() != binding.verified_proof_sha256 {
        bail!("pending repair verified disposition proof changed");
    }
    if Some(verified.launch_report_sha256()) != launch_record.launch.report_sha256.as_deref() {
        bail!("pending repair independent-auditor report digest changed");
    }
    Ok(verified)
}

fn load_validation_evidence(
    repo: &Path,
    binding: &PendingRepairBinding,
) -> Result<crate::merge::BoundValidationEvidenceBundle> {
    let run_id = RunId::new(&binding.inbox_run_id)?;
    let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Inbox, &run_id)?;
    let store: RepairValidationEvidenceStore = read_artifact_json(
        &reader,
        &format!(
            "item-{}-repair-validation-evidence.json",
            binding.item_index
        ),
    )?;
    let bundle = validation_bundle_for_final_candidate(&store)?;
    let digest = sha256_hex(&serde_json::to_vec(&store).context("hash validation evidence store")?);
    if digest != binding.validation_evidence_sha256 {
        bail!("pending repair validation evidence digest mismatch");
    }
    Ok(bundle)
}

fn replay_update_receipt(
    repo: &Path,
    binding: &PendingRepairBinding,
) -> Result<Option<OriginalPrUpdateReceipt>> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair replay authentication")?;
    let journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for replay")?;
    for record in journal.records().iter().rev() {
        if record.phase == PHASE_UPDATE
            && record.subject.as_deref() == Some(binding.inbox_run_id.as_str())
        {
            let stored: PendingRepairUpdateReceipt = serde_json::from_value(record.payload.clone())
                .context("decode pending repair update receipt")?;
            return Ok(Some(stored.receipt));
        }
    }
    Ok(None)
}

fn record_update_receipt(
    repo: &Path,
    binding: &PendingRepairBinding,
    receipt: &OriginalPrUpdateReceipt,
) -> Result<()> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair update authentication")?;
    let mut journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for update receipt")?;
    let event = PendingRepairUpdateReceipt {
        version: PENDING_FORMAT_VERSION,
        receipt: receipt.clone(),
    };
    journal
        .append(PHASE_UPDATE, Some(binding.inbox_run_id.as_str()), &event)
        .context("record pending repair update receipt")?;
    Ok(())
}

fn record_advanced(
    repo: &Path,
    binding: &PendingRepairBinding,
    state_sha256: String,
    collection_started_at: &str,
) -> Result<()> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("bind pending repair advance authentication")?;
    let mut journal = PendingRepairJournal::open_instance(
        authenticator,
        &pending_instance_id(&binding.provider_repository_id, binding.pr_number)?,
    )
    .context("open pending repair journal for advance")?;
    let event = PendingRepairAdvancedRecord {
        version: PENDING_FORMAT_VERSION,
        advanced_state_sha256: state_sha256,
        collection_started_at: collection_started_at.to_string(),
        source_bound_completion: true,
    };
    journal
        .append(PHASE_ADVANCED, Some(binding.inbox_run_id.as_str()), &event)
        .context("record pending repair journal advance")?;
    Ok(())
}

fn observe_post_update_snapshot(
    repo: &Path,
    policy: &BoundReviewPolicy,
    pr_number: u64,
    expected_head: &str,
) -> Result<(FrozenReviewSnapshot, ForgeTimestamp)> {
    use crate::publication::forge_transport::{ForgeItemKind, GithubForge, GithubProductionRunner};

    policy.verify_repository(policy.repository())?;
    let forge_item = crate::publication::resolve_github_forge_item(
        repo,
        policy.repository().canonical_locator(),
        ForgeItemKind::PullRequest,
        pr_number,
    )?;
    if forge_item.head_oid() != Some(expected_head) {
        bail!("provider PR head is not the authenticated repair candidate after update");
    }
    let transport = GithubForge::new(GithubProductionRunner::for_repository(
        repo,
        policy.repository().canonical_locator(),
    )?);
    let collection_started_at = ForgeTimestamp::new(
        crate::orchestration_event::format_rfc3339_utc(SystemTime::now())?,
    )?;
    let snapshot = FrozenReviewSnapshot::observe(&transport, &forge_item, &collection_started_at)?;
    if snapshot.item().head_oid() != Some(expected_head) {
        bail!("post-update review snapshot head does not match repair candidate");
    }
    Ok((snapshot, collection_started_at))
}

#[cfg(test)]
#[path = "review_repair_flow_tests.rs"]
mod review_repair_flow_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_instance_id_is_stable() {
        let id = pending_instance_id("node:sha256:abc", 42).expect("id");
        assert_eq!(id.len(), 64);
    }
}
