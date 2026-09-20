//! Parent-retained supervisor measurements for held-out experiment runs.
//!
//! These values are copied from authenticated `supervisor-final.json` artifacts and
//! optional Git tree diffs. They are observations only: reported costs are
//! cost-equivalent figures from the supervisor report, not billed spend.

use super::{observed_dispatch_record_from_supervisor_final_json, ObservedDispatchRecord};
use crate::{
    artifacts::state_auth::sha256_hex,
    llm::provider::Usage,
    merge::CandidateValidationBinding,
    review::{
        AggregatedReviewLensVerdict, ReviewAggregationDecision, ReviewCoverageRequirement,
        ReviewInformationScope, ReviewLensAggregate, ReviewLensAggregateAuthority,
        ReviewLensVerdictStatus,
    },
    supervise::{
        held_out::HeldOutCandidateEvidence, AgentRole, Finding, OrchestratorReviewReport,
        RoleUsageReport, SupervisorFinalReport,
    },
};
use anyhow::{Context, Result};
use git2::{Diff, DiffOptions, Oid, Repository};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub const OBSERVED_RUN_MEASUREMENTS_VERSION: u32 = 1;
pub const REPORTED_COST_EQUIVALENT_NOTICE: &str =
    "reported cost-equivalent from parent-retained supervisor-final.json; not billed provider spend";

/// Serialized observation only. Authority is **not** re-established after deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentReviewCaptureObservation {
    #[default]
    UnprovenAfterDeserialize,
    ProvenAtCapture,
    FailedAtCapture,
}

/// In-process parent capture proof. Never serialized; absent after JSON round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentReviewCaptureProof {
    report_sha256: String,
    public_measurements_sha256: String,
    held_out_evidence_sha256: String,
}

/// Typed measurements bound to one held-out profile repetition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRunMeasurements {
    pub version: u32,
    pub manifest_sha256: String,
    pub profile_sha256: String,
    pub profile_id: String,
    pub repetition: u32,
    pub baseline_head: String,
    pub baseline_tree: String,
    pub retained_supervisor_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_supervisor_report_unavailable_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_usage: Option<Usage>,
    pub total_cost_usd: Option<f64>,
    #[serde(default = "reported_cost_notice")]
    pub cost_notice: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    pub usage_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_dispatch: Option<ObservedDispatchRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_unavailable_reason: Option<String>,
    pub candidate_footprint: ObservedCandidateFootprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_lens_aggregate: Option<ReviewLensAggregate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_evidence_unavailable_reason: Option<String>,
    pub supervisor_final_accepted: Option<bool>,
    pub supervisor_final_rejected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_auditor_accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_auditor_id: Option<String>,
    #[serde(default)]
    pub parent_review_capture: ParentReviewCaptureObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_review_capture_unavailable_reason: Option<String>,
    #[serde(skip)]
    pub(crate) parent_review_capture_proof: Option<ParentReviewCaptureProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCandidateFootprint {
    pub files_touched: Option<u32>,
    pub lines_added: Option<u32>,
    pub lines_deleted: Option<u32>,
    pub bytes_added: Option<u64>,
    pub bytes_deleted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

fn reported_cost_notice() -> String {
    REPORTED_COST_EQUIVALENT_NOTICE.to_string()
}

fn binding_from_held_out(held_out: &HeldOutCandidateEvidence) -> ObservedRunMeasurements {
    let run = &held_out.run;
    ObservedRunMeasurements {
        version: OBSERVED_RUN_MEASUREMENTS_VERSION,
        manifest_sha256: run.manifest_sha256.clone(),
        profile_sha256: run.profile_sha256.clone(),
        profile_id: run.profile_id.clone(),
        repetition: run.repetition,
        baseline_head: run.baseline_head.clone(),
        baseline_tree: run.baseline_tree.clone(),
        retained_supervisor_report_sha256: None,
        retained_supervisor_report_unavailable_reason: None,
        total_usage: None,
        total_cost_usd: None,
        cost_notice: reported_cost_notice(),
        role_usage: BTreeMap::new(),
        usage_complete: None,
        findings: Vec::new(),
        observed_dispatch: None,
        execution_unavailable_reason: None,
        candidate_footprint: ObservedCandidateFootprint::unknown(
            "supervisor-final.json was not retained",
        ),
        review_lens_aggregate: None,
        review_evidence_unavailable_reason: None,
        supervisor_final_accepted: None,
        supervisor_final_rejected: None,
        parent_auditor_accepted: None,
        parent_auditor_id: None,
        parent_review_capture: ParentReviewCaptureObservation::UnprovenAfterDeserialize,
        parent_review_capture_unavailable_reason: None,
        parent_review_capture_proof: None,
    }
}

/// Measurements when the parent never retained a verified supervisor-final report.
pub fn observed_run_measurements_unavailable(
    held_out: &HeldOutCandidateEvidence,
    report_unavailable_reason: &str,
) -> ObservedRunMeasurements {
    let mut measurements = binding_from_held_out(held_out);
    measurements.retained_supervisor_report_unavailable_reason =
        Some(report_unavailable_reason.to_string());
    measurements.execution_unavailable_reason =
        Some("supervisor-final.json was not retained for execution projection".to_string());
    measurements.candidate_footprint = ObservedCandidateFootprint::unknown(
        "candidate footprint requires a retained supervisor-final report and observed candidate",
    );
    measurements
}

/// Byte-only lift for tests and replay inspection. Never licenses accepted-quality proof.
pub fn observed_run_measurements_from_retained_supervisor_final_report(
    held_out: &HeldOutCandidateEvidence,
    report_bytes: &[u8],
    candidate_repo: &Path,
    exclude_repo_paths: &BTreeSet<PathBuf>,
) -> Result<ObservedRunMeasurements> {
    let report = serde_json::from_slice::<SupervisorFinalReport>(report_bytes)
        .context("retained supervisor-final.json is invalid")?;
    let mut measurements = lift_observational_fields(
        held_out,
        &report,
        report_bytes,
        candidate_repo,
        exclude_repo_paths,
    )?;
    measurements.parent_review_capture = ParentReviewCaptureObservation::UnprovenAfterDeserialize;
    measurements.parent_review_capture_proof = None;
    Ok(measurements)
}

/// Capture path used by held-out execution: live parent report + retained bytes before cleanup.
pub fn observed_run_measurements_from_captured_supervisor_final_report(
    held_out: &HeldOutCandidateEvidence,
    live_report: &SupervisorFinalReport,
    report_bytes: &[u8],
    candidate_repo: &Path,
    exclude_repo_paths: &BTreeSet<PathBuf>,
) -> Result<ObservedRunMeasurements> {
    let report_sha256 = sha256_hex(report_bytes);
    retained_bytes_match_live_report(live_report, report_bytes)
        .map_err(|error| anyhow::anyhow!(error))?;
    let mut measurements = lift_observational_fields(
        held_out,
        live_report,
        report_bytes,
        candidate_repo,
        exclude_repo_paths,
    )?;
    match attest_parent_review_capture(live_report, held_out, &report_sha256) {
        Ok(()) => {
            measurements.parent_review_capture = ParentReviewCaptureObservation::ProvenAtCapture;
            measurements.parent_review_capture_unavailable_reason = None;
            measurements.parent_review_capture_proof = Some(seal_parent_review_capture_proof(
                &measurements,
                held_out,
                &report_sha256,
            ));
        }
        Err(reason) => {
            measurements.parent_review_capture = ParentReviewCaptureObservation::FailedAtCapture;
            measurements.parent_review_capture_unavailable_reason = Some(reason);
            measurements.parent_review_capture_proof = None;
        }
    }
    Ok(measurements)
}

fn lift_observational_fields(
    held_out: &HeldOutCandidateEvidence,
    report: &SupervisorFinalReport,
    report_bytes: &[u8],
    candidate_repo: &Path,
    exclude_repo_paths: &BTreeSet<PathBuf>,
) -> Result<ObservedRunMeasurements> {
    let mut measurements = binding_from_held_out(held_out);
    measurements.retained_supervisor_report_sha256 = Some(sha256_hex(report_bytes));
    measurements.total_usage = report.total_usage;
    measurements.total_cost_usd = report.total_cost_usd;
    measurements.role_usage = report.role_usage.clone();
    measurements.usage_complete = Some(report.usage_complete);
    measurements.findings = report.findings.clone();
    match observed_dispatch_record_from_supervisor_final_json(report_bytes) {
        Ok(record) => measurements.observed_dispatch = Some(record),
        Err(reason) => measurements.execution_unavailable_reason = Some(reason),
    }
    measurements.candidate_footprint =
        observed_candidate_footprint_from_held_out(held_out, candidate_repo, exclude_repo_paths);
    let review = observed_parent_review_evidence_from_report(report, &held_out.run.assignment_id);
    measurements.review_lens_aggregate = review.review_lens_aggregate;
    measurements.review_evidence_unavailable_reason = review.unavailable_reason;
    measurements.supervisor_final_accepted = Some(report.accepted);
    measurements.supervisor_final_rejected = Some(report.rejected);
    measurements.parent_auditor_accepted = review.parent_auditor_accepted;
    measurements.parent_auditor_id = review.parent_auditor_id;
    Ok(measurements)
}

fn retained_bytes_match_live_report(
    live_report: &SupervisorFinalReport,
    report_bytes: &[u8],
) -> Result<(), String> {
    let parsed_value: serde_json::Value = serde_json::from_slice(report_bytes)
        .map_err(|error| format!("retained supervisor-final.json is invalid: {error}"))?;
    let live_value = serde_json::to_value(live_report).map_err(|error| {
        format!("live parent supervisor report is not JSON-serializable: {error}")
    })?;
    if parsed_value != live_value {
        return Err(
            "retained supervisor-final bytes do not match the live parent supervisor report"
                .to_string(),
        );
    }
    Ok(())
}

fn hash_public_measurements_for_proof(
    measurements: &ObservedRunMeasurements,
    capture_observation: ParentReviewCaptureObservation,
) -> Result<String, String> {
    let mut material = measurements.clone();
    material.parent_review_capture = capture_observation;
    material.parent_review_capture_proof = None;
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("public measurements are not serializable: {error}"))?;
    Ok(sha256_hex(&bytes))
}

fn hash_held_out_evidence_for_proof(held_out: &HeldOutCandidateEvidence) -> Result<String, String> {
    let bytes = serde_json::to_vec(held_out)
        .map_err(|error| format!("held-out evidence is not serializable: {error}"))?;
    Ok(sha256_hex(&bytes))
}

fn seal_parent_review_capture_proof(
    measurements: &ObservedRunMeasurements,
    held_out: &HeldOutCandidateEvidence,
    report_sha256: &str,
) -> ParentReviewCaptureProof {
    ParentReviewCaptureProof {
        report_sha256: report_sha256.to_string(),
        public_measurements_sha256: hash_public_measurements_for_proof(
            measurements,
            ParentReviewCaptureObservation::ProvenAtCapture,
        )
        .expect("measurements were sealed immediately after in-process capture"),
        held_out_evidence_sha256: hash_held_out_evidence_for_proof(held_out)
            .expect("held-out evidence was sealed immediately after in-process capture"),
    }
}

pub(crate) fn attest_parent_review_capture(
    live_report: &SupervisorFinalReport,
    held_out: &HeldOutCandidateEvidence,
    report_sha256: &str,
) -> Result<(), String> {
    if !held_out.passed() {
        return Err("held-out candidate validation did not pass".to_string());
    }
    validated_candidate_binding(held_out)?;
    let assignment_id = &held_out.run.assignment_id;
    let child = live_report
        .orchestrator_reports
        .iter()
        .find(|child| child.id == *assignment_id)
        .ok_or_else(|| {
            "live supervisor report lacks parent-orchestrator review evidence for the bound assignment"
                .to_string()
        })?;
    let aggregate = child.review_lens_aggregate.as_ref().ok_or_else(|| {
        "live supervisor report lacks a parent-computed review_lens_aggregate".to_string()
    })?;
    if aggregate.authority() != ReviewLensAggregateAuthority::ParentComputed {
        return Err(
            "live review_lens_aggregate was not parent-computed at capture time".to_string(),
        );
    }
    review_aggregate_establishes_full_independent_coverage(aggregate)?;
    if !parent_auditor_supports_review_aggregate(
        aggregate,
        parent_auditor_observation(child, assignment_id).0,
    ) {
        return Err("parent auditor did not accept the review-backed outcome".to_string());
    }
    if report_sha256.trim().is_empty() {
        return Err("retained supervisor-final report digest is missing".to_string());
    }
    Ok(())
}

pub fn review_aggregate_establishes_full_independent_coverage(
    aggregate: &ReviewLensAggregate,
) -> Result<(), String> {
    if aggregate.decision != ReviewAggregationDecision::Accept {
        return Err("review aggregate decision is not accept".to_string());
    }
    if aggregate.lens_verdicts.is_empty() {
        return Err("review aggregate retained no lens verdicts".to_string());
    }
    for verdict in &aggregate.lens_verdicts {
        if verdict.effective_verdict != ReviewLensVerdictStatus::Accept {
            return Err("review aggregate includes a non-accept effective verdict".to_string());
        }
        if !verdict.validation_errors.is_empty() {
            return Err("review aggregate retained validation errors".to_string());
        }
    }
    let mut omitted_independent_coverage = None;
    for verdict in &aggregate.lens_verdicts {
        if verdict.lens.information_scope != ReviewInformationScope::FullChildTranscript {
            continue;
        }
        match accepted_verdict_covers_required(verdict, &aggregate.required_coverage) {
            Ok(()) => return Ok(()),
            Err(error) => {
                if omitted_independent_coverage.is_none() {
                    omitted_independent_coverage = Some(error);
                }
            }
        }
    }
    Err(omitted_independent_coverage.unwrap_or_else(|| {
        "review aggregate has no independent full-child-transcript accept coverage".to_string()
    }))
}

fn accepted_verdict_covers_required(
    verdict: &AggregatedReviewLensVerdict,
    required: &ReviewCoverageRequirement,
) -> Result<(), String> {
    for worker in &required.worker_ids {
        if !verdict.coverage.worker_ids.contains(worker) {
            return Err(format!(
                "accepted review lens omitted required worker coverage '{worker}'"
            ));
        }
    }
    for path in &required.paths {
        if !verdict.coverage.paths.contains(path) {
            return Err(format!(
                "accepted review lens omitted required path coverage '{}'",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn parent_review_capture_proof_binding_invalid(
    measurements: &ObservedRunMeasurements,
) -> bool {
    match (
        measurements.parent_review_capture_proof.as_ref(),
        measurements.retained_supervisor_report_sha256.as_deref(),
    ) {
        (Some(proof), Some(digest)) => proof.report_sha256 != digest,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

pub(crate) fn parent_review_capture_proven(
    measurements: &ObservedRunMeasurements,
    held_out: &HeldOutCandidateEvidence,
) -> bool {
    if measurements.parent_review_capture != ParentReviewCaptureObservation::ProvenAtCapture {
        return false;
    }
    let proof = match measurements.parent_review_capture_proof.as_ref() {
        Some(proof) => proof,
        None => return false,
    };
    if measurements.retained_supervisor_report_sha256.as_deref()
        != Some(proof.report_sha256.as_str())
    {
        return false;
    }
    match (
        hash_public_measurements_for_proof(
            measurements,
            ParentReviewCaptureObservation::ProvenAtCapture,
        ),
        hash_held_out_evidence_for_proof(held_out),
    ) {
        (Ok(public), Ok(held_out_hash)) => {
            public == proof.public_measurements_sha256
                && held_out_hash == proof.held_out_evidence_sha256
        }
        _ => false,
    }
}

struct ObservedParentReviewLift {
    review_lens_aggregate: Option<ReviewLensAggregate>,
    unavailable_reason: Option<String>,
    parent_auditor_accepted: Option<bool>,
    parent_auditor_id: Option<String>,
}

fn observed_parent_review_evidence_from_report(
    report: &SupervisorFinalReport,
    assignment_id: &str,
) -> ObservedParentReviewLift {
    let child = report
        .orchestrator_reports
        .iter()
        .find(|child| child.id == assignment_id);
    let Some(child) = child else {
        return ObservedParentReviewLift {
            review_lens_aggregate: None,
            unavailable_reason: Some(
                "supervisor-final.json lacks parent-orchestrator review evidence for the bound assignment"
                    .to_string(),
            ),
            parent_auditor_accepted: None,
            parent_auditor_id: None,
        };
    };
    let (parent_auditor_accepted, parent_auditor_id) =
        parent_auditor_observation(child, assignment_id);
    let (review_lens_aggregate, unavailable_reason) = match child.review_lens_aggregate.clone() {
        Some(aggregate) => (Some(aggregate), None),
        None => (
            None,
            Some(
                "parent-orchestrator report lacks a parent-computed review_lens_aggregate"
                    .to_string(),
            ),
        ),
    };
    ObservedParentReviewLift {
        review_lens_aggregate,
        unavailable_reason,
        parent_auditor_accepted,
        parent_auditor_id,
    }
}

fn parent_auditor_observation(
    child: &OrchestratorReviewReport,
    assignment_id: &str,
) -> (Option<bool>, Option<String>) {
    let auditor = child
        .audit_reports
        .iter()
        .find(|report| is_assignment_parent_auditor(assignment_id, &report.id));
    match auditor {
        Some(report) => (Some(report.accepted), Some(report.id.clone())),
        None => (None, None),
    }
}

fn is_assignment_parent_auditor(assignment_id: &str, auditor_id: &str) -> bool {
    if auditor_id == format!("{assignment_id}-review-auditor") {
        return true;
    }
    auditor_id
        .strip_prefix(&format!("{assignment_id}-review-auditor-lens-"))
        .is_some_and(|index| !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn parent_auditor_supports_review_aggregate(
    aggregate: &ReviewLensAggregate,
    parent_auditor_accepted: Option<bool>,
) -> bool {
    parent_auditor_accepted == Some(true)
        && aggregate.decision == crate::review::ReviewAggregationDecision::Accept
}

impl ObservedCandidateFootprint {
    fn unknown(reason: &str) -> Self {
        Self {
            files_touched: None,
            lines_added: None,
            lines_deleted: None,
            bytes_added: None,
            bytes_deleted: None,
            unavailable_reason: Some(reason.to_string()),
        }
    }
}

fn observed_candidate_footprint_from_held_out(
    held_out: &HeldOutCandidateEvidence,
    candidate_repo: &Path,
    exclude_repo_paths: &BTreeSet<PathBuf>,
) -> ObservedCandidateFootprint {
    let binding = match validated_candidate_binding(held_out) {
        Ok(binding) => binding,
        Err(reason) => return ObservedCandidateFootprint::unknown(&reason),
    };
    let git = match Repository::open(candidate_repo) {
        Ok(repo) => repo,
        Err(error) => {
            return ObservedCandidateFootprint::unknown(&format!(
                "failed to open isolated candidate repository: {error}"
            ));
        }
    };
    let baseline_tree = match parse_oid(&held_out.run.baseline_tree, "baseline_tree") {
        Ok(oid) => oid,
        Err(error) => {
            return ObservedCandidateFootprint::unknown(&error.to_string());
        }
    };
    let agent_head = match binding.agent_head.as_deref() {
        Some(head) => head,
        None => {
            return ObservedCandidateFootprint::unknown("held-out candidate lacks agent_head");
        }
    };
    let candidate_tree = match parse_oid(agent_head, "agent_head") {
        Ok(oid) => match git.find_commit(oid) {
            Ok(commit) => commit.tree_id(),
            Err(error) => {
                return ObservedCandidateFootprint::unknown(&format!(
                    "held-out candidate agent_head is unavailable: {error}"
                ));
            }
        },
        Err(error) => return ObservedCandidateFootprint::unknown(&error),
    };
    count_tree_diff_footprint(&git, baseline_tree, candidate_tree, exclude_repo_paths)
        .unwrap_or_else(|error| ObservedCandidateFootprint::unknown(&error))
}

fn validated_candidate_binding(
    held_out: &HeldOutCandidateEvidence,
) -> Result<CandidateValidationBinding, String> {
    let candidate = held_out
        .candidate
        .as_ref()
        .ok_or_else(|| "held-out candidate was not observed".to_string())?;
    if candidate.agent_id != held_out.run.assignment_id {
        return Err("held-out candidate agent_id does not match run binding".to_string());
    }
    if candidate.primary_head.as_deref() != Some(held_out.run.baseline_head.as_str()) {
        return Err(
            "held-out candidate primary_head does not match pinned baseline head".to_string(),
        );
    }
    candidate
        .clone()
        .canonicalized()
        .map_err(|error| format!("held-out candidate binding is invalid: {error}"))
}

fn parse_oid(value: &str, label: &str) -> Result<Oid, String> {
    Oid::from_str(value).map_err(|error| format!("invalid {label} oid {value}: {error}"))
}

fn path_excluded(path: &Path, exclude_repo_paths: &BTreeSet<PathBuf>) -> bool {
    exclude_repo_paths.iter().any(|excluded| path == excluded)
}

fn count_tree_diff_footprint(
    repo: &Repository,
    old_tree: Oid,
    new_tree: Oid,
    exclude_repo_paths: &BTreeSet<PathBuf>,
) -> Result<ObservedCandidateFootprint, String> {
    let old_tree = repo
        .find_tree(old_tree)
        .map_err(|error| format!("baseline tree is unavailable: {error}"))?;
    let new_tree = repo
        .find_tree(new_tree)
        .map_err(|error| format!("candidate tree is unavailable: {error}"))?;
    let mut options = DiffOptions::new();
    options
        .include_typechange(true)
        .include_typechange_trees(true);
    let diff = repo
        .diff_tree_to_tree(Some(&old_tree), Some(&new_tree), Some(&mut options))
        .map_err(|error| format!("candidate tree diff is unavailable: {error}"))?;
    let mut files_touched = 0u32;
    let mut lines_added = 0u32;
    let mut lines_deleted = 0u32;
    let mut bytes_added = 0u64;
    let mut bytes_deleted = 0u64;
    for delta in diff.deltas() {
        let path = delta
            .new_file()
            .path()
            .or_else(|| delta.old_file().path())
            .ok_or_else(|| "candidate tree diff omitted a path".to_string())?;
        if path_excluded(path, exclude_repo_paths) {
            continue;
        }
        files_touched += 1;
        accumulate_blob_bytes(repo, delta.old_file().id(), &mut bytes_deleted)?;
        accumulate_blob_bytes(repo, delta.new_file().id(), &mut bytes_added)?;
    }
    accumulate_line_counts(
        &diff,
        exclude_repo_paths,
        &mut lines_added,
        &mut lines_deleted,
    )?;
    Ok(ObservedCandidateFootprint {
        files_touched: Some(files_touched),
        lines_added: Some(lines_added),
        lines_deleted: Some(lines_deleted),
        bytes_added: Some(bytes_added),
        bytes_deleted: Some(bytes_deleted),
        unavailable_reason: None,
    })
}

fn accumulate_blob_bytes(repo: &Repository, oid: Oid, total: &mut u64) -> Result<(), String> {
    if oid.is_zero() {
        return Ok(());
    }
    let blob = repo
        .find_blob(oid)
        .map_err(|error| format!("candidate diff blob is unavailable: {error}"))?;
    *total = total.saturating_add(blob.size() as u64);
    Ok(())
}

fn accumulate_line_counts(
    diff: &Diff,
    exclude_repo_paths: &BTreeSet<PathBuf>,
    lines_added: &mut u32,
    lines_deleted: &mut u32,
) -> Result<(), String> {
    let mut current_excluded = false;
    diff.print(git2::DiffFormat::Patch, |delta, _hunk, line| {
        if let Some(path) = delta.new_file().path().or_else(|| delta.old_file().path()) {
            current_excluded = path_excluded(path, exclude_repo_paths);
        }
        if current_excluded {
            return true;
        }
        match line.origin() {
            '+' => *lines_added = lines_added.saturating_add(1),
            '-' => *lines_deleted = lines_deleted.saturating_add(1),
            _ => {}
        }
        true
    })
    .map_err(|error| format!("candidate tree diff line stats are unavailable: {error}"))?;
    Ok(())
}

#[cfg(test)]
pub(super) fn supervisor_final_report_execution_fixture_bytes() -> Vec<u8> {
    use crate::artifacts::RunArtifactFamily;
    use crate::orchestrator::RunId;
    use crate::supervise::{
        AutonomyKpiReport, ReviewStatus, RoleEconomicsProfile, SupervisorFinalReport,
        SupervisorRunLifecycle, SupervisorRuntime,
    };
    const SUPERVISOR_EXECUTION_V2: &[u8] = include_bytes!(
        "../../tests/fixtures/model_mix_evaluation/supervisor-final-execution-v2.json"
    );
    let partial: serde_json::Value =
        serde_json::from_slice(SUPERVISOR_EXECUTION_V2).expect("execution projection fixture");
    let economics_profile: RoleEconomicsProfile =
        serde_json::from_value(partial["role_economics_profile"].clone())
            .expect("role economics profile");
    let total_usage = economics_profile
        .execution
        .as_ref()
        .and_then(|execution| execution.usage.total_usage);
    let total_cost_usd = economics_profile
        .execution
        .as_ref()
        .and_then(|execution| execution.usage.total_cost_usd);
    let report = SupervisorFinalReport {
        version: 1,
        run_id: RunId::new("fixture-run-v2").expect("run id"),
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: PathBuf::from("plan.json"),
        run_dir: RunArtifactFamily::Supervise
            .run_root()
            .join("fixture-run-v2"),
        runtime: SupervisorRuntime::Fake,
        publishable: false,
        success: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        run_lifecycle: SupervisorRunLifecycle::Finalized,
        evidence_only_reaudit: None,
        assigned_paths: Vec::new(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        claim_tokens: Vec::new(),
        semantic_intent_tokens: Vec::new(),
        role_economics_profile: Some(economics_profile),
        run_budget: None,
        role_usage: BTreeMap::new(),
        review_lens_usage: Vec::new(),
        review_lens_total_usage: None,
        review_lens_total_cost_usd: None,
        total_usage,
        total_cost_usd,
        usage_complete: true,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        sandbox_denials: Vec::new(),
        gate_denials: Vec::new(),
        pre_action_review_metrics: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        autonomy_kpis: AutonomyKpiReport::default(),
        files_changed: Vec::new(),
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
        remaining_risk: "fixture".to_string(),
        next_safe_action: String::new(),
    };
    serde_json::to_vec(&report).expect("serialize supervisor-final fixture")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::CandidateValidationBinding;
    use crate::supervise::held_out::{HeldOutCommandEvidence, HeldOutRunBinding};
    use git2::{IndexAddOption, Signature};

    fn sample_binding() -> HeldOutCandidateEvidence {
        HeldOutCandidateEvidence {
            version: 1,
            run: HeldOutRunBinding {
                manifest_sha256: "m".repeat(64),
                profile_sha256: "p".repeat(64),
                profile_id: "profile-a".to_string(),
                repetition: 0,
                experiment_run_id: "experiment".to_string(),
                supervisor_run_id: "supervisor".to_string(),
                assignment_id: "child-a".to_string(),
                baseline_head: "b".repeat(40),
                baseline_tree: "t".repeat(40),
            },
            candidate: Some(CandidateValidationBinding {
                version: 1,
                agent_id: "child-a".to_string(),
                primary_head: Some("b".repeat(40)),
                agent_head: Some("c".repeat(40)),
                merge_base: Some("b".repeat(40)),
                diff_oid: "d".repeat(40),
            }),
            candidate_revalidated: true,
            commands: vec![HeldOutCommandEvidence {
                id: "unit".to_string(),
                argv: vec!["true".to_string()],
                command_sha256: "1".repeat(64),
                observation: crate::merge::held_out::CommandObservation::unknown("fixture"),
            }],
        }
    }

    #[test]
    fn byte_only_lift_remains_unproven_after_round_trip() {
        let held_out = sample_binding();
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo_path = workspace.path().join("repo");
        git2::Repository::init(&repo_path).expect("init");
        let bytes = supervisor_final_report_execution_fixture_bytes();
        let measurements = observed_run_measurements_from_retained_supervisor_final_report(
            &held_out,
            &bytes,
            &repo_path,
            &BTreeSet::new(),
        )
        .expect("byte lift");
        assert_eq!(
            measurements.parent_review_capture,
            ParentReviewCaptureObservation::UnprovenAfterDeserialize
        );
        assert!(!parent_review_capture_proven(&measurements, &held_out));
    }

    #[test]
    fn retained_supervisor_fixture_projects_usage_cost_and_execution() {
        let held_out = sample_binding();
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo_path = workspace.path().join("repo");
        git2::Repository::init(&repo_path).expect("init");
        let bytes = supervisor_final_report_execution_fixture_bytes();
        let measurements = observed_run_measurements_from_retained_supervisor_final_report(
            &held_out,
            &bytes,
            &repo_path,
            &BTreeSet::new(),
        )
        .expect("project fixture");
        assert_eq!(
            measurements.retained_supervisor_report_sha256,
            Some(sha256_hex(&bytes))
        );
        assert_eq!(measurements.manifest_sha256, held_out.run.manifest_sha256);
        assert_eq!(measurements.profile_id, held_out.run.profile_id);
        assert_eq!(measurements.repetition, held_out.run.repetition);
        assert_eq!(measurements.baseline_head, held_out.run.baseline_head);
        let usage = measurements.total_usage.expect("total usage");
        assert_eq!(usage.input_tokens, 1200);
        assert_eq!(usage.output_tokens, 300);
        assert_eq!(measurements.total_cost_usd, Some(0.0125));
        assert!(measurements.observed_dispatch.is_some());
        assert!(measurements.execution_unavailable_reason.is_none());
        assert_eq!(measurements.cost_notice, REPORTED_COST_EQUIVALENT_NOTICE);
    }

    #[test]
    fn omitted_supervisor_fields_remain_unknown_without_zero_substitution() {
        let held_out = sample_binding();
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo_path = workspace.path().join("repo");
        git2::Repository::init(&repo_path).expect("init");
        let mut document: serde_json::Value =
            serde_json::from_slice(&supervisor_final_report_execution_fixture_bytes())
                .expect("parse");
        {
            let object = document.as_object_mut().expect("object");
            object.remove("role_economics_profile");
            object.remove("total_usage");
            object.remove("total_cost_usd");
            object.insert("usage_complete".into(), serde_json::Value::Bool(false));
        }
        let bytes = serde_json::to_vec(&document).expect("serialize");
        let measurements = observed_run_measurements_from_retained_supervisor_final_report(
            &held_out,
            &bytes,
            &repo_path,
            &BTreeSet::new(),
        )
        .expect("project partial report");
        assert!(measurements.total_usage.is_none());
        assert!(measurements.total_cost_usd.is_none());
        assert!(measurements.observed_dispatch.is_none());
        assert!(measurements
            .execution_unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("role_economics_profile")));
    }

    #[test]
    fn candidate_footprint_counts_real_diff_and_excludes_unrelated_path() {
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo_path = workspace.path().join("repo");
        let repo = git2::Repository::init(&repo_path).expect("init");
        std::fs::write(repo_path.join("README.md"), "baseline\n").expect("baseline readme");
        std::fs::create_dir_all(repo_path.join("artifact-owner")).expect("artifact dir");
        std::fs::write(repo_path.join("artifact-owner/unrelated.txt"), "ignore\n").expect("ignore");
        let baseline_commit = commit_all(&repo, "baseline").expect("baseline commit");
        let baseline_head = baseline_commit.id().to_string();
        let baseline_tree = baseline_commit.tree_id().to_string();
        std::fs::create_dir_all(repo_path.join("src")).expect("src dir");
        std::fs::write(repo_path.join("src/a.rs"), "line one\nline two\n").expect("add file");
        std::fs::write(repo_path.join("artifact-owner/unrelated.txt"), "changed\n")
            .expect("change");
        let candidate_commit = commit_all(&repo, "candidate").expect("candidate commit");
        let held_out = HeldOutCandidateEvidence {
            version: 1,
            run: HeldOutRunBinding {
                manifest_sha256: "m".repeat(64),
                profile_sha256: "p".repeat(64),
                profile_id: "profile".to_string(),
                repetition: 0,
                experiment_run_id: "experiment".to_string(),
                supervisor_run_id: "supervisor".to_string(),
                assignment_id: "child-a".to_string(),
                baseline_head: baseline_head.clone(),
                baseline_tree,
            },
            candidate: Some(CandidateValidationBinding {
                version: 1,
                agent_id: "child-a".to_string(),
                primary_head: Some(baseline_head.clone()),
                agent_head: Some(candidate_commit.id().to_string()),
                merge_base: Some(baseline_head.clone()),
                diff_oid: "d".repeat(40),
            }),
            candidate_revalidated: true,
            commands: Vec::new(),
        };
        let exclude = BTreeSet::from([PathBuf::from("artifact-owner/unrelated.txt")]);
        let footprint = observed_candidate_footprint_from_held_out(&held_out, &repo_path, &exclude);
        assert_eq!(footprint.files_touched, Some(1));
        assert_eq!(footprint.lines_added, Some(2));
        assert_eq!(footprint.lines_deleted, Some(0));
        assert_eq!(footprint.bytes_added, Some(18));
        assert_eq!(footprint.bytes_deleted, Some(0));
        assert!(footprint.unavailable_reason.is_none());
    }

    #[test]
    fn tampered_candidate_binding_yields_unknown_footprint() {
        let mut held_out = sample_binding();
        let workspace = tempfile::TempDir::new().expect("workspace");
        let repo_path = workspace.path().join("repo");
        git2::Repository::init(&repo_path).expect("init");
        held_out.candidate.as_mut().expect("candidate").primary_head = Some("0".repeat(40));
        let footprint =
            observed_candidate_footprint_from_held_out(&held_out, &repo_path, &BTreeSet::new());
        assert!(footprint.files_touched.is_none());
        assert!(footprint
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("primary_head")));
    }

    #[test]
    fn stacked_accept_aggregate_establishes_coverage_only_with_full_transcript() {
        use crate::review::{
            aggregate_review_lenses, ReviewAggregationPolicy, ReviewLensCoverage,
            ReviewLensEvidenceKind, ReviewLensVerdict, ReviewLensVerdictStatus,
        };
        use crate::supervise::default_supervisor_review_lenses;

        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("README.md")],
        };
        let coverage = ReviewLensCoverage {
            worker_ids: required.worker_ids.clone(),
            paths: required.paths.clone(),
        };
        let accept_aggregate = |lenses: Vec<crate::review::ReviewLensConfig>| {
            let verdicts = lenses
                .iter()
                .map(|lens| {
                    ReviewLensVerdict::for_lens(
                        lens,
                        sha256_hex(format!("request-{}", lens.id).as_bytes()),
                        ReviewLensVerdictStatus::Accept,
                        coverage.clone(),
                        vec![(
                            ReviewLensEvidenceKind::ModelReview,
                            format!("stacked-accept-{}", lens.id),
                        )],
                    )
                    .expect("accept verdict")
                })
                .collect();
            aggregate_review_lenses(
                &lenses,
                ReviewAggregationPolicy::AllMustAccept,
                required.clone(),
                verdicts,
            )
            .expect("parent-computed accept aggregate")
        };

        let stacked = accept_aggregate(default_supervisor_review_lenses());
        assert_eq!(stacked.lens_verdicts.len(), 3);
        assert!(
            stacked.lens_verdicts.iter().any(|verdict| {
                verdict.lens.information_scope == ReviewInformationScope::OutputReportOnly
            }) && stacked.lens_verdicts.iter().any(|verdict| {
                verdict.lens.information_scope == ReviewInformationScope::DiffOnly
            })
        );
        review_aggregate_establishes_full_independent_coverage(&stacked)
            .expect("stacked FullChildTranscript + scoped Accept lenses establish coverage");

        let without_full_transcript = accept_aggregate(
            default_supervisor_review_lenses()
                .into_iter()
                .filter(|lens| {
                    lens.information_scope != ReviewInformationScope::FullChildTranscript
                })
                .collect(),
        );
        assert!(without_full_transcript.lens_verdicts.iter().all(|verdict| {
            verdict.lens.information_scope != ReviewInformationScope::FullChildTranscript
        }));
        let error =
            review_aggregate_establishes_full_independent_coverage(&without_full_transcript)
                .expect_err("coverage requires at least one FullChildTranscript Accept");
        assert!(
            error.contains("full-child-transcript"),
            "unexpected coverage refusal: {error}"
        );
    }

    fn commit_all<'repo>(repo: &'repo Repository, message: &str) -> Result<git2::Commit<'repo>> {
        let mut index = repo.index()?;
        index.add_all(["*"], IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = Signature::now("held-out-test", "held-out-test@example.invalid")?;
        let parents: Vec<git2::Commit> = repo
            .head()
            .ok()
            .and_then(|reference| reference.peel_to_commit().ok())
            .into_iter()
            .collect();
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
        let oid = repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parent_refs,
        )?;
        Ok(repo.find_commit(oid)?)
    }
}
