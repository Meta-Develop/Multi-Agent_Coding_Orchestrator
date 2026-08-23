//! Pre-claim viability gate.
//!
//! First slice of issue #92: refuse durable path claims unless repository map,
//! risk report, and runtime evidence are all present. Missing evidence is
//! fail-closed on the Verified/production path. NonpublishableSimulation
//! records a typed synthetic viability decision and proceeds without scanning
//! map/risk evidence that Fake fixtures do not supply. The decision is
//! recorded before any claim token is issued.

use super::*;
use crate::repo_map::RepoMap;
use crate::repo_semantic::{risk_report_for_paths, SemanticRepoMap, SemanticRiskReport};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;

pub(super) const PRECLAIM_DECISIONS_RELATIVE: &str = "preclaim/decisions.jsonl";

#[cfg(test)]
thread_local! {
    static FORCE_MISSING_PRECLAIM_EVIDENCE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(super) struct ForceMissingPreclaimEvidence;

#[cfg(test)]
impl ForceMissingPreclaimEvidence {
    pub(super) fn install() -> Self {
        FORCE_MISSING_PRECLAIM_EVIDENCE.with(|flag| flag.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ForceMissingPreclaimEvidence {
    fn drop(&mut self) {
        FORCE_MISSING_PRECLAIM_EVIDENCE.with(|flag| flag.set(false));
    }
}

/// Whether the candidate may receive a durable path claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimDisposition {
    Claim,
    Reject,
}

/// How the gate obtained the evidence it recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimEvidenceSource {
    Acquired,
    SyntheticSimulation,
}

/// Auditable pre-claim viability decision for one assignment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreclaimDecision {
    pub assignment_id: String,
    pub disposition: PreclaimDisposition,
    pub reason: String,
    pub map_present: bool,
    pub risk_present: bool,
    pub runtime_present: bool,
    pub evidence_source: PreclaimEvidenceSource,
}

impl PreclaimDecision {
    pub(super) const fn allows_path_claim(&self) -> bool {
        matches!(self.disposition, PreclaimDisposition::Claim)
    }
}

/// Run-scoped map/risk/runtime evidence used before claiming paths.
pub(super) struct PreclaimRunEvidence {
    pub(super) repo_map: Option<RepoMap>,
    semantic_map: Option<SemanticRepoMap>,
    pub(super) runtime: Option<SupervisorRuntime>,
    execution_runtime: SupervisorExecutionRuntime,
}

impl PreclaimRunEvidence {
    pub(super) fn acquire(
        repo: &Path,
        runtime: SupervisorRuntime,
        execution_runtime: SupervisorExecutionRuntime,
    ) -> Self {
        #[cfg(test)]
        if FORCE_MISSING_PRECLAIM_EVIDENCE.with(Cell::get) {
            return Self::missing();
        }
        if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation {
            // Fake/simulation fixtures do not carry map/risk artifacts. Do not
            // scan here: discover+walk can escape a temp fixture and stall the
            // scheduler for the repository-map deadline.
            return Self {
                repo_map: None,
                semantic_map: None,
                runtime: Some(runtime),
                execution_runtime,
            };
        }
        Self {
            repo_map: crate::repo_map::scan_repository(repo).ok(),
            semantic_map: crate::repo_semantic::scan_repository(repo).ok(),
            runtime: Some(runtime),
            execution_runtime,
        }
    }

    #[cfg(test)]
    pub(super) fn missing() -> Self {
        Self {
            repo_map: None,
            semantic_map: None,
            runtime: None,
            execution_runtime: SupervisorExecutionRuntime::Verified,
        }
    }

    pub(super) fn risk_for(&self, paths: &[PathBuf]) -> Option<SemanticRiskReport> {
        self.semantic_map
            .as_ref()
            .map(|map| risk_report_for_paths(map, paths.iter()))
    }
}

/// Fail-closed viability gate on the Verified path: every evidence handle must
/// be present. Simulation records a typed synthetic claim instead of parking.
pub(super) fn evaluate_preclaim_viability(
    assignment_id: &str,
    repo_map: Option<&RepoMap>,
    risk_report: Option<&SemanticRiskReport>,
    runtime: Option<SupervisorRuntime>,
    execution_runtime: SupervisorExecutionRuntime,
) -> PreclaimDecision {
    if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation {
        return PreclaimDecision {
            assignment_id: assignment_id.to_string(),
            disposition: PreclaimDisposition::Claim,
            reason: format!(
                "assignment '{assignment_id}' recorded synthetic simulation pre-claim viability"
            ),
            map_present: repo_map.is_some(),
            risk_present: risk_report.is_some(),
            runtime_present: runtime.is_some(),
            evidence_source: PreclaimEvidenceSource::SyntheticSimulation,
        };
    }
    let map_present = repo_map.is_some();
    let risk_present = risk_report.is_some();
    let runtime_present = runtime.is_some();
    let missing = [
        (!map_present).then_some("map"),
        (!risk_present).then_some("risk"),
        (!runtime_present).then_some("runtime"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if missing.is_empty() {
        return PreclaimDecision {
            assignment_id: assignment_id.to_string(),
            disposition: PreclaimDisposition::Claim,
            reason: format!("assignment '{assignment_id}' passed pre-claim viability"),
            map_present,
            risk_present,
            runtime_present,
            evidence_source: PreclaimEvidenceSource::Acquired,
        };
    }
    PreclaimDecision {
        assignment_id: assignment_id.to_string(),
        disposition: PreclaimDisposition::Reject,
        reason: format!(
            "assignment '{assignment_id}' failed closed before path claim: missing {}",
            missing.join(", ")
        ),
        map_present,
        risk_present,
        runtime_present,
        evidence_source: PreclaimEvidenceSource::Acquired,
    }
}

pub(super) fn preclaim_assignment(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    evidence: &PreclaimRunEvidence,
) -> Result<PreclaimDecision> {
    let risk = evidence.risk_for(&assignment.assigned_paths);
    let decision = evaluate_preclaim_viability(
        &assignment.id,
        evidence.repo_map.as_ref(),
        risk.as_ref(),
        evidence.runtime,
        evidence.execution_runtime,
    );
    persist_preclaim_decision(artifacts, assignment, &decision)?;
    Ok(decision)
}

pub(super) fn persist_preclaim_decision(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    decision: &PreclaimDecision,
) -> Result<()> {
    let payload = serde_json::to_value(decision)
        .context("failed to serialize pre-claim viability decision")?;
    with_supervisor_artifacts(artifacts, |writer, journal| {
        writer
            .append_json_line(
                PRECLAIM_DECISIONS_RELATIVE,
                decision,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .context("failed to persist pre-claim viability decision")?;
        record_orchestration_event(
            journal,
            writer,
            &assignment.id,
            None,
            OrchestrationRole::Supervisor,
            OrchestrationEventKind::Gate,
            payload,
        );
        Ok(())
    })
}

pub(super) fn parked_preclaim_outcome(
    assignment: &OrchestratorAssignment,
    decision: &PreclaimDecision,
) -> AssignmentExecutionOutcome {
    AssignmentExecutionOutcome {
        assignment_failed: true,
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "pre-claim viability rejected '{}': {}",
                assignment.id, decision.reason
            ),
            paths: assignment.assigned_paths.clone(),
        }],
        ..AssignmentExecutionOutcome::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn present_map() -> RepoMap {
        RepoMap {
            root: PathBuf::from("."),
            entries: Vec::new(),
        }
    }

    fn present_risk() -> SemanticRiskReport {
        SemanticRiskReport {
            changed_paths: Vec::new(),
            touched_files: Vec::new(),
            touched_symbols: Vec::new(),
            dependency_impacts: Vec::new(),
            impacted_files: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn complete_evidence_allows_path_claim() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            Some(&present_map()),
            Some(&present_risk()),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
        assert_eq!(decision.evidence_source, PreclaimEvidenceSource::Acquired);
        assert!(decision.allows_path_claim());
        assert!(decision.map_present && decision.risk_present && decision.runtime_present);
        assert!(decision.reason.contains("passed pre-claim viability"));
    }

    #[test]
    fn missing_map_fails_closed_on_verified_path() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            None,
            Some(&present_risk()),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Reject);
        assert_eq!(decision.evidence_source, PreclaimEvidenceSource::Acquired);
        assert!(!decision.allows_path_claim());
        assert!(!decision.map_present);
        assert!(decision.reason.contains("missing map"));
        assert!(!decision.reason.contains("risk"));
        assert!(!decision.reason.contains("runtime"));
    }

    #[test]
    fn missing_risk_fails_closed_on_verified_path() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            Some(&present_map()),
            None,
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Reject);
        assert!(!decision.allows_path_claim());
        assert!(!decision.risk_present);
        assert!(decision.reason.contains("missing risk"));
    }

    #[test]
    fn missing_runtime_fails_closed_on_verified_path() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            Some(&present_map()),
            Some(&present_risk()),
            None,
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Reject);
        assert!(!decision.allows_path_claim());
        assert!(!decision.runtime_present);
        assert!(decision.reason.contains("missing runtime"));
    }

    #[test]
    fn missing_all_evidence_lists_every_gap_on_verified_path() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            None,
            None,
            None,
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Reject);
        assert!(!decision.allows_path_claim());
        assert!(decision.reason.contains("missing map, risk, runtime"));
        assert_eq!(
            (
                decision.map_present,
                decision.risk_present,
                decision.runtime_present
            ),
            (false, false, false)
        );
    }

    #[test]
    fn simulation_records_synthetic_claim_when_evidence_is_missing() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            None,
            None,
            None,
            SupervisorExecutionRuntime::NonpublishableSimulation,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
        assert_eq!(
            decision.evidence_source,
            PreclaimEvidenceSource::SyntheticSimulation
        );
        assert!(decision.allows_path_claim());
        assert!(decision
            .reason
            .contains("synthetic simulation pre-claim viability"));
        assert!(!decision.map_present);
        assert!(!decision.risk_present);
        assert!(!decision.runtime_present);
    }

    #[test]
    fn decision_round_trips_for_the_recorded_ledger() {
        let decision = evaluate_preclaim_viability(
            "child-a",
            None,
            None,
            None,
            SupervisorExecutionRuntime::Verified,
        );
        let encoded = serde_json::to_string(&decision).expect("serialize decision");
        let decoded: PreclaimDecision =
            serde_json::from_str(&encoded).expect("deserialize decision");
        assert_eq!(decoded, decision);
    }
}
