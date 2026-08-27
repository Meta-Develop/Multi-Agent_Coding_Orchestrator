//! Deterministic pre-claim viability gate.
//!
//! `NonpublishableSimulation` records a typed, all-positive synthetic viability
//! assessment without production map/risk/environment inference, then still
//! applies requested-plan policy binding and operator Park. Verified execution
//! requires acquired repository-map, risk, and runtime evidence plus real
//! positive answers for limited scope, a clear verification path, and autonomous
//! completion. A non-claim decision is always a reversible, read-only park;
//! rejection is classification evidence, never mutation authority.

use super::*;
use crate::repo_map::{RepoEntryKind, RepoMap};
use crate::repo_semantic::{risk_report_for_paths, SemanticRepoMap, SemanticRiskReport};
use serde::{Deserialize, Serialize};

pub(super) const PRECLAIM_DECISIONS_RELATIVE: &str = "preclaim/decisions.jsonl";
const PRECLAIM_RESERVED_NAMESPACE: &str = "maco-preclaim";
const PRECLAIM_DIRECTIVE_PREFIX: &str = "maco-preclaim-v1:";
const MAX_DETERMINISTIC_SCOPE_PATHS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimDisposition {
    Claim,
    Park,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimRejectionBucket {
    Unclear,
    NeedsDecision,
    Duplicate,
    Invalid,
    OutOfScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimTriageOutcome {
    Viable,
    Ambiguous,
    Rejected,
    /// A caller-authenticated requested-plan directive decided the disposition.
    OperatorOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimConfidence {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ViabilityFinding {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreclaimViabilityDimensions {
    pub limited_scope: ViabilityFinding,
    pub clear_verification_path: ViabilityFinding,
    pub autonomously_completable: ViabilityFinding,
}

impl PreclaimViabilityDimensions {
    const fn all_positive(self) -> bool {
        matches!(self.limited_scope, ViabilityFinding::Yes)
            && matches!(self.clear_verification_path, ViabilityFinding::Yes)
            && matches!(self.autonomously_completable, ViabilityFinding::Yes)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimAmbiguityBias {
    /// Ambiguity is recoverable, while an erroneous claim creates worker and
    /// worktree state. Prefer the reversible action when evidence is incomplete.
    #[default]
    Park,
    /// Classify an ambiguous assessment as rejected while still parking it.
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimOverrideDisposition {
    Claim,
    Park,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedPreclaimOverride {
    pub disposition: PreclaimOverrideDisposition,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedPreclaimDirective {
    #[serde(default)]
    ambiguity_bias: Option<PreclaimAmbiguityBias>,
    #[serde(default)]
    operator_override: Option<RecordedPreclaimOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPreclaimPolicy {
    ambiguity_bias: PreclaimAmbiguityBias,
    operator_override: Option<RecordedPreclaimOverride>,
}

impl Default for ResolvedPreclaimPolicy {
    fn default() -> Self {
        Self {
            ambiguity_bias: PreclaimAmbiguityBias::Park,
            operator_override: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreclaimPolicyResolution {
    Resolved(ResolvedPreclaimPolicy),
    FailClosed {
        authority: PreclaimDecisionAuthority,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum PreclaimDecisionAuthority {
    DeterministicPolicy,
    /// Caller-authenticated requested-plan policy with an exact assignment binding.
    Operator,
    /// Assignment task and notes are generic, untrusted scheduler inputs. They
    /// cannot carry acceptance-gate policy or an operator's provenance.
    UntrustedAssignmentInput,
    Model {
        capability: ModelCapabilityClass,
    },
}

impl PreclaimDecisionAuthority {
    fn may_decide_acceptance(self) -> bool {
        match self {
            Self::DeterministicPolicy | Self::Operator => true,
            Self::UntrustedAssignmentInput => false,
            Self::Model { capability } => {
                capability >= OrchestrationPhase::GateClassification.required_model_capability()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreclaimEvidenceSource {
    Acquired,
    SyntheticSimulation,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreclaimDecision {
    pub assignment_id: String,
    pub disposition: PreclaimDisposition,
    pub triage_outcome: PreclaimTriageOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_bucket: Option<PreclaimRejectionBucket>,
    pub confidence: PreclaimConfidence,
    pub dimensions: PreclaimViabilityDimensions,
    pub ambiguity_bias: PreclaimAmbiguityBias,
    pub authority: PreclaimDecisionAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_override: Option<RecordedPreclaimOverride>,
    pub parking_reversible: bool,
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
        if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreclaimAssessment {
    dimensions: PreclaimViabilityDimensions,
    rejection_bucket: Option<PreclaimRejectionBucket>,
    confidence: PreclaimConfidence,
    authority: PreclaimDecisionAuthority,
    reason: String,
}

trait PreclaimAssessmentProvider {
    fn assess(
        &self,
        assignment: &OrchestratorAssignment,
        requested_assignments: &[OrchestratorAssignment],
        repo_map: Option<&RepoMap>,
        risk_report: Option<&SemanticRiskReport>,
    ) -> PreclaimAssessment;
}

struct DeterministicPreclaimProvider;

struct SyntheticSimulationPreclaimProvider;

impl PreclaimAssessmentProvider for SyntheticSimulationPreclaimProvider {
    fn assess(
        &self,
        _: &OrchestratorAssignment,
        _: &[OrchestratorAssignment],
        _: Option<&RepoMap>,
        _: Option<&SemanticRiskReport>,
    ) -> PreclaimAssessment {
        PreclaimAssessment {
            dimensions: PreclaimViabilityDimensions {
                limited_scope: ViabilityFinding::Yes,
                clear_verification_path: ViabilityFinding::Yes,
                autonomously_completable: ViabilityFinding::Yes,
            },
            rejection_bucket: None,
            confidence: PreclaimConfidence::High,
            authority: PreclaimDecisionAuthority::DeterministicPolicy,
            reason: concat!(
                "synthetic simulation viability dimensions: limited_scope=yes, ",
                "clear_verification_path=yes, autonomously_completable=yes"
            )
            .to_string(),
        }
    }
}

impl PreclaimAssessmentProvider for DeterministicPreclaimProvider {
    fn assess(
        &self,
        assignment: &OrchestratorAssignment,
        requested_assignments: &[OrchestratorAssignment],
        repo_map: Option<&RepoMap>,
        risk_report: Option<&SemanticRiskReport>,
    ) -> PreclaimAssessment {
        let limited_scope = deterministic_limited_scope(assignment, repo_map);
        let clear_verification_path = deterministic_verification_path(
            assignment,
            requested_assignments,
            repo_map,
            risk_report,
        );
        let autonomously_completable = deterministic_autonomous_completion(assignment);
        let dimensions = PreclaimViabilityDimensions {
            limited_scope,
            clear_verification_path,
            autonomously_completable,
        };
        let rejection_bucket = deterministic_bucket(assignment, dimensions);
        let confidence = if dimensions.all_positive()
            || dimensions.limited_scope == ViabilityFinding::No
            || dimensions.autonomously_completable == ViabilityFinding::No
        {
            PreclaimConfidence::High
        } else {
            PreclaimConfidence::Low
        };
        PreclaimAssessment {
            dimensions,
            rejection_bucket,
            confidence,
            authority: PreclaimDecisionAuthority::DeterministicPolicy,
            reason: format!(
                "deterministic viability dimensions: limited_scope={}, clear_verification_path={}, autonomously_completable={}",
                finding_name(limited_scope),
                finding_name(clear_verification_path),
                finding_name(autonomously_completable),
            ),
        }
    }
}

fn finding_name(finding: ViabilityFinding) -> &'static str {
    match finding {
        ViabilityFinding::Yes => "yes",
        ViabilityFinding::No => "no",
        ViabilityFinding::Unknown => "unknown",
    }
}

fn deterministic_limited_scope(
    assignment: &OrchestratorAssignment,
    repo_map: Option<&RepoMap>,
) -> ViabilityFinding {
    if assignment.assigned_paths.is_empty()
        || assignment.assigned_paths.len() > MAX_DETERMINISTIC_SCOPE_PATHS
        || assignment
            .assigned_paths
            .iter()
            .any(|path| path.as_os_str() == ".")
    {
        return ViabilityFinding::No;
    }
    let Some(repo_map) = repo_map else {
        return ViabilityFinding::Yes;
    };
    if assignment.assigned_paths.iter().any(|path| {
        repo_map
            .entries
            .iter()
            .find(|entry| entry.path == *path)
            .is_some_and(|entry| entry.kind == RepoEntryKind::Directory)
    }) {
        ViabilityFinding::No
    } else {
        ViabilityFinding::Yes
    }
}

fn deterministic_verification_path(
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
    repo_map: Option<&RepoMap>,
    risk_report: Option<&SemanticRiskReport>,
) -> ViabilityFinding {
    // Production callers supply the already validated requested plan. Require
    // the typed declaration to remain uniquely and exactly bound to that plan;
    // current assignment input alone cannot manufacture this verification path.
    if requested_licensed_breakage_contract(assignment, requested_assignments) {
        return ViabilityFinding::Yes;
    }
    let assignment_names_exact_test_target = assignment
        .assigned_paths
        .iter()
        .any(|path| is_recognized_test_target(path));

    let Some(repo_map) = repo_map else {
        return ViabilityFinding::Unknown;
    };
    if assignment_names_exact_test_target
        && assignment
            .assigned_paths
            .iter()
            .any(|path| is_recognized_test_target(path) && mapped_regular_file(repo_map, path))
    {
        return ViabilityFinding::Yes;
    }

    let Some(risk_report) = risk_report else {
        return ViabilityFinding::Unknown;
    };
    if !risk_is_bound_to_assignment(risk_report, &assignment.assigned_paths) {
        return ViabilityFinding::Unknown;
    }

    let related_test_target = risk_report.dependency_impacts.iter().any(|impact| {
        assignment.assigned_paths.contains(&impact.changed_path)
            && impact.related_file.as_ref().is_some_and(|related_file| {
                risk_report.impacted_files.contains(related_file)
                    && is_recognized_test_target(related_file)
                    && mapped_regular_file(repo_map, related_file)
            })
    });
    if related_test_target {
        ViabilityFinding::Yes
    } else {
        ViabilityFinding::Unknown
    }
}

fn requested_licensed_breakage_contract(
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
) -> bool {
    let mut matching = requested_assignments
        .iter()
        .filter(|requested| requested.id == assignment.id);
    let Some(requested) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && requested.phase == assignment.phase
        && requested.role == assignment.role
        && requested.assigned_paths == assignment.assigned_paths
        && assignment.licensed_breakage.is_some()
        && requested.licensed_breakage == assignment.licensed_breakage
}

fn mapped_regular_file(repo_map: &RepoMap, path: &Path) -> bool {
    repo_map
        .entries
        .iter()
        .any(|entry| entry.path == path && entry.kind == RepoEntryKind::File)
}

fn risk_is_bound_to_assignment(
    risk_report: &SemanticRiskReport,
    assigned_paths: &[PathBuf],
) -> bool {
    let mut expected = assigned_paths.to_vec();
    expected.sort();
    expected.dedup();
    let mut recorded = risk_report.changed_paths.clone();
    recorded.sort();
    recorded.dedup();
    recorded == expected
}

fn is_recognized_test_target(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    let runnable_test_source = matches!(
        extension.to_ascii_lowercase().as_str(),
        "rs" | "py" | "go" | "java" | "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx"
    );
    if !runnable_test_source {
        return false;
    }
    let parent_names_tests = path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|component| {
                matches!(
                    component.to_ascii_lowercase().as_str(),
                    "test" | "tests" | "__tests__" | "spec" | "specs"
                )
            })
        })
    });
    if parent_names_tests {
        return true;
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    file_name == "tests.rs"
        || file_name.starts_with("test_")
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
        || [
            "_test.rs",
            "_test.go",
            "_test.py",
            "test.java",
            "tests.java",
        ]
        .iter()
        .any(|suffix| file_name.ends_with(suffix))
}

fn deterministic_autonomous_completion(assignment: &OrchestratorAssignment) -> ViabilityFinding {
    if assignment_requires_environment(assignment) {
        ViabilityFinding::No
    } else {
        ViabilityFinding::Yes
    }
}

fn assignment_requires_environment(assignment: &OrchestratorAssignment) -> bool {
    !assignment.environment_requirements.is_empty()
        || assignment
            .worker_assignments
            .iter()
            .any(|worker| !worker.environment_requirements.is_empty())
}

fn deterministic_bucket(
    assignment: &OrchestratorAssignment,
    dimensions: PreclaimViabilityDimensions,
) -> Option<PreclaimRejectionBucket> {
    let unique_path_count = assignment
        .assigned_paths
        .iter()
        .collect::<BTreeSet<_>>()
        .len();
    if assignment.id.trim().is_empty() || assignment.assigned_paths.is_empty() {
        Some(PreclaimRejectionBucket::Invalid)
    } else if unique_path_count != assignment.assigned_paths.len() {
        Some(PreclaimRejectionBucket::Duplicate)
    } else if dimensions.limited_scope == ViabilityFinding::No {
        Some(PreclaimRejectionBucket::OutOfScope)
    } else if dimensions.autonomously_completable == ViabilityFinding::No {
        Some(PreclaimRejectionBucket::NeedsDecision)
    } else if dimensions.clear_verification_path != ViabilityFinding::Yes
        || dimensions.limited_scope != ViabilityFinding::Yes
    {
        Some(PreclaimRejectionBucket::Unclear)
    } else {
        None
    }
}

fn reserved_preclaim_input_location(assignment: &OrchestratorAssignment) -> Option<&'static str> {
    let task_contains_reserved = assignment
        .task
        .as_deref()
        .is_some_and(contains_reserved_preclaim_namespace);
    let notes_contain_reserved = assignment
        .notes
        .as_deref()
        .is_some_and(contains_reserved_preclaim_namespace);
    match (task_contains_reserved, notes_contain_reserved) {
        (true, true) => Some("task and notes"),
        (true, false) => Some("task"),
        (false, true) => Some("notes"),
        (false, false) => None,
    }
}

fn contains_reserved_preclaim_namespace(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(PRECLAIM_RESERVED_NAMESPACE)
}

fn resolve_preclaim_policy(
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
) -> PreclaimPolicyResolution {
    let mut matching = requested_assignments
        .iter()
        .filter(|requested| requested.id == assignment.id);
    let Some(requested) = matching.next() else {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' has no unique requested-plan identity binding",
                assignment.id
            ),
        );
    };
    if matching.next().is_some() {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' has a duplicate requested-plan identity binding",
                assignment.id
            ),
        );
    }

    let mut mismatches = Vec::new();
    if requested.phase != assignment.phase {
        mismatches.push("phase");
    }
    if requested.role != assignment.role {
        mismatches.push("role");
    }
    if requested.assigned_paths != assignment.assigned_paths {
        mismatches.push("assigned_paths");
    }
    if requested.licensed_breakage != assignment.licensed_breakage {
        mismatches.push("licensed_breakage");
    }
    if requested.environment_requirements.is_empty()
        != assignment.environment_requirements.is_empty()
    {
        mismatches.push("environment_requirements");
    }
    let requested_worker_requires_environment = requested
        .worker_assignments
        .iter()
        .any(|worker| !worker.environment_requirements.is_empty());
    let assignment_worker_requires_environment = assignment
        .worker_assignments
        .iter()
        .any(|worker| !worker.environment_requirements.is_empty());
    if requested_worker_requires_environment != assignment_worker_requires_environment {
        mismatches.push("worker_environment_requirements");
    }
    if !mismatches.is_empty() {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' does not exactly match its requested-plan {} binding",
                assignment.id,
                mismatches.join(", ")
            ),
        );
    }

    if requested
        .task
        .as_deref()
        .is_some_and(contains_reserved_preclaim_namespace)
    {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' placed reserved pre-claim policy outside requested-plan notes",
                assignment.id
            ),
        );
    }

    let Some(requested_notes) = requested
        .notes
        .as_deref()
        .filter(|notes| contains_reserved_preclaim_namespace(notes))
    else {
        if let Some(location) = reserved_preclaim_input_location(assignment) {
            return fail_closed_policy(
                PreclaimDecisionAuthority::UntrustedAssignmentInput,
                format!(
                    "assignment '{}' supplied reserved pre-claim policy only through current assignment {location}",
                    assignment.id
                ),
            );
        }
        return PreclaimPolicyResolution::Resolved(ResolvedPreclaimPolicy::default());
    };

    if assignment
        .task
        .as_deref()
        .is_some_and(contains_reserved_preclaim_namespace)
    {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' supplied reserved pre-claim policy through current assignment task",
                assignment.id
            ),
        );
    }
    if assignment
        .notes
        .as_deref()
        .is_some_and(contains_reserved_preclaim_namespace)
        && assignment.notes != requested.notes
    {
        return fail_closed_policy(
            PreclaimDecisionAuthority::UntrustedAssignmentInput,
            format!(
                "assignment '{}' current notes do not match the trusted requested-plan directive",
                assignment.id
            ),
        );
    }

    parse_requested_preclaim_directive(assignment, requested_notes)
}

fn parse_requested_preclaim_directive(
    assignment: &OrchestratorAssignment,
    notes: &str,
) -> PreclaimPolicyResolution {
    let trimmed = notes.trim();
    if !trimmed.starts_with(PRECLAIM_DIRECTIVE_PREFIX)
        || trimmed.matches(PRECLAIM_DIRECTIVE_PREFIX).count() != 1
    {
        return invalid_requested_directive(assignment);
    }
    let Some(payload) = trimmed.strip_prefix(PRECLAIM_DIRECTIVE_PREFIX) else {
        return invalid_requested_directive(assignment);
    };
    let Ok(mut directive) = serde_json::from_str::<RequestedPreclaimDirective>(payload) else {
        return invalid_requested_directive(assignment);
    };
    if directive.ambiguity_bias.is_none() && directive.operator_override.is_none() {
        return invalid_requested_directive(assignment);
    }
    if let Some(operator_override) = directive.operator_override.as_mut() {
        let rationale = operator_override.rationale.trim();
        if rationale.is_empty() {
            return invalid_requested_directive(assignment);
        }
        operator_override.rationale = rationale.to_string();
    }
    PreclaimPolicyResolution::Resolved(ResolvedPreclaimPolicy {
        ambiguity_bias: directive.ambiguity_bias.unwrap_or_default(),
        operator_override: directive.operator_override,
    })
}

fn invalid_requested_directive(assignment: &OrchestratorAssignment) -> PreclaimPolicyResolution {
    fail_closed_policy(
        PreclaimDecisionAuthority::DeterministicPolicy,
        format!(
            "assignment '{}' has an invalid requested-plan maco-preclaim-v1 directive",
            assignment.id
        ),
    )
}

fn fail_closed_policy(
    authority: PreclaimDecisionAuthority,
    reason: String,
) -> PreclaimPolicyResolution {
    PreclaimPolicyResolution::FailClosed { authority, reason }
}

fn evaluate_with_provider(
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
    repo_map: Option<&RepoMap>,
    risk_report: Option<&SemanticRiskReport>,
    runtime: Option<SupervisorRuntime>,
    execution_runtime: SupervisorExecutionRuntime,
    provider: &impl PreclaimAssessmentProvider,
) -> PreclaimDecision {
    let map_present = repo_map.is_some();
    let risk_present = risk_report.is_some();
    let runtime_present = runtime.is_some();
    let evidence_source =
        if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation {
            PreclaimEvidenceSource::SyntheticSimulation
        } else {
            PreclaimEvidenceSource::Acquired
        };
    let assessment = provider.assess(assignment, requested_assignments, repo_map, risk_report);
    let dimensions = assessment.dimensions;
    let rejection_bucket = assessment.rejection_bucket;
    let confidence = assessment.confidence;
    let assessment_reason = assessment.reason.clone();
    let policy = match resolve_preclaim_policy(assignment, requested_assignments) {
        PreclaimPolicyResolution::Resolved(policy) => policy,
        PreclaimPolicyResolution::FailClosed { authority, reason } => {
            return parked_decision(
                assignment,
                PreclaimTriageOutcome::Rejected,
                rejection_bucket.or(Some(PreclaimRejectionBucket::Unclear)),
                PreclaimConfidence::High,
                dimensions,
                PreclaimAmbiguityBias::Park,
                authority,
                None,
                reason,
                map_present,
                risk_present,
                runtime_present,
                evidence_source,
            );
        }
    };
    let ambiguity_bias = policy.ambiguity_bias;
    let operator_override = policy.operator_override;
    let evidence_complete = execution_runtime
        == SupervisorExecutionRuntime::NonpublishableSimulation
        || (map_present && risk_present && runtime_present);
    let operator_claim_lacks_acquired_evidence = operator_override.as_ref().is_some_and(|value| {
        value.disposition == PreclaimOverrideDisposition::Claim
            && !(map_present && risk_present && runtime_present)
    });

    if !evidence_complete || operator_claim_lacks_acquired_evidence {
        let missing = [
            (!map_present).then_some("map"),
            (!risk_present).then_some("risk"),
            (!runtime_present).then_some("runtime"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let has_operator_override = operator_override.is_some();
        return parked_decision(
            assignment,
            if has_operator_override {
                PreclaimTriageOutcome::OperatorOverride
            } else {
                PreclaimTriageOutcome::Rejected
            },
            Some(PreclaimRejectionBucket::Unclear),
            PreclaimConfidence::High,
            dimensions,
            ambiguity_bias,
            if has_operator_override {
                PreclaimDecisionAuthority::Operator
            } else {
                assessment.authority
            },
            operator_override,
            format!(
                "assignment '{}' failed closed before path claim because required evidence is missing {}",
                assignment.id,
                missing.join(", ")
            ),
            map_present,
            risk_present,
            runtime_present,
            evidence_source,
        );
    }

    if operator_override
        .as_ref()
        .is_some_and(|value| value.disposition == PreclaimOverrideDisposition::Park)
    {
        return parked_decision(
            assignment,
            PreclaimTriageOutcome::OperatorOverride,
            rejection_bucket,
            confidence,
            dimensions,
            ambiguity_bias,
            PreclaimDecisionAuthority::Operator,
            operator_override,
            format!(
                "assignment '{}' parked by authenticated requested-plan operator policy",
                assignment.id
            ),
            map_present,
            risk_present,
            runtime_present,
            evidence_source,
        );
    }

    if !assessment.authority.may_decide_acceptance() {
        return parked_decision(
            assignment,
            PreclaimTriageOutcome::Ambiguous,
            rejection_bucket.or(Some(PreclaimRejectionBucket::Unclear)),
            PreclaimConfidence::High,
            dimensions,
            ambiguity_bias,
            assessment.authority,
            operator_override,
            format!(
                "{}; model authority is below the acceptance-gate capability floor",
                assessment_reason
            ),
            map_present,
            risk_present,
            runtime_present,
            evidence_source,
        );
    }

    if let Some(operator_override) = operator_override {
        if operator_claim_may_admit(dimensions, rejection_bucket, confidence) {
            return claim_decision(
                assignment,
                PreclaimTriageOutcome::OperatorOverride,
                rejection_bucket,
                confidence,
                dimensions,
                ambiguity_bias,
                PreclaimDecisionAuthority::Operator,
                Some(operator_override),
                format!(
                    "assignment '{}' admitted by authenticated requested-plan operator policy",
                    assignment.id
                ),
                map_present,
                risk_present,
                runtime_present,
                evidence_source,
            );
        }
        return parked_decision(
            assignment,
            PreclaimTriageOutcome::OperatorOverride,
            rejection_bucket.or(Some(PreclaimRejectionBucket::Unclear)),
            confidence,
            dimensions,
            ambiguity_bias,
            PreclaimDecisionAuthority::Operator,
            Some(operator_override),
            format!(
                "assignment '{}' operator claim policy requires a genuinely ambiguous viability assessment",
                assignment.id
            ),
            map_present,
            risk_present,
            runtime_present,
            evidence_source,
        );
    }

    if dimensions.all_positive() && rejection_bucket.is_none() {
        return claim_decision(
            assignment,
            PreclaimTriageOutcome::Viable,
            None,
            confidence,
            dimensions,
            ambiguity_bias,
            assessment.authority,
            None,
            format!(
                "assignment '{}' passed pre-claim viability: {}",
                assignment.id, assessment_reason
            ),
            map_present,
            risk_present,
            runtime_present,
            evidence_source,
        );
    }

    let rejected =
        confidence == PreclaimConfidence::High || ambiguity_bias == PreclaimAmbiguityBias::Reject;
    parked_decision(
        assignment,
        if rejected {
            PreclaimTriageOutcome::Rejected
        } else {
            PreclaimTriageOutcome::Ambiguous
        },
        rejection_bucket.or(Some(PreclaimRejectionBucket::Unclear)),
        confidence,
        dimensions,
        ambiguity_bias,
        assessment.authority,
        None,
        format!(
            "assignment '{}' parked before path claim: {}",
            assignment.id, assessment_reason
        ),
        map_present,
        risk_present,
        runtime_present,
        evidence_source,
    )
}

fn operator_claim_may_admit(
    dimensions: PreclaimViabilityDimensions,
    rejection_bucket: Option<PreclaimRejectionBucket>,
    confidence: PreclaimConfidence,
) -> bool {
    let findings = [
        dimensions.limited_scope,
        dimensions.clear_verification_path,
        dimensions.autonomously_completable,
    ];
    confidence == PreclaimConfidence::Low
        && rejection_bucket == Some(PreclaimRejectionBucket::Unclear)
        && findings.contains(&ViabilityFinding::Unknown)
        && !findings.contains(&ViabilityFinding::No)
}

#[allow(clippy::too_many_arguments)]
fn claim_decision(
    assignment: &OrchestratorAssignment,
    triage_outcome: PreclaimTriageOutcome,
    rejection_bucket: Option<PreclaimRejectionBucket>,
    confidence: PreclaimConfidence,
    dimensions: PreclaimViabilityDimensions,
    ambiguity_bias: PreclaimAmbiguityBias,
    authority: PreclaimDecisionAuthority,
    operator_override: Option<RecordedPreclaimOverride>,
    reason: String,
    map_present: bool,
    risk_present: bool,
    runtime_present: bool,
    evidence_source: PreclaimEvidenceSource,
) -> PreclaimDecision {
    PreclaimDecision {
        assignment_id: assignment.id.clone(),
        disposition: PreclaimDisposition::Claim,
        triage_outcome,
        rejection_bucket,
        confidence,
        dimensions,
        ambiguity_bias,
        authority,
        operator_override,
        parking_reversible: false,
        reason,
        map_present,
        risk_present,
        runtime_present,
        evidence_source,
    }
}

#[allow(clippy::too_many_arguments)]
fn parked_decision(
    assignment: &OrchestratorAssignment,
    triage_outcome: PreclaimTriageOutcome,
    rejection_bucket: Option<PreclaimRejectionBucket>,
    confidence: PreclaimConfidence,
    dimensions: PreclaimViabilityDimensions,
    ambiguity_bias: PreclaimAmbiguityBias,
    authority: PreclaimDecisionAuthority,
    operator_override: Option<RecordedPreclaimOverride>,
    reason: String,
    map_present: bool,
    risk_present: bool,
    runtime_present: bool,
    evidence_source: PreclaimEvidenceSource,
) -> PreclaimDecision {
    PreclaimDecision {
        assignment_id: assignment.id.clone(),
        disposition: PreclaimDisposition::Park,
        triage_outcome,
        rejection_bucket,
        confidence,
        dimensions,
        ambiguity_bias,
        authority,
        operator_override,
        parking_reversible: true,
        reason,
        map_present,
        risk_present,
        runtime_present,
        evidence_source,
    }
}

pub(super) fn evaluate_preclaim_viability(
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
    repo_map: Option<&RepoMap>,
    risk_report: Option<&SemanticRiskReport>,
    runtime: Option<SupervisorRuntime>,
    execution_runtime: SupervisorExecutionRuntime,
) -> PreclaimDecision {
    match execution_runtime {
        SupervisorExecutionRuntime::NonpublishableSimulation => evaluate_with_provider(
            assignment,
            requested_assignments,
            repo_map,
            risk_report,
            runtime,
            execution_runtime,
            &SyntheticSimulationPreclaimProvider,
        ),
        SupervisorExecutionRuntime::Verified => evaluate_with_provider(
            assignment,
            requested_assignments,
            repo_map,
            risk_report,
            runtime,
            execution_runtime,
            &DeterministicPreclaimProvider,
        ),
    }
}

pub(super) fn preclaim_assignment(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
    evidence: &PreclaimRunEvidence,
) -> Result<PreclaimDecision> {
    let risk = evidence.risk_for(&assignment.assigned_paths);
    let decision = evaluate_preclaim_viability(
        assignment,
        requested_assignments,
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
        if !orchestration_journal_observable(journal) {
            bail!(
                "pre-claim viability decision requires an observable orchestration event journal"
            );
        }
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
        if !orchestration_journal_observable(journal) {
            bail!("failed to persist pre-claim orchestration Gate event");
        }
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
                "pre-claim viability parked '{}': {}",
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
    use crate::external_agent::EnvironmentNetworkAccess;
    use crate::repo_map::{RepoGitStatus, RepoMapEntry};
    use crate::repo_semantic::{
        SemanticDependency, SemanticDependencyDirection, SemanticDependencyImpact,
        SemanticDependencyKind, SourceSpan,
    };

    fn assignment() -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: "child-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from("tests/preclaim.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some("update the bounded test target".to_string()),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }
    }

    fn present_map() -> RepoMap {
        RepoMap {
            root: PathBuf::from("."),
            entries: vec![
                RepoMapEntry {
                    path: PathBuf::from("README.md"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "documentation".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
                RepoMapEntry {
                    path: PathBuf::from("Cargo.toml"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "manifest".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
                RepoMapEntry {
                    path: PathBuf::from("src/lib.rs"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "source".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
                RepoMapEntry {
                    path: PathBuf::from("tests/preclaim.rs"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "source".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
                RepoMapEntry {
                    path: PathBuf::from("tests/related.rs"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "source".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
                RepoMapEntry {
                    path: PathBuf::from("tests/unrelated.rs"),
                    kind: RepoEntryKind::File,
                    size_bytes: Some(1),
                    category: "source".to_string(),
                    git_status: RepoGitStatus::Clean,
                },
            ],
        }
    }

    fn present_risk() -> SemanticRiskReport {
        risk_for_path("tests/preclaim.rs")
    }

    fn risk_for_path(path: &str) -> SemanticRiskReport {
        SemanticRiskReport {
            changed_paths: vec![PathBuf::from(path)],
            touched_files: Vec::new(),
            touched_symbols: Vec::new(),
            dependency_impacts: Vec::new(),
            impacted_files: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn related_test_risk(changed_path: &str, related_test: &str) -> SemanticRiskReport {
        let changed_path = PathBuf::from(changed_path);
        let related_test = PathBuf::from(related_test);
        SemanticRiskReport {
            changed_paths: vec![changed_path.clone()],
            touched_files: Vec::new(),
            touched_symbols: Vec::new(),
            dependency_impacts: vec![SemanticDependencyImpact {
                direction: SemanticDependencyDirection::Incoming,
                changed_path: changed_path.clone(),
                related_file: Some(related_test.clone()),
                dependency: SemanticDependency {
                    from_file: related_test.clone(),
                    from_module: Vec::new(),
                    to: "crate::subject".to_string(),
                    to_file: Some(changed_path),
                    kind: SemanticDependencyKind::Import,
                    span: SourceSpan {
                        start_byte: 0,
                        end_byte: 1,
                        start_line: 1,
                        end_line: 1,
                        signature_end_line: 1,
                    },
                },
            }],
            impacted_files: vec![related_test],
            errors: Vec::new(),
        }
    }

    fn evaluate(assignment: &OrchestratorAssignment) -> PreclaimDecision {
        evaluate_with_requested(assignment, std::slice::from_ref(assignment))
    }

    fn evaluate_with_requested(
        assignment: &OrchestratorAssignment,
        requested_assignments: &[OrchestratorAssignment],
    ) -> PreclaimDecision {
        evaluate_preclaim_viability(
            assignment,
            requested_assignments,
            Some(&present_map()),
            Some(&present_risk()),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        )
    }

    fn set_directive(assignment: &mut OrchestratorAssignment, directive: &str) {
        assignment.notes = Some(format!("{PRECLAIM_DIRECTIVE_PREFIX}{directive}"));
    }

    fn assert_policy_binding_failure(
        assignment: &OrchestratorAssignment,
        requested_assignments: &[OrchestratorAssignment],
        reason_fragment: &str,
    ) {
        let decision = evaluate_with_requested(assignment, requested_assignments);
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert_eq!(
            decision.authority,
            PreclaimDecisionAuthority::UntrustedAssignmentInput
        );
        assert!(
            decision.reason.contains(reason_fragment),
            "{}",
            decision.reason
        );
        assert!(decision.operator_override.is_none());
    }

    #[derive(Clone)]
    struct FakeProvider(PreclaimAssessment);

    impl PreclaimAssessmentProvider for FakeProvider {
        fn assess(
            &self,
            _: &OrchestratorAssignment,
            _: &[OrchestratorAssignment],
            _: Option<&RepoMap>,
            _: Option<&SemanticRiskReport>,
        ) -> PreclaimAssessment {
            self.0.clone()
        }
    }

    fn fake_rejection(bucket: PreclaimRejectionBucket) -> FakeProvider {
        FakeProvider(PreclaimAssessment {
            dimensions: PreclaimViabilityDimensions {
                limited_scope: ViabilityFinding::No,
                clear_verification_path: ViabilityFinding::No,
                autonomously_completable: ViabilityFinding::No,
            },
            rejection_bucket: Some(bucket),
            confidence: PreclaimConfidence::High,
            authority: PreclaimDecisionAuthority::DeterministicPolicy,
            reason: "deterministic fake rejection".to_string(),
        })
    }

    #[test]
    fn complete_evidence_and_dimensions_allow_path_claim() {
        let decision = evaluate(&assignment());
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
        assert_eq!(decision.triage_outcome, PreclaimTriageOutcome::Viable);
        assert!(decision.dimensions.all_positive());
        assert!(decision.allows_path_claim());
    }

    #[test]
    fn fake_provider_covers_every_typed_rejection_bucket() {
        for bucket in [
            PreclaimRejectionBucket::Unclear,
            PreclaimRejectionBucket::NeedsDecision,
            PreclaimRejectionBucket::Duplicate,
            PreclaimRejectionBucket::Invalid,
            PreclaimRejectionBucket::OutOfScope,
        ] {
            let candidate = assignment();
            let requested = [candidate.clone()];
            let decision = evaluate_with_provider(
                &candidate,
                &requested,
                Some(&present_map()),
                Some(&present_risk()),
                Some(SupervisorRuntime::Fake),
                SupervisorExecutionRuntime::Verified,
                &fake_rejection(bucket),
            );
            assert_eq!(decision.disposition, PreclaimDisposition::Park);
            assert_eq!(decision.triage_outcome, PreclaimTriageOutcome::Rejected);
            assert_eq!(decision.rejection_bucket, Some(bucket));
            assert!(decision.parking_reversible);
        }
    }

    fn assert_deterministic_bucket(
        assignment: &OrchestratorAssignment,
        map: &RepoMap,
        expected: PreclaimRejectionBucket,
    ) {
        let requested = [assignment.clone()];
        let decision = evaluate_preclaim_viability(
            assignment,
            &requested,
            Some(map),
            Some(&present_risk()),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert_eq!(decision.rejection_bucket, Some(expected));
        assert!(decision.parking_reversible);
    }

    #[test]
    fn unclear_bucket_fixture_has_no_assignment_specific_verification() {
        let mut unclear = assignment();
        unclear.assigned_paths = vec![PathBuf::from("README.md")];
        unclear.task = Some("update the bounded file".to_string());
        assert_deterministic_bucket(&unclear, &present_map(), PreclaimRejectionBucket::Unclear);
    }

    #[test]
    fn needs_decision_bucket_fixture_requires_environment_authority() {
        let mut needs_decision = assignment();
        needs_decision.environment_requirements = vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
        assert_deterministic_bucket(
            &needs_decision,
            &present_map(),
            PreclaimRejectionBucket::NeedsDecision,
        );
    }

    #[test]
    fn duplicate_bucket_fixture_repeats_an_identical_scope() {
        let mut duplicate = assignment();
        duplicate
            .assigned_paths
            .push(PathBuf::from("tests/preclaim.rs"));
        assert_deterministic_bucket(
            &duplicate,
            &present_map(),
            PreclaimRejectionBucket::Duplicate,
        );
    }

    #[test]
    fn invalid_bucket_fixture_has_no_assignment_scope() {
        let mut invalid = assignment();
        invalid.assigned_paths.clear();
        assert_deterministic_bucket(&invalid, &present_map(), PreclaimRejectionBucket::Invalid);
    }

    #[test]
    fn out_of_scope_bucket_fixture_exceeds_the_bounded_path_limit() {
        let mut out_of_scope = assignment();
        out_of_scope.assigned_paths = (0..=MAX_DETERMINISTIC_SCOPE_PATHS)
            .map(|index| PathBuf::from(format!("src/file-{index}.rs")))
            .collect();
        assert_deterministic_bucket(
            &out_of_scope,
            &present_map(),
            PreclaimRejectionBucket::OutOfScope,
        );
    }

    #[test]
    fn missing_verified_evidence_fails_closed() {
        let candidate = assignment();
        let requested = [candidate.clone()];
        let decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            None,
            None,
            None,
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert!(decision.reason.contains("missing map, risk, runtime"));
        assert!(decision.operator_override.is_none());
    }

    #[test]
    fn ambiguity_defaults_to_reversible_parking() {
        let mut ambiguous = assignment();
        ambiguous.assigned_paths = vec![PathBuf::from("README.md")];
        let requested = [ambiguous.clone()];
        let default = evaluate_preclaim_viability(
            &ambiguous,
            &requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(default.ambiguity_bias, PreclaimAmbiguityBias::Park);
        assert_eq!(default.triage_outcome, PreclaimTriageOutcome::Ambiguous);
        assert_eq!(default.disposition, PreclaimDisposition::Park);
        assert!(default.parking_reversible);
    }

    #[test]
    fn trusted_reject_bias_changes_classification_but_never_claims() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("README.md")];
        set_directive(&mut candidate, r#"{"ambiguity_bias":"reject"}"#);
        let requested = [candidate.clone()];
        let first = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        let second = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(first, second);
        assert_eq!(first.ambiguity_bias, PreclaimAmbiguityBias::Reject);
        assert_eq!(first.triage_outcome, PreclaimTriageOutcome::Rejected);
        assert_eq!(first.disposition, PreclaimDisposition::Park);
        assert_eq!(
            first.authority,
            PreclaimDecisionAuthority::DeterministicPolicy
        );
        assert!(first.operator_override.is_none());
        assert!(first.parking_reversible);
    }

    #[test]
    fn trusted_requested_plan_claim_override_admits_ambiguity_and_records_proof() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("README.md")];
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"claim","rationale":"Operator reviewed the bounded ambiguity"}}"#,
        );
        let requested = [candidate.clone()];
        let decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
        assert_eq!(
            decision.triage_outcome,
            PreclaimTriageOutcome::OperatorOverride
        );
        assert_eq!(decision.authority, PreclaimDecisionAuthority::Operator);
        assert_eq!(
            decision.rejection_bucket,
            Some(PreclaimRejectionBucket::Unclear)
        );
        assert_eq!(
            decision.dimensions.clear_verification_path,
            ViabilityFinding::Unknown
        );
        assert!(decision.map_present && decision.risk_present && decision.runtime_present);
        assert_eq!(decision.evidence_source, PreclaimEvidenceSource::Acquired);
        let recorded = decision
            .operator_override
            .as_ref()
            .expect("trusted override must be recorded");
        assert_eq!(recorded.disposition, PreclaimOverrideDisposition::Claim);
        assert!(!recorded.rationale.is_empty());
        assert!(!decision.reason.contains("README.md"));
        assert!(!decision.reason.contains(&recorded.rationale));
        assert_eq!(
            decision,
            evaluate_preclaim_viability(
                &candidate,
                &requested,
                Some(&present_map()),
                Some(&risk_for_path("README.md")),
                Some(SupervisorRuntime::Fake),
                SupervisorExecutionRuntime::Verified,
            )
        );
    }

    #[test]
    fn trusted_requested_plan_park_override_is_reversible() {
        let mut candidate = assignment();
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"park","rationale":"Operator requests a reversible pause"}}"#,
        );
        let requested = [candidate.clone()];
        let decision = evaluate_with_requested(&candidate, &requested);
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert_eq!(
            decision.triage_outcome,
            PreclaimTriageOutcome::OperatorOverride
        );
        assert_eq!(decision.authority, PreclaimDecisionAuthority::Operator);
        assert!(decision.parking_reversible);
        assert_eq!(
            decision
                .operator_override
                .as_ref()
                .map(|value| value.disposition),
            Some(PreclaimOverrideDisposition::Park)
        );
    }

    #[test]
    fn current_assignment_only_directives_are_untrusted_and_park() {
        let requested = assignment();
        let mut candidate = assignment();
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"claim","rationale":"Current text is not authority"}}"#,
        );
        for current in [candidate, {
            let mut task_candidate = assignment();
            task_candidate.task = Some(format!(
                "current-only {PRECLAIM_DIRECTIVE_PREFIX}{{\"ambiguity_bias\":\"reject\"}}"
            ));
            task_candidate
        }] {
            let decision = evaluate_with_requested(&current, std::slice::from_ref(&requested));
            assert_eq!(decision.disposition, PreclaimDisposition::Park);
            assert_eq!(
                decision.authority,
                PreclaimDecisionAuthority::UntrustedAssignmentInput
            );
            assert!(decision.operator_override.is_none());
        }
    }

    #[test]
    fn requested_task_cannot_carry_the_reserved_directive() {
        let mut requested = assignment();
        requested.task = Some(format!(
            "wrong trusted location {PRECLAIM_DIRECTIVE_PREFIX}{{\"ambiguity_bias\":\"reject\"}}"
        ));
        let decision = evaluate_with_requested(&requested, &[requested.clone()]);
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert_eq!(
            decision.authority,
            PreclaimDecisionAuthority::UntrustedAssignmentInput
        );
        assert!(decision.reason.contains("outside requested-plan notes"));
    }

    #[test]
    fn requested_plan_binding_covers_every_deterministic_assessment_input() {
        let candidate = assignment();
        assert_policy_binding_failure(&candidate, &[], "no unique requested-plan identity");

        let duplicate = candidate.clone();
        assert_policy_binding_failure(
            &candidate,
            &[duplicate.clone(), duplicate],
            "duplicate requested-plan identity",
        );

        let mut wrong_id = candidate.clone();
        wrong_id.id = "child-other".to_string();
        assert_policy_binding_failure(&candidate, &[wrong_id], "no unique requested-plan identity");

        let mut wrong_scope = candidate.clone();
        wrong_scope.assigned_paths = vec![PathBuf::from("tests/related.rs")];
        assert_policy_binding_failure(&candidate, &[wrong_scope], "assigned_paths binding");

        let mut wrong_phase = candidate.clone();
        wrong_phase.phase = AssignmentPhase::Planning;
        assert_policy_binding_failure(&candidate, &[wrong_phase], "phase binding");

        let mut wrong_role = candidate.clone();
        wrong_role.role = AgentRole::Worker;
        assert_policy_binding_failure(&candidate, &[wrong_role], "role binding");

        let mut requested_environment = candidate.clone();
        requested_environment.environment_requirements = vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
        assert_policy_binding_failure(
            &candidate,
            &[requested_environment],
            "environment_requirements binding",
        );

        let mut requested_worker_environment = candidate.clone();
        requested_worker_environment
            .worker_assignments
            .push(WorkerAssignment {
                id: "worker-a".to_string(),
                role: AgentRole::Worker,
                assigned_paths: candidate.assigned_paths.clone(),
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                environment_requirements: vec![EnvironmentRequirement::network(
                    EnvironmentNetworkAccess::Enabled,
                )],
                report_path: None,
            });
        assert_policy_binding_failure(
            &candidate,
            &[requested_worker_environment],
            "worker_environment_requirements binding",
        );
    }

    #[test]
    fn malformed_unknown_or_empty_requested_directives_fail_closed() {
        for notes in [
            r#"maco-preclaim-v2:{"ambiguity_bias":"reject"}"#,
            r#"maco-preclaim-v1:{"#,
            r#"maco-preclaim-v1:{}"#,
            r#"maco-preclaim-v1:{"unknown":true}"#,
            r#"maco-preclaim-v1:{"operator_override":{"disposition":"claim","rationale":"  "}}"#,
            r#"maco-preclaim-v1:{"operator_override":{"disposition":"launch","rationale":"invalid disposition"}}"#,
        ] {
            let mut candidate = assignment();
            candidate.notes = Some(notes.to_string());
            let requested = [candidate.clone()];
            let decision = evaluate_with_requested(&candidate, &requested);
            assert_eq!(decision.disposition, PreclaimDisposition::Park, "{notes}");
            assert_eq!(
                decision.authority,
                PreclaimDecisionAuthority::DeterministicPolicy,
                "{notes}"
            );
            assert!(decision.operator_override.is_none(), "{notes}");
            assert!(
                decision.reason.contains("invalid requested-plan"),
                "{notes}"
            );
        }
    }

    #[test]
    fn operator_claim_override_cannot_synthesize_required_evidence_or_override_no() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("README.md")];
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"claim","rationale":"Evidence must remain independently acquired"}}"#,
        );
        let requested = [candidate.clone()];
        let missing = evaluate_preclaim_viability(
            &candidate,
            &requested,
            None,
            None,
            None,
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(missing.disposition, PreclaimDisposition::Park);
        assert_eq!(missing.authority, PreclaimDecisionAuthority::Operator);
        assert_eq!(
            missing.triage_outcome,
            PreclaimTriageOutcome::OperatorOverride
        );
        assert!(missing.reason.contains("missing map, risk, runtime"));
        assert!(!missing.map_present && !missing.risk_present && !missing.runtime_present);
        assert_eq!(
            missing
                .operator_override
                .as_ref()
                .map(|value| value.disposition),
            Some(PreclaimOverrideDisposition::Claim)
        );

        let mut deterministic_no = candidate;
        deterministic_no.environment_requirements = vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
        let requested_no = [deterministic_no.clone()];
        let rejected = evaluate_preclaim_viability(
            &deterministic_no,
            &requested_no,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(rejected.disposition, PreclaimDisposition::Park);
        assert_eq!(
            rejected.rejection_bucket,
            Some(PreclaimRejectionBucket::NeedsDecision)
        );
        assert_eq!(
            rejected.dimensions.autonomously_completable,
            ViabilityFinding::No
        );
    }

    #[test]
    fn ordinary_task_and_notes_do_not_affect_a_deterministic_decision() {
        let mut without_text = assignment();
        without_text.task = None;
        without_text.notes = None;
        let mut ordinary_text = without_text.clone();
        ordinary_text.task = Some("run cargo test for this exact target".to_string());
        ordinary_text.notes = Some("ordinary planning context without reserved policy".to_string());
        assert_eq!(evaluate(&without_text), evaluate(&ordinary_text));
    }

    #[test]
    fn exact_assigned_test_target_is_assignment_specific_verification() {
        let decision = evaluate(&assignment());
        assert_eq!(
            decision.dimensions.clear_verification_path,
            ViabilityFinding::Yes
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
    }

    #[test]
    fn test_target_classifier_accepts_runnable_sources_and_rejects_fixture_files() {
        for path in ["tests/preclaim.rs", "tests/test_generator.py"] {
            assert!(
                is_recognized_test_target(Path::new(path)),
                "runnable test source should be recognized: {path}"
            );
        }

        for path in ["tests/fixtures/input.json", "tests/README.md"] {
            assert!(
                !is_recognized_test_target(Path::new(path)),
                "non-runnable fixture must not be a verification target: {path}"
            );
        }
    }

    #[test]
    fn exact_risk_binding_to_mapped_related_test_is_assignment_specific_verification() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("src/lib.rs")];
        let risk = related_test_risk("src/lib.rs", "tests/related.rs");
        let requested = [candidate.clone()];
        let decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(
            decision.dimensions.clear_verification_path,
            ViabilityFinding::Yes
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
    }

    #[test]
    fn verified_requested_plan_bound_licensed_breakage_is_a_verification_contract() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("README.md")];
        candidate.licensed_breakage = Some(LicensedBreakageDeclaration {
            migration_rationale: "Update the declared dependent after the breaking change"
                .to_string(),
            dependents: vec![LicensedBreakageDependentScope {
                dependent_id: "dependent-a".to_string(),
                paths: vec![PathBuf::from("src/dependent.rs")],
                interfaces: vec!["crate::api::renamed".to_string()],
            }],
        });
        let requested = [candidate.clone()];
        let decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Claim);
        assert_eq!(
            decision.dimensions.clear_verification_path,
            ViabilityFinding::Yes
        );
        assert_eq!(
            decision.dimensions.autonomously_completable,
            ViabilityFinding::Yes
        );
        assert!(decision.map_present && decision.risk_present && decision.runtime_present);

        let mut unbound_requested = candidate.clone();
        unbound_requested.licensed_breakage = None;
        let unbound = evaluate_preclaim_viability(
            &candidate,
            &[unbound_requested],
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(unbound.disposition, PreclaimDisposition::Park);
        assert_eq!(
            unbound.authority,
            PreclaimDecisionAuthority::UntrustedAssignmentInput
        );

        let mut environment_bound = candidate;
        environment_bound.environment_requirements = vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
        let environment_requested = [environment_bound.clone()];
        let parked = evaluate_preclaim_viability(
            &environment_bound,
            &environment_requested,
            Some(&present_map()),
            Some(&risk_for_path("README.md")),
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(parked.disposition, PreclaimDisposition::Park);
        assert_eq!(
            parked.dimensions.autonomously_completable,
            ViabilityFinding::No
        );
        assert_eq!(
            parked.rejection_bucket,
            Some(PreclaimRejectionBucket::NeedsDecision)
        );
    }

    #[test]
    fn manifest_and_generic_verification_wording_are_insufficient() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("README.md")];
        candidate.task = Some("build, test, lint, verify, and validate the repository".to_string());
        candidate.notes = Some("cargo test is a generic suggestion".to_string());
        let risk = risk_for_path("README.md");
        let requested = [candidate.clone()];
        let decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&risk),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(
            decision.dimensions.clear_verification_path,
            ViabilityFinding::Unknown
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
    }

    #[test]
    fn unrelated_test_file_and_mismatched_risk_binding_are_insufficient() {
        let mut candidate = assignment();
        candidate.assigned_paths = vec![PathBuf::from("src/lib.rs")];
        let requested = [candidate.clone()];

        let unrelated = risk_for_path("src/lib.rs");
        let unrelated_decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&unrelated),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(
            unrelated_decision.dimensions.clear_verification_path,
            ViabilityFinding::Unknown
        );

        let mismatched = related_test_risk("src/other.rs", "tests/related.rs");
        let mismatched_decision = evaluate_preclaim_viability(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&mismatched),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(
            mismatched_decision.dimensions.clear_verification_path,
            ViabilityFinding::Unknown
        );
        assert_eq!(mismatched_decision.disposition, PreclaimDisposition::Park);
    }

    #[test]
    fn weak_model_cannot_decide_acceptance_or_rejection() {
        for bucket in [None, Some(PreclaimRejectionBucket::Invalid)] {
            let provider = FakeProvider(PreclaimAssessment {
                dimensions: PreclaimViabilityDimensions {
                    limited_scope: ViabilityFinding::Yes,
                    clear_verification_path: ViabilityFinding::Yes,
                    autonomously_completable: ViabilityFinding::Yes,
                },
                rejection_bucket: bucket,
                confidence: PreclaimConfidence::High,
                authority: PreclaimDecisionAuthority::Model {
                    capability: ModelCapabilityClass::WeakMechanical,
                },
                reason: "weak fake proposal".to_string(),
            });
            let candidate = assignment();
            let requested = [candidate.clone()];
            let decision = evaluate_with_provider(
                &candidate,
                &requested,
                Some(&present_map()),
                Some(&present_risk()),
                Some(SupervisorRuntime::Fake),
                SupervisorExecutionRuntime::Verified,
                &provider,
            );
            assert_eq!(decision.disposition, PreclaimDisposition::Park);
            assert!(decision.reason.contains("acceptance-gate capability floor"));
        }
    }

    #[test]
    fn operator_claim_requires_structurally_coherent_ambiguity() {
        let mut candidate = assignment();
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"claim","rationale":"Operator reviewed only a genuine ambiguity"}}"#,
        );
        let requested = [candidate.clone()];
        for (dimensions, bucket) in [
            (
                PreclaimViabilityDimensions {
                    limited_scope: ViabilityFinding::No,
                    clear_verification_path: ViabilityFinding::Unknown,
                    autonomously_completable: ViabilityFinding::Yes,
                },
                PreclaimRejectionBucket::Unclear,
            ),
            (
                PreclaimViabilityDimensions {
                    limited_scope: ViabilityFinding::Yes,
                    clear_verification_path: ViabilityFinding::Unknown,
                    autonomously_completable: ViabilityFinding::Yes,
                },
                PreclaimRejectionBucket::NeedsDecision,
            ),
        ] {
            let provider = FakeProvider(PreclaimAssessment {
                dimensions,
                rejection_bucket: Some(bucket),
                confidence: PreclaimConfidence::Low,
                authority: PreclaimDecisionAuthority::DeterministicPolicy,
                reason: "incoherent low-confidence fake assessment".to_string(),
            });
            let decision = evaluate_with_provider(
                &candidate,
                &requested,
                Some(&present_map()),
                Some(&present_risk()),
                Some(SupervisorRuntime::Fake),
                SupervisorExecutionRuntime::Verified,
                &provider,
            );
            assert_eq!(decision.disposition, PreclaimDisposition::Park);
            assert_eq!(
                decision.triage_outcome,
                PreclaimTriageOutcome::OperatorOverride
            );
            assert_eq!(decision.authority, PreclaimDecisionAuthority::Operator);
            assert_eq!(decision.dimensions, dimensions);
            assert_eq!(decision.rejection_bucket, Some(bucket));
            assert!(decision.reason.contains("genuinely ambiguous"));
        }
    }

    #[test]
    fn trusted_operator_park_precedes_weak_assessment_authority_floor() {
        let mut candidate = assignment();
        set_directive(
            &mut candidate,
            r#"{"operator_override":{"disposition":"park","rationale":"Operator requires a reversible pause"}}"#,
        );
        let requested = [candidate.clone()];
        let provider = FakeProvider(PreclaimAssessment {
            dimensions: PreclaimViabilityDimensions {
                limited_scope: ViabilityFinding::Yes,
                clear_verification_path: ViabilityFinding::Yes,
                autonomously_completable: ViabilityFinding::Yes,
            },
            rejection_bucket: None,
            confidence: PreclaimConfidence::High,
            authority: PreclaimDecisionAuthority::Model {
                capability: ModelCapabilityClass::WeakMechanical,
            },
            reason: "weak fake proposal".to_string(),
        });
        let decision = evaluate_with_provider(
            &candidate,
            &requested,
            Some(&present_map()),
            Some(&present_risk()),
            Some(SupervisorRuntime::Fake),
            SupervisorExecutionRuntime::Verified,
            &provider,
        );
        assert_eq!(decision.disposition, PreclaimDisposition::Park);
        assert_eq!(
            decision.triage_outcome,
            PreclaimTriageOutcome::OperatorOverride
        );
        assert_eq!(decision.authority, PreclaimDecisionAuthority::Operator);
        assert!(decision.parking_reversible);
        assert_eq!(
            decision
                .operator_override
                .as_ref()
                .map(|value| value.disposition),
            Some(PreclaimOverrideDisposition::Park)
        );
        assert!(!decision.reason.contains("capability floor"));
    }

    #[test]
    fn simulation_uses_typed_synthetic_viability_while_preserving_policy_gates() {
        let mut simulated = assignment();
        simulated.assigned_paths = vec![PathBuf::from("src/lib.rs")];
        simulated.environment_requirements = vec![EnvironmentRequirement::network(
            EnvironmentNetworkAccess::Enabled,
        )];
        let requested = [simulated.clone()];
        let viable = evaluate_preclaim_viability(
            &simulated,
            &requested,
            None,
            None,
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::NonpublishableSimulation,
        );
        assert_eq!(viable.disposition, PreclaimDisposition::Claim);
        assert_eq!(viable.triage_outcome, PreclaimTriageOutcome::Viable);
        assert!(viable.dimensions.all_positive());
        assert_eq!(viable.rejection_bucket, None);
        assert_eq!(
            viable.evidence_source,
            PreclaimEvidenceSource::SyntheticSimulation
        );
        assert!(!viable.map_present && !viable.risk_present && viable.runtime_present);

        let current = simulated.clone();
        let mut requested_park = current.clone();
        set_directive(
            &mut requested_park,
            r#"{"operator_override":{"disposition":"park","rationale":"Operator preserves the simulation policy boundary"}}"#,
        );
        let parked_by_policy = evaluate_preclaim_viability(
            &current,
            &[requested_park],
            None,
            None,
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::NonpublishableSimulation,
        );
        assert_eq!(parked_by_policy.disposition, PreclaimDisposition::Park);
        assert_eq!(
            parked_by_policy.triage_outcome,
            PreclaimTriageOutcome::OperatorOverride
        );
        assert_eq!(
            parked_by_policy.authority,
            PreclaimDecisionAuthority::Operator
        );
        assert!(parked_by_policy.dimensions.all_positive());

        let trusted_requested = simulated.clone();
        let mut current_only_directive = simulated.clone();
        set_directive(
            &mut current_only_directive,
            r#"{"operator_override":{"disposition":"claim","rationale":"Current input is not trusted policy"}}"#,
        );
        let untrusted = evaluate_preclaim_viability(
            &current_only_directive,
            &[trusted_requested],
            None,
            None,
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::NonpublishableSimulation,
        );
        assert_eq!(untrusted.disposition, PreclaimDisposition::Park);
        assert_eq!(
            untrusted.authority,
            PreclaimDecisionAuthority::UntrustedAssignmentInput
        );
        assert!(untrusted.operator_override.is_none());

        assert_eq!(
            viable,
            evaluate_preclaim_viability(
                &simulated,
                &requested,
                None,
                None,
                Some(SupervisorRuntime::Codex),
                SupervisorExecutionRuntime::NonpublishableSimulation,
            )
        );
    }

    #[test]
    fn decision_round_trips_for_the_recorded_ledger() {
        let decision = evaluate(&assignment());
        let encoded = serde_json::to_string(&decision).expect("serialize decision");
        let decoded: PreclaimDecision =
            serde_json::from_str(&encoded).expect("deserialize decision");
        assert_eq!(decoded, decision);
    }
}
