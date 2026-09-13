//! Parent-owned attempt evidence and a frozen, authenticated selector history.
//! The artifact store supplies the only authenticity boundary. A digest here is
//! replay provenance, not an independent signature or a source of authority.

use super::*;
use crate::selection::{CandidateKey, FailureClass, OutcomeRecord, OutcomeResult, TaskProfile};
use std::collections::BTreeMap;
use std::sync::Mutex;

const ATTEMPT_EVIDENCE_VERSION: u32 = 1;
const ATTEMPT_EVIDENCE_DIR: &str = "selection-attempts";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptSelectionBinding {
    pub role: AgentRole,
    pub event_assignment_id: Option<String>,
    pub event_attempt: usize,
    pub normalized_input_sha256: String,
    pub task: TaskProfile,
    pub requested_candidate: CandidateKey,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptAttributableCosts {
    pub execution_cost_microunits: Option<u64>,
    pub review_cost_microunits: Option<u64>,
    pub rework_cost_microunits: Option<u64>,
    pub rereview_cost_microunits: Option<u64>,
    pub environment_cost_microunits: Option<u64>,
}

impl AttemptAttributableCosts {
    fn complete(&self) -> Option<[u64; 5]> {
        Some([
            self.execution_cost_microunits?,
            self.review_cost_microunits?,
            self.rework_cost_microunits?,
            self.rereview_cost_microunits?,
            self.environment_cost_microunits?,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptOutcomeEvidence {
    pub version: u32,
    pub run_id: String,
    pub assignment_id: String,
    pub attempt: usize,
    pub verified_execution: bool,
    pub selection: Option<AttemptSelectionBinding>,
    pub requested_runtime: String,
    pub requested_model: Option<String>,
    pub requested_effort: Option<String>,
    /// A configured launch is a request. Only provider/session evidence may set
    /// this field; current supervisor telemetry cannot resolve it.
    pub observed_candidate: Option<CandidateKey>,
    /// A retry is a parent decision. Terminal acceptance is established from
    /// the authenticated final assignment report when history is loaded.
    pub parent_result: Option<OutcomeResult>,
    pub parent_cause: Option<String>,
    pub failure_class: Option<FailureClass>,
    pub costs: AttemptAttributableCosts,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_child_attempt_outcome(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    run_id: &RunId,
    assignment_id: &str,
    attempt: usize,
    role: AgentRole,
    events: &[SupervisorSelectionEvent],
    initial_events: &[SupervisorSelectionEvent],
    requested_runtime: &str,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
    verified_execution: bool,
    retried: bool,
) -> Result<AttemptOutcomeEvidence> {
    let selection =
        selection_binding_for_attempt(role, assignment_id, attempt, events, initial_events);
    let evidence = AttemptOutcomeEvidence {
        version: ATTEMPT_EVIDENCE_VERSION,
        run_id: run_id.as_str().to_string(),
        assignment_id: assignment_id.to_string(),
        attempt,
        verified_execution,
        selection,
        requested_runtime: requested_runtime.to_string(),
        requested_model: requested_model.map(str::to_string),
        requested_effort: requested_effort.map(str::to_string),
        observed_candidate: None,
        parent_result: retried.then_some(OutcomeResult::Rejected),
        parent_cause: retried.then(|| "parent_authorized_retry".to_string()),
        failure_class: None,
        costs: AttemptAttributableCosts::default(),
    };
    write_attempt_evidence(artifacts, &evidence)?;
    Ok(evidence)
}

fn selection_binding_for_attempt(
    role: AgentRole,
    assignment_id: &str,
    attempt: usize,
    events: &[SupervisorSelectionEvent],
    initial_events: &[SupervisorSelectionEvent],
) -> Option<AttemptSelectionBinding> {
    let event = events
        .iter()
        .rev()
        .find(|event| {
            event.role == role
                && event.assignment_id.as_deref() == Some(assignment_id)
                && (event.attempt == attempt || attempt == 1 && event.attempt == 0)
        })
        .or_else(|| {
            initial_events.iter().find(|event| {
                event.role == role && event.assignment_id.is_none() && event.attempt == 0
            })
        });
    event.and_then(|event| {
        let choice = event.provenance.choice.as_ref()?;
        Some(AttemptSelectionBinding {
            role,
            event_assignment_id: event.assignment_id.clone(),
            event_attempt: event.attempt,
            normalized_input_sha256: event
                .provenance
                .input_digests
                .normalized_input
                .value
                .clone(),
            task: event.provenance.normalized_task.clone(),
            requested_candidate: choice.candidate.clone(),
        })
    })
}

fn write_attempt_evidence(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    evidence: &AttemptOutcomeEvidence,
) -> Result<()> {
    let relative = PathBuf::from(ATTEMPT_EVIDENCE_DIR).join(format!(
        "{}.attempt-{}.json",
        evidence.assignment_id, evidence.attempt
    ));
    with_supervisor_artifacts(artifacts, |writer, _| {
        writer.write_json(
            &relative,
            evidence,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    })
}

pub(super) fn record_parent_auditor_retry(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    original: &AttemptOutcomeEvidence,
) -> Result<()> {
    let mut rejected = original.clone();
    rejected.parent_result = Some(OutcomeResult::Rejected);
    rejected.parent_cause = Some("parent_auditor_authorized_retry".to_string());
    write_attempt_evidence(artifacts, &rejected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrozenOutcomeHistory {
    pub provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance,
    rows: Vec<OutcomeRecord>,
}

impl FrozenOutcomeHistory {
    pub fn outcomes_for(&self, task: &TaskProfile) -> Vec<OutcomeRecord> {
        self.rows
            .iter()
            .filter(|row| &row.task == task)
            .cloned()
            .collect()
    }
}

pub(super) fn load_frozen_outcome_history(
    repo: &Path,
    current_run: &RunId,
) -> Result<FrozenOutcomeHistory> {
    let mut sources = Vec::new();
    let mut exclusions = Vec::new();
    let mut candidates: BTreeMap<(String, String, usize), Vec<Option<OutcomeRecord>>> =
        BTreeMap::new();
    for summary in crate::artifacts::list_runs(repo, RunArtifactFamily::Supervise)?.runs {
        if summary.run_id == current_run.as_str() {
            continue;
        }
        let Ok(run_id) = RunId::new(&summary.run_id) else {
            exclusions.push(format!("{}:invalid_run_id", summary.run_id));
            continue;
        };
        let Ok(reader) = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, &run_id)
        else {
            exclusions.push(format!("{}:unfinalized_or_unauthenticated", summary.run_id));
            continue;
        };
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        let Ok(final_bytes) = reader.read(&final_relative) else {
            exclusions.push(format!("{}:missing_final_report", summary.run_id));
            continue;
        };
        let Ok(report) = serde_json::from_slice::<SupervisorFinalReport>(&final_bytes) else {
            exclusions.push(format!("{}:invalid_final_report", summary.run_id));
            continue;
        };
        if report.run_id != run_id
            || report.repo != Path::new(".")
            || report.run_dir
                != RunArtifactFamily::Supervise
                    .run_root()
                    .join(run_id.as_str())
            || report.run_lifecycle != SupervisorRunLifecycle::Finalized
            || report.runtime == SupervisorRuntime::Fake
            || report.evidence_only_reaudit.is_some()
        {
            exclusions.push(format!("{}:invalid_or_simulation_source", summary.run_id));
            continue;
        }
        let final_sha = crate::artifacts::state_auth::sha256_hex(&final_bytes);
        let mut last_attempt_by_assignment = BTreeMap::<String, usize>::new();
        let mut manifest_attempt_counts = BTreeMap::<(String, String, usize), usize>::new();
        for file in &reader.finalization().files {
            if !file.path.starts_with(ATTEMPT_EVIDENCE_DIR)
                || file
                    .path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    != Some("json")
            {
                continue;
            }
            if let Ok(bytes) = reader.read(&file.path) {
                if let Ok(attempt) = serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes) {
                    if attempt.run_id == run_id.as_str() && attempt.attempt > 0 {
                        *manifest_attempt_counts
                            .entry((attempt.run_id, attempt.assignment_id, attempt.attempt))
                            .or_default() += 1;
                    }
                }
            }
            let Some(name) = file.path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some((assignment, ordinal)) = name
                .strip_suffix(".json")
                .and_then(|name| name.rsplit_once(".attempt-"))
            else {
                continue;
            };
            if let Ok(ordinal) = ordinal.parse::<usize>() {
                last_attempt_by_assignment
                    .entry(assignment.to_string())
                    .and_modify(|last| *last = (*last).max(ordinal))
                    .or_insert(ordinal);
            }
        }
        for file in &reader.finalization().files {
            if !file.path.starts_with(ATTEMPT_EVIDENCE_DIR)
                || file.path.extension().and_then(|s| s.to_str()) != Some("json")
            {
                continue;
            }
            let source = format!(
                "{}:{}:{}:{}",
                run_id.as_str(),
                file.path.display(),
                final_sha,
                file.sha256
            );
            let Ok(bytes) = reader.read(&file.path) else {
                exclusions.push(format!("{}:unreadable_attempt", source));
                continue;
            };
            let Ok(mut row) = serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes) else {
                exclusions.push(format!("{}:invalid_attempt", source));
                continue;
            };
            if row.version != ATTEMPT_EVIDENCE_VERSION
                || row.run_id != run_id.as_str()
                || row.attempt == 0
            {
                exclusions.push(format!("{}:invalid_attempt_binding", source));
                continue;
            }
            if manifest_attempt_counts
                .get(&(row.run_id.clone(), row.assignment_id.clone(), row.attempt))
                .copied()
                .unwrap_or(0)
                != 1
            {
                exclusions.push(format!("{}:duplicate_attempt", source));
                continue;
            }
            if !row.verified_execution {
                exclusions.push(format!("{}:synthetic_execution", source));
                continue;
            }
            let expected_path = PathBuf::from(ATTEMPT_EVIDENCE_DIR).join(format!(
                "{}.attempt-{}.json",
                row.assignment_id, row.attempt
            ));
            if file.path != expected_path {
                exclusions.push(format!("{}:path_binding_mismatch", source));
                continue;
            }
            let Some(binding) = row.selection.as_ref() else {
                exclusions.push(format!("{}:missing_selection", source));
                continue;
            };
            let matching_event_count = report
                .role_economics_profile
                .as_ref()
                .and_then(|profile| profile.execution.as_ref())
                .into_iter()
                .flat_map(|execution| &execution.selection_decisions)
                .filter(|event| {
                    event.role == binding.role
                        && event.assignment_id == binding.event_assignment_id
                        && event.attempt == binding.event_attempt
                        && event.provenance.input_digests.normalized_input.value
                            == binding.normalized_input_sha256
                        && event.provenance.normalized_task == binding.task
                        && event
                            .provenance
                            .choice
                            .as_ref()
                            .map(|choice| &choice.candidate)
                            == Some(&binding.requested_candidate)
                })
                .count();
            if matching_event_count != 1
                || !(binding.event_attempt == 0 && binding.event_assignment_id.is_none()
                    || row.attempt == 1
                        && binding.event_attempt == 0
                        && binding.event_assignment_id.as_deref()
                            == Some(row.assignment_id.as_str())
                    || binding.event_attempt == row.attempt
                        && binding.event_assignment_id.as_deref()
                            == Some(row.assignment_id.as_str()))
            {
                exclusions.push(format!("{}:selection_binding_mismatch", source));
                continue;
            }
            let final_assignments = report
                .orchestrator_reports
                .iter()
                .filter(|item| item.id == row.assignment_id)
                .collect::<Vec<_>>();
            if final_assignments.len() > 1
                || final_assignments
                    .first()
                    .is_some_and(|item| item.role != binding.role)
                || (row.parent_result.is_some()
                    && (row.parent_result != Some(OutcomeResult::Rejected)
                        || !matches!(
                            row.parent_cause.as_deref(),
                            Some("parent_authorized_retry" | "parent_auditor_authorized_retry")
                        )))
            {
                exclusions.push(format!("{}:ambiguous_or_unreviewed_result", source));
                continue;
            }
            if row.parent_result.is_none() {
                if last_attempt_by_assignment.get(&row.assignment_id) != Some(&row.attempt) {
                    exclusions.push(format!("{}:superseded_attempt", source));
                    continue;
                }
                row.parent_result = final_assignments.first().and_then(|item| {
                    if item.accepted && !item.rejected {
                        Some(OutcomeResult::Accepted)
                    } else if item.rejected && !item.accepted {
                        Some(OutcomeResult::Rejected)
                    } else {
                        None
                    }
                });
                row.parent_cause = row
                    .parent_result
                    .map(|_| "final_parent_assignment_review".to_string());
            }
            sources.push(source.clone());
            let key = (row.run_id.clone(), row.assignment_id.clone(), row.attempt);
            let projected = project_numeric_row(&row);
            if projected.is_none() {
                exclusions.push(format!("{}:unknown_or_ineligible_numeric_evidence", source));
            }
            candidates.entry(key).or_default().push(projected);
        }
    }
    let mut rows = Vec::new();
    for (key, mut group) in candidates {
        if group.len() == 1 {
            if let Some(row) = group.remove(0) {
                rows.push(row);
            }
        } else {
            exclusions.push(format!("{}:{}:{}:duplicate_attempt", key.0, key.1, key.2));
        }
    }
    rows.sort_by(|a, b| a.attempt_id.cmp(&b.attempt_id));
    sources.sort();
    exclusions.sort();
    let snapshot_bytes =
        serde_json::to_vec(&(sources.as_slice(), exclusions.as_slice(), rows.as_slice()))?;
    Ok(FrozenOutcomeHistory {
        provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance {
            snapshot_sha256: crate::artifacts::state_auth::sha256_hex(&snapshot_bytes),
            source_digests: sources,
            exclusions,
            projected_attempt_count: rows.len(),
        },
        rows,
    })
}

fn project_numeric_row(row: &AttemptOutcomeEvidence) -> Option<OutcomeRecord> {
    let binding = row.selection.as_ref()?;
    let observed = row.observed_candidate.as_ref()?;
    if observed != &binding.requested_candidate {
        return None;
    }
    let requested_effort = match binding.requested_candidate.effort {
        crate::selection::ReasoningEffort::Low => "low",
        crate::selection::ReasoningEffort::Medium => "medium",
        crate::selection::ReasoningEffort::High => "high",
        crate::selection::ReasoningEffort::Xhigh => "xhigh",
        crate::selection::ReasoningEffort::Max => "max",
        crate::selection::ReasoningEffort::Ultra => "ultra",
    };
    if row.requested_runtime != binding.requested_candidate.runtime
        || row.requested_model.as_deref() != Some(binding.requested_candidate.model.as_str())
        || row.requested_effort.as_deref() != Some(requested_effort)
    {
        return None;
    }
    let result = row.parent_result?;
    let [execution, review, rework, rereview, environment] = row.costs.complete()?;
    let attempt_id = format!("{}:{}:{}", row.run_id, row.assignment_id, row.attempt);
    Some(OutcomeRecord {
        attempt_id,
        task: binding.task.clone(),
        candidate: observed.clone(),
        result,
        failure_class: row.failure_class,
        execution_cost_microunits: execution,
        review_cost_microunits: review,
        rework_cost_microunits: rework,
        rereview_cost_microunits: rereview,
        environment_cost_microunits: environment,
        environment_failures: Vec::new(),
        fixed_cause_relaunch: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::{
        AuthorityRole, Boundedness, ContextSize, ReasoningEffort, RiskLevel, TaskHorizon,
    };

    fn fixture() -> AttemptOutcomeEvidence {
        let candidate = CandidateKey {
            runtime: "codex".to_string(),
            model: "fixture-model".to_string(),
            effort: ReasoningEffort::High,
        };
        AttemptOutcomeEvidence {
            version: ATTEMPT_EVIDENCE_VERSION,
            run_id: "run-1".to_string(),
            assignment_id: "assignment-1".to_string(),
            attempt: 1,
            verified_execution: true,
            selection: Some(AttemptSelectionBinding {
                role: AgentRole::Worker,
                event_assignment_id: None,
                event_attempt: 0,
                normalized_input_sha256: "fixture-digest".to_string(),
                task: TaskProfile {
                    task_class: "localized_code_change".to_string(),
                    risk: RiskLevel::Medium,
                    boundedness: Boundedness::Bounded,
                    context: ContextSize::Medium,
                    horizon: TaskHorizon::Medium,
                    authority_role: AuthorityRole::TerminalLeaf,
                },
                requested_candidate: candidate.clone(),
            }),
            requested_runtime: "codex".to_string(),
            requested_model: Some("fixture-model".to_string()),
            requested_effort: Some("high".to_string()),
            observed_candidate: Some(candidate),
            parent_result: Some(OutcomeResult::Accepted),
            parent_cause: Some("final_parent_assignment_review".to_string()),
            failure_class: None,
            costs: AttemptAttributableCosts {
                execution_cost_microunits: Some(5),
                review_cost_microunits: Some(2),
                rework_cost_microunits: Some(0),
                rereview_cost_microunits: Some(0),
                environment_cost_microunits: Some(0),
            },
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AuthenticatedFixtureMode {
        Initial,
        DebugOverride,
        AssignmentDegrade,
        AuditorRetry,
    }

    fn write_authenticated_fixture(
        repo: &Path,
        run_name: &str,
        accepted: bool,
        duplicate: bool,
        synthetic: bool,
        foreign_report: bool,
        mode: AuthenticatedFixtureMode,
    ) -> Result<()> {
        let run_id = RunId::new(run_name)?;
        let decision = crate::selection::select(&crate::selection::selection_test_base_input())?;
        let selected = decision
            .choice
            .as_ref()
            .context("fixture selector choice")?;
        let mut evidence = fixture();
        evidence.run_id = run_name.to_string();
        evidence.verified_execution = !synthetic;
        evidence.selection = Some(AttemptSelectionBinding {
            role: AgentRole::Worker,
            event_assignment_id: None,
            event_attempt: 0,
            normalized_input_sha256: decision.input_digests.normalized_input.value.clone(),
            task: decision.normalized_task.clone(),
            requested_candidate: selected.candidate.clone(),
        });
        evidence.requested_runtime = selected.candidate.runtime.clone();
        evidence.requested_model = Some(selected.candidate.model.clone());
        evidence.requested_effort = Some(
            match selected.candidate.effort {
                ReasoningEffort::Low => "low",
                ReasoningEffort::Medium => "medium",
                ReasoningEffort::High => "high",
                ReasoningEffort::Xhigh => "xhigh",
                ReasoningEffort::Max => "max",
                ReasoningEffort::Ultra => "ultra",
            }
            .to_string(),
        );
        evidence.observed_candidate = Some(selected.candidate.clone());
        evidence.parent_result = None;
        evidence.parent_cause = None;
        let mut profile: RoleEconomicsProfile = serde_json::from_str(include_str!(
            "../../tests/fixtures/supervise/supervisor-final-economics-v4.json"
        ))?;
        let initial_event = SupervisorSelectionEvent {
            assignment_id: (mode == AuthenticatedFixtureMode::AssignmentDegrade)
                .then(|| "assignment-1".to_string()),
            attempt: 0,
            role: AgentRole::Worker,
            primary_cause: match mode {
                AuthenticatedFixtureMode::Initial | AuthenticatedFixtureMode::AuditorRetry => {
                    SupervisorSelectionEventCause::Initial
                }
                AuthenticatedFixtureMode::DebugOverride => {
                    SupervisorSelectionEventCause::DebugOverride
                }
                AuthenticatedFixtureMode::AssignmentDegrade => {
                    SupervisorSelectionEventCause::BudgetDegrade
                }
            },
            provenance: decision,
        };
        evidence.selection = selection_binding_for_attempt(
            AgentRole::Worker,
            "assignment-1",
            1,
            if mode == AuthenticatedFixtureMode::AssignmentDegrade {
                std::slice::from_ref(&initial_event)
            } else {
                &[]
            },
            std::slice::from_ref(&initial_event),
        );
        profile
            .execution
            .as_mut()
            .context("fixture execution")?
            .selection_decisions = vec![initial_event];
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            let execution = profile.execution.as_mut().context("fixture execution")?;
            let mut retry_event = execution.selection_decisions[0].clone();
            retry_event.assignment_id = Some("assignment-1".to_string());
            retry_event.attempt = 2;
            retry_event.primary_cause = SupervisorSelectionEventCause::Retry;
            execution.selection_decisions.push(retry_event);
        }
        let mut assignment: OrchestratorReviewReport = serde_json::from_str(
            &super::super::tests::sample_child_report_json("assignment-1"),
        )?;
        assignment.role = AgentRole::Worker;
        assignment.accepted = accepted;
        assignment.rejected = !accepted;
        assignment.status = if accepted {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        };
        let mut report = super::super::tests::artifact_test_final_report(&run_id);
        report.runtime = SupervisorRuntime::Codex;
        report.publishable = accepted;
        report.success = accepted;
        report.accepted = accepted;
        report.rejected = !accepted;
        report.status = assignment.status;
        report.role_economics_profile = Some(profile);
        report.orchestrator_reports = vec![assignment];
        if foreign_report {
            report.repo = PathBuf::from("foreign-repository");
        }
        let mut writer = ArtifactRunWriter::reserve(
            repo,
            RunArtifactFamily::Supervise,
            run_id,
            "maco-supervise",
        )?;
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            evidence.parent_result = Some(OutcomeResult::Rejected);
            evidence.parent_cause = Some("parent_auditor_authorized_retry".to_string());
        }
        writer.write_json(
            Path::new("selection-attempts/assignment-1.attempt-1.json"),
            &evidence,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        if mode == AuthenticatedFixtureMode::AuditorRetry {
            let mut second = evidence.clone();
            second.attempt = 2;
            second.selection = selection_binding_for_attempt(
                AgentRole::Worker,
                "assignment-1",
                2,
                &report
                    .role_economics_profile
                    .as_ref()
                    .and_then(|profile| profile.execution.as_ref())
                    .context("fixture execution")?
                    .selection_decisions,
                &[],
            );
            second.parent_result = None;
            second.parent_cause = None;
            writer.write_json(
                Path::new("selection-attempts/assignment-1.attempt-2.json"),
                &second,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        }
        if duplicate {
            writer.write_json(
                Path::new("selection-attempts/duplicate.json"),
                &evidence,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        }
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        writer.write_json(
            &final_relative,
            &report,
            ArtifactFileDisposition::Publishable,
        )?;
        writer.finalize(&final_relative, false)?;
        Ok(())
    }

    #[test]
    fn authenticated_accepted_and_rejected_attempts_project_and_freeze() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "accepted-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "rejected-history",
            false,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        let current = RunId::new("next-run")?;
        let frozen = load_frozen_outcome_history(&repo, &current)?;
        assert_eq!(frozen.rows.len(), 2);
        assert!(frozen
            .rows
            .iter()
            .any(|row| row.result == OutcomeResult::Accepted));
        assert!(frozen
            .rows
            .iter()
            .any(|row| row.result == OutcomeResult::Rejected));
        assert_eq!(frozen.provenance.projected_attempt_count, 2);
        assert_eq!(frozen.provenance.source_digests.len(), 2);
        write_authenticated_fixture(
            &repo,
            "later-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        assert_eq!(frozen.rows.len(), 2);
        let later = load_frozen_outcome_history(&repo, &current)?;
        assert_eq!(later.rows.len(), 3);
        assert_ne!(
            frozen.provenance.snapshot_sha256,
            later.provenance.snapshot_sha256
        );
        Ok(())
    }

    #[test]
    fn authenticated_exact_bound_outcome_changes_existing_selector_score() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "selector-influence-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        let mut input = crate::selection::selection_test_base_input();
        let baseline = crate::selection::select(&input)?;
        let candidate = baseline
            .choice
            .as_ref()
            .context("baseline choice")?
            .candidate
            .clone();
        input.outcomes = frozen.outcomes_for(&input.task);
        assert_eq!(input.outcomes.len(), 1);
        assert_eq!(input.outcomes[0].candidate, candidate);
        let with_history = crate::selection::select(&input)?;
        let score_for = |decision: &crate::selection::SelectionProvenance| {
            decision
                .candidate_set
                .iter()
                .find(|item| item.candidate == candidate)
                .and_then(|item| item.score.as_ref())
                .map(|score| score.expected_total_cost_per_accepted_task_microunits)
        };
        assert_ne!(score_for(&baseline), score_for(&with_history));
        assert_ne!(
            baseline.input_digests.normalized_input.value,
            with_history.input_digests.normalized_input.value
        );
        Ok(())
    }

    #[test]
    fn authenticated_auditor_retry_keeps_original_rejected_attempt() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "auditor-retry-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::AuditorRetry,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 2);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "auditor-retry-history:assignment-1:1"
        );
        assert_eq!(frozen.rows[0].result, OutcomeResult::Rejected);
        assert_eq!(
            frozen.rows[1].attempt_id,
            "auditor-retry-history:assignment-1:2"
        );
        assert_eq!(frozen.rows[1].result, OutcomeResult::Accepted);
        assert!(!frozen
            .provenance
            .exclusions
            .iter()
            .any(|item| item.contains("superseded_attempt")));
        let reader = ArtifactRunReader::open(
            &repo,
            RunArtifactFamily::Supervise,
            &RunId::new("auditor-retry-history")?,
        )?;
        let first: AttemptOutcomeEvidence = serde_json::from_slice(
            &reader.read(Path::new("selection-attempts/assignment-1.attempt-1.json"))?,
        )?;
        assert_eq!(
            first.parent_cause.as_deref(),
            Some("parent_auditor_authorized_retry")
        );
        assert_eq!(first.selection, fixture_selection_for_row(&reader, &first)?);
        let second: AttemptOutcomeEvidence = serde_json::from_slice(
            &reader.read(Path::new("selection-attempts/assignment-1.attempt-2.json"))?,
        )?;
        assert_ne!(first.selection, second.selection);
        Ok(())
    }

    fn fixture_selection_for_row(
        reader: &ArtifactRunReader,
        row: &AttemptOutcomeEvidence,
    ) -> Result<Option<AttemptSelectionBinding>> {
        let report: SupervisorFinalReport = serde_json::from_slice(
            &reader.read(RunArtifactFamily::Supervise.final_report_relative_path())?,
        )?;
        let events = &report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.execution.as_ref())
            .context("fixture execution")?
            .selection_decisions;
        Ok(selection_binding_for_attempt(
            AgentRole::Worker,
            &row.assignment_id,
            row.attempt,
            events,
            events,
        ))
    }

    #[test]
    fn authenticated_degraded_first_attempt_uses_assignment_event_zero() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "degraded-first-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::AssignmentDegrade,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 1);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "degraded-first-history:assignment-1:1"
        );
        assert!(!frozen
            .provenance
            .exclusions
            .iter()
            .any(|item| item.contains("selection_binding_mismatch")));
        Ok(())
    }

    #[test]
    fn authenticated_debug_override_binds_initial_choice() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "debug-override-history",
            true,
            false,
            false,
            false,
            AuthenticatedFixtureMode::DebugOverride,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert_eq!(frozen.rows.len(), 1);
        assert_eq!(
            frozen.rows[0].attempt_id,
            "debug-override-history:assignment-1:1"
        );
        assert_eq!(frozen.provenance.projected_attempt_count, 1);
        Ok(())
    }

    #[test]
    fn duplicate_synthetic_and_foreign_rows_cannot_enter_numeric_history() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        write_authenticated_fixture(
            &repo,
            "duplicate-history",
            true,
            true,
            false,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "synthetic-history",
            true,
            false,
            true,
            false,
            AuthenticatedFixtureMode::Initial,
        )?;
        write_authenticated_fixture(
            &repo,
            "foreign-history",
            true,
            false,
            false,
            true,
            AuthenticatedFixtureMode::Initial,
        )?;
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(frozen.rows.is_empty());
        for reason in [
            "duplicate_attempt",
            "synthetic_execution",
            "invalid_or_simulation_source",
        ] {
            assert!(frozen
                .provenance
                .exclusions
                .iter()
                .any(|item| item.contains(reason)));
        }
        Ok(())
    }

    #[test]
    fn unfinalized_attempt_source_is_excluded() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("unfinalized-history")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id,
            "maco-supervise",
        )?;
        writer.write_json(
            Path::new("selection-attempts/assignment-1.attempt-1.json"),
            &fixture(),
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        drop(writer);
        let frozen = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(frozen.rows.is_empty());
        assert!(frozen
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("unfinalized_or_unauthenticated")));
        Ok(())
    }

    #[test]
    fn numeric_projection_requires_observed_identity_and_every_attempt_cost() {
        let mut evidence = fixture();
        assert_eq!(
            project_numeric_row(&evidence)
                .unwrap()
                .execution_cost_microunits,
            5
        );
        evidence.costs.review_cost_microunits = None;
        assert!(project_numeric_row(&evidence).is_none());
        evidence.costs.review_cost_microunits = Some(0);
        evidence.observed_candidate = None;
        assert!(project_numeric_row(&evidence).is_none());
        evidence.observed_candidate = Some(CandidateKey {
            model: "different-model".to_string(),
            ..fixture().observed_candidate.unwrap()
        });
        assert!(project_numeric_row(&evidence).is_none());
        evidence.observed_candidate = fixture().observed_candidate;
        evidence.requested_model = Some("different-request".to_string());
        assert!(project_numeric_row(&evidence).is_none());
        evidence.requested_model = Some("fixture-model".to_string());
        evidence.parent_result = Some(OutcomeResult::Rejected);
        let rejected = project_numeric_row(&evidence).unwrap();
        assert_eq!(rejected.failure_class, None);
    }

    #[test]
    fn authenticated_fake_run_is_excluded_and_tamper_is_refused() -> Result<()> {
        let (_temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("fake-history-source")?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "maco-supervise",
        )?;
        let final_relative = RunArtifactFamily::Supervise.final_report_relative_path();
        writer.write_json(
            &final_relative,
            &super::super::tests::artifact_test_final_report(&run_id),
            ArtifactFileDisposition::Publishable,
        )?;
        writer.finalize(&final_relative, false)?;
        ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)?;
        let before = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(before.rows.is_empty());
        assert!(before
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("invalid_or_simulation_source")));
        std::fs::write(
            repo.join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join(&final_relative),
            b"tampered",
        )?;
        let after = load_frozen_outcome_history(&repo, &RunId::new("next-run")?)?;
        assert!(after.rows.is_empty());
        assert!(after
            .provenance
            .exclusions
            .iter()
            .any(|reason| reason.contains("unfinalized_or_unauthenticated")));
        Ok(())
    }

    #[test]
    fn frozen_projection_filters_exact_task_without_mutating_source() {
        let row = project_numeric_row(&fixture()).unwrap();
        let snapshot = FrozenOutcomeHistory {
            provenance: crate::selection::AuthenticatedOutcomeHistoryProvenance {
                snapshot_sha256: "fixture".to_string(),
                source_digests: Vec::new(),
                exclusions: Vec::new(),
                projected_attempt_count: 1,
            },
            rows: vec![row.clone()],
        };
        assert_eq!(snapshot.outcomes_for(&row.task), vec![row]);
        let mut other = snapshot.rows[0].task.clone();
        other.task_class = "other".to_string();
        assert!(snapshot.outcomes_for(&other).is_empty());
        assert_eq!(snapshot.provenance.snapshot_sha256, "fixture");
    }
}
