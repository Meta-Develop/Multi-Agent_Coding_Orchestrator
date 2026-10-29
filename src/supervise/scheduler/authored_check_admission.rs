//! Scheduler-only admission backed by freshly revalidated authored-check receipts.

use super::*;
use crate::repo_semantic::SemanticRiskReport;
use anyhow::ensure;

pub(super) struct AcquiredAuthoredChecks {
    document: String,
    requested_assignments: Vec<OrchestratorAssignment>,
    metadata: AssignmentMetadata,
    receipts: BTreeMap<
        String,
        std::result::Result<authored_checks::AcquiredAuthoredCheckEvidence, String>,
    >,
}

/// This value is constructed only after receipt revalidation, never from metadata.
pub(super) struct AuthoredCheckAdmission<'a> {
    assignment: &'a OrchestratorAssignment,
}

impl AuthoredCheckAdmission<'_> {
    pub(super) fn matches(&self, assignment: &OrchestratorAssignment) -> bool {
        self.assignment == assignment
    }
}

impl AcquiredAuthoredChecks {
    pub(super) fn acquire(
        repo: &Path,
        document: String,
        requested_assignments: &[OrchestratorAssignment],
        metadata: &AssignmentMetadata,
        evidence: &PreclaimRunEvidence,
    ) -> Self {
        let receipts = metadata
            .authored_independent_checks
            .keys()
            .map(|parent_id| {
                let acquired = (|| -> Result<_> {
                    let loaded =
                        super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
                            &document,
                            Some(repo),
                        )?;
                    ensure!(
                        loaded.plan.assignments == requested_assignments
                            && &loaded.assignment_metadata == metadata,
                        "authored check declarations differ from the frozen plan document"
                    );
                    let parent = requested_assignments
                        .iter()
                        .find(|item| &item.id == parent_id)
                        .context("authored check parent is missing")?;
                    let risk = evidence
                        .risk_for(&parent.assigned_paths)
                        .context("authored checks require acquired semantic risk")?;
                    let fresh = crate::repo_semantic::scan_repository(repo)?;
                    ensure!(
                        risk == crate::repo_semantic::risk_report_for_paths(
                            &fresh,
                            parent.assigned_paths.iter()
                        ),
                        "authored check semantic risk changed during acquisition"
                    );
                    authored_checks::acquire(repo, &document, parent_id, &risk)
                })();
                (
                    parent_id.clone(),
                    acquired.map_err(|error| format!("{error:#}")),
                )
            })
            .collect();
        Self {
            document,
            requested_assignments: requested_assignments.to_vec(),
            metadata: metadata.clone(),
            receipts,
        }
    }

    pub(super) fn declares(&self, id: &str) -> bool {
        self.receipts.contains_key(id)
    }

    pub(super) fn admission<'a>(
        &self,
        repo: &Path,
        assignment: &'a OrchestratorAssignment,
        requested_assignments: &[OrchestratorAssignment],
        metadata: &AssignmentMetadata,
        risk: Option<&SemanticRiskReport>,
    ) -> Result<AuthoredCheckAdmission<'a>> {
        ensure!(
            requested_assignments == self.requested_assignments && metadata == &self.metadata,
            "authored check requested plan or metadata changed"
        );
        let requested = self
            .requested_assignments
            .iter()
            .find(|item| item.id == assignment.id)
            .context("authored check assignment is unrelated")?;
        // Selection may resolve a runtime after the gate. Every authored task,
        // nested Worker, scope and other assignment field must remain frozen.
        let mut current = assignment.clone();
        current.runtime = requested.runtime;
        ensure!(&current == requested, "authored check assignment changed");
        let receipt = self
            .receipts
            .get(&assignment.id)
            .context("authored check receipt is missing")?
            .as_ref()
            .map_err(|error| anyhow!("{error}"))?;
        receipt.revalidate(
            repo,
            &self.document,
            risk.context("authored check fresh semantic risk is missing")?,
        )?;
        Ok(AuthoredCheckAdmission { assignment })
    }
}
