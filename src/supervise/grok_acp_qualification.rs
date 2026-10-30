//! Process-local operator authority for the unqualified 4.7 ACP writable route.
//! Neither environment variables nor serialized plans/Worker reports mint this authority.

use super::{
    AgentRole, AssignmentPhase, RoleCategory, SupervisorBudgetConfig, SupervisorPlan,
    SupervisorRunOptions, SupervisorRuntime, UnavailableModelFallback,
};
use crate::artifacts::{ArtifactFileDisposition, ArtifactRunWriter};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub(crate) const EVIDENCE_PATH: &str = "qualification/grok47-acp.json";

#[derive(Debug, thiserror::Error)]
#[error("writable_grok47_acp_qualification_required: grok-4.7 ACP writable admission is disabled pending Linux managed-child qualification (#616); a fresh Codex supervise run requires operator --qualify-grok47-acp and archived qualification evidence")]
pub(crate) struct QualificationRequired;

type RunKey = (PathBuf, String);
static OPERATOR_RUNS: Mutex<BTreeMap<RunKey, Option<String>>> = Mutex::new(BTreeMap::new());

pub(crate) struct OperatorRunGuard(RunKey);

impl Drop for OperatorRunGuard {
    fn drop(&mut self) {
        OPERATOR_RUNS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Called only by explicit CLI intake, never by plan parsing or child command construction.
pub(crate) fn bind_operator_run(
    repo: &Path,
    run_id: &str,
    runtime: SupervisorRuntime,
) -> Result<OperatorRunGuard> {
    if runtime != SupervisorRuntime::Codex {
        bail!("--qualify-grok47-acp requires --runtime codex");
    }
    let key = (repo.to_path_buf(), run_id.to_string());
    let mut runs = OPERATOR_RUNS.lock().map_err(|_| QualificationRequired)?;
    if runs.contains_key(&key) {
        bail!("duplicate Grok ACP qualification authority for this run");
    }
    runs.insert(key.clone(), None);
    Ok(OperatorRunGuard(key))
}

pub(crate) fn admits_worker(repo: &Path, run_id: &str, assignment_id: &str) -> bool {
    OPERATOR_RUNS.lock().ok().is_some_and(|runs| {
        runs.get(&(repo.to_path_buf(), run_id.to_string()))
            .and_then(Option::as_deref)
            == Some(assignment_id)
    })
}

fn qualification_assignment<'a>(
    runtime: SupervisorRuntime,
    plan: &'a SupervisorPlan,
    budget: &SupervisorBudgetConfig,
) -> Result<&'a str> {
    if runtime != SupervisorRuntime::Codex
        || plan.assignments.len() != 1
        || plan.max_child_retries != 0
        || plan.max_gate_corrections != 0
        || plan.child_timeout_seconds > 1200
        || !matches!(budget.limits.hard_tokens, Some(1..=160_000))
    {
        bail!("Grok ACP qualification requires Codex control, one assignment, zero retries/corrections, <=1200 seconds per child and <=160000 hard tokens");
    }
    let worker = &plan.assignments[0];
    let selection = plan
        .role_models
        .get(&AgentRole::Worker)
        .context("Grok ACP qualification requires explicit Worker selection")?;
    if worker.runtime != Some(SupervisorRuntime::Grok)
        || worker.phase != AssignmentPhase::Execution
        || worker.role != AgentRole::Worker
        || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
        || !worker.worker_assignments.is_empty()
        || selection.model.as_deref() != Some("grok-4.7")
        || selection.reasoning_effort.as_deref() != Some("xhigh")
        || selection.unavailable_model_fallback != UnavailableModelFallback::FailClosed
    {
        bail!("Grok ACP qualification requires exactly one non-delegating terminal grok-4.7/xhigh Worker with fail-closed availability");
    }
    Ok(&worker.id)
}

/// Persist authenticated run evidence before making the process-local exception usable.
/// Existing account, selection, schema, containment and publication gates remain independent.
pub(crate) fn archive_and_admit(
    writer: &mut ArtifactRunWriter,
    repo: &Path,
    options: &SupervisorRunOptions,
    plan: &SupervisorPlan,
    budget: &SupervisorBudgetConfig,
) -> Result<()> {
    let key = (repo.to_path_buf(), options.run_id.as_str().to_string());
    let mut runs = OPERATOR_RUNS.lock().map_err(|_| QualificationRequired)?;
    let Some(assignment) = runs.get_mut(&key) else {
        return Ok(());
    };
    let assignment_id = qualification_assignment(options.runtime, plan, budget)?;
    writer.write_json(
        EVIDENCE_PATH,
        &json!({
            "schema_version": 1,
            "source": "operator_cli",
            "flag": "--qualify-grok47-acp",
            "qualification_only": true,
            "issue": 616,
            "run_id": options.run_id.as_str(),
            "assignment_id": assignment_id,
            "supervisor_runtime": "codex",
            "worker_runtime": "grok",
            "model": "grok-4.7",
            "reasoning_effort": "xhigh",
            "protocol": "acp_stdio",
            "hard_tokens": budget.limits.hard_tokens,
            "max_child_retries": 0,
            "max_gate_corrections": 0,
            "child_timeout_seconds": plan.child_timeout_seconds,
            "production_qualified": false
        }),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    *assignment = Some(assignment_id.to_string());
    Ok(())
}

#[cfg(test)]
pub(crate) fn admit_for_test(repo: &Path, run: &str, worker: &str) -> OperatorRunGuard {
    let guard = bind_operator_run(repo, run, SupervisorRuntime::Codex).unwrap();
    *OPERATOR_RUNS.lock().unwrap().get_mut(&guard.0).unwrap() = Some(worker.into());
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{artifacts::RunArtifactFamily, orchestrator::RunId};

    fn fixture() -> (SupervisorPlan, SupervisorBudgetConfig) {
        let document = include_str!("../../examples/supervise/qualification-grok47-acp.json");
        let plan = serde_json::from_str(document).unwrap();
        let value: serde_json::Value = serde_json::from_str(document).unwrap();
        let budget = serde_json::from_value(value["run_budget"].clone()).unwrap();
        (plan, budget)
    }

    #[test]
    fn qualification_exception_requires_bounded_exact_worker() {
        let (plan, budget) = fixture();
        assert!(qualification_assignment(SupervisorRuntime::Codex, &plan, &budget).is_ok());
        assert!(qualification_assignment(SupervisorRuntime::Grok, &plan, &budget).is_err());
        for case in [
            "retries",
            "corrections",
            "timeout",
            "two-workers",
            "effort",
            "model",
            "runtime",
            "role",
            "fallback",
        ] {
            let mut changed = plan.clone();
            match case {
                "retries" => changed.max_child_retries = 1,
                "corrections" => changed.max_gate_corrections = 1,
                "timeout" => changed.child_timeout_seconds = 1201,
                "two-workers" => changed.assignments.push(changed.assignments[0].clone()),
                "effort" => {
                    changed
                        .role_models
                        .get_mut(&AgentRole::Worker)
                        .unwrap()
                        .reasoning_effort = Some("low".into())
                }
                "model" => {
                    changed
                        .role_models
                        .get_mut(&AgentRole::Worker)
                        .unwrap()
                        .model = Some("grok-4.6".into())
                }
                "runtime" => changed.assignments[0].runtime = Some(SupervisorRuntime::Codex),
                "role" => changed.assignments[0].role = AgentRole::ChildOrchestrator,
                "fallback" => {
                    changed
                        .role_models
                        .get_mut(&AgentRole::Worker)
                        .unwrap()
                        .unavailable_model_fallback = UnavailableModelFallback::RuntimeDefault
                }
                _ => unreachable!(),
            }
            assert!(
                qualification_assignment(SupervisorRuntime::Codex, &changed, &budget).is_err(),
                "{case}"
            );
        }
        for hard_tokens in [None, Some(0), Some(160_001)] {
            let mut changed = budget.clone();
            changed.limits.hard_tokens = hard_tokens;
            assert!(qualification_assignment(SupervisorRuntime::Codex, &plan, &changed).is_err());
        }
    }

    #[test]
    fn qualification_authority_requires_archived_evidence_and_is_run_scoped() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let repo = temp.path().canonicalize()?;
        let run_id = RunId::new("qualification-evidence")?;
        let (plan, budget) = fixture();
        let worker = &plan.assignments[0].id;
        // A valid authored plan alone grants no authority.
        assert!(!admits_worker(&repo, run_id.as_str(), worker));
        let guard = bind_operator_run(&repo, run_id.as_str(), SupervisorRuntime::Codex)?;
        assert!(!admits_worker(&repo, run_id.as_str(), worker));
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "qualification-test",
        )?;
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: "unused.json".into(),
            run_id: run_id.clone(),
            parent_node: None,
            codex_bin: "codex".into(),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: Default::default(),
            budget_overrides: Default::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: None,
        };
        // Evidence must be durably written before the exception becomes usable.
        std::fs::write(writer.run_dir().join("qualification"), "blocked directory")?;
        assert!(archive_and_admit(&mut writer, &repo, &options, &plan, &budget).is_err());
        assert!(!admits_worker(&repo, run_id.as_str(), worker));
        std::fs::remove_file(writer.run_dir().join("qualification"))?;
        archive_and_admit(&mut writer, &repo, &options, &plan, &budget)?;
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(writer.run_dir().join(EVIDENCE_PATH))?)?;
        assert_eq!(receipt["source"], "operator_cli");
        assert_eq!(receipt["run_id"], run_id.as_str());
        assert_eq!(receipt["assignment_id"], worker.as_str());
        assert_eq!(receipt["hard_tokens"], 160000);
        assert_eq!(receipt["production_qualified"], false);
        assert!(admits_worker(&repo, run_id.as_str(), worker));
        assert!(!admits_worker(&repo, "other-run", worker));
        assert!(!admits_worker(temp.path(), run_id.as_str(), "other-worker"));
        assert!(!admits_worker(
            Path::new("other-repo"),
            run_id.as_str(),
            worker
        ));
        drop(guard);
        assert!(!admits_worker(&repo, run_id.as_str(), worker));
        Ok(())
    }
}
