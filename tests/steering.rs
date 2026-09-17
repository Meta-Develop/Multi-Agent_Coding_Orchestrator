use anyhow::{Context, Result};
use git2::Repository;
use multi_agent_coding_orchestrator::{
    agent_lifecycle::{AgentLaunchMetadata, AgentRegistry},
    hierarchy_ledger::RoleCategory,
    steering::{
        AssignmentBinding, AssignmentKind, SteeringAction, SteeringActor, SteeringOutcome,
        SteeringPlane, SteeringRequest, STEERING_REQUEST_VERSION, STEERING_STATE_NAMESPACE,
    },
    supervise::ModelCapabilityClass,
};
use std::{
    path::Path,
    process::{Child, Command},
};
use tempfile::TempDir;

struct SleepChild(Child);

impl SleepChild {
    fn spawn() -> Result<Self> {
        let program = [
            "/run/current-system/sw/bin/sleep",
            "/usr/bin/sleep",
            "/bin/sleep",
        ]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("sleep executable")?;
        Ok(Self(
            Command::new(program)
                .arg("60")
                .spawn()
                .context("spawn sleep")?,
        ))
    }
}

impl Drop for SleepChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn plane() -> Result<(TempDir, SteeringPlane)> {
    let temp = TempDir::new().context("tempdir")?;
    Repository::init(temp.path()).context("init repository")?;
    let plane = SteeringPlane::open(temp.path()).context("open steering plane")?;
    Ok((temp, plane))
}

#[test]
fn public_api_records_authenticated_inject_evidence_without_checkpoint_state() -> Result<()> {
    let (temp, plane) = plane()?;
    plane.register_assignment(AssignmentBinding {
        run_id: "run-public".to_string(),
        assignment_id: "task-public".to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    })?;
    let now = plane.current_unix_ms()?;
    let decision = plane.submit(
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: "act-public".to_string(),
            run_id: "run-public".to_string(),
            assignment_id: "task-public".to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::InjectCorrectiveInput {
                message: "keep the change inside src/steering.rs".to_string(),
            },
            deadline_unix_ms: now + 10_000,
        },
        now,
    )?;
    assert_eq!(decision.ack().outcome, SteeringOutcome::Delivered);
    assert!(!decision.ack().steered);
    let ack = plane.acknowledge("run-public", "task-public", "act-public", now)?;
    assert_eq!(ack.outcome, SteeringOutcome::Acknowledged);
    assert!(ack.steered);
    let evidence = plane.evidence("run-public")?;
    assert!(evidence
        .iter()
        .any(|record| record.event == "ack" && record.steered));
    let common = temp.path().join(".git").join("maco").join("state");
    assert!(common.join(STEERING_STATE_NAMESPACE).is_dir());
    assert!(!common.join("orchestration-checkpoints-v3").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancel_stops_a_launched_child_registered_in_the_agent_lifecycle() -> Result<()> {
    let (temp, plane) = plane()?;
    let registry = AgentRegistry::open(temp.path())?;
    let mut child = SleepChild::spawn()?;
    let pid = child.0.id();
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-live", "task-live")?,
        pid,
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    plane.register_assignment(AssignmentBinding {
        run_id: "run-live".to_string(),
        assignment_id: "task-live".to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    })?;
    let now = plane.current_unix_ms()?;
    let decision = plane.submit(
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: "act-stop".to_string(),
            run_id: "run-live".to_string(),
            assignment_id: "task-live".to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::CancelAssignment {
                reason: "operator cancelled the in-flight worker".to_string(),
            },
            deadline_unix_ms: now + 10_000,
        },
        now,
    )?;
    assert_eq!(decision.ack().outcome, SteeringOutcome::Acknowledged);
    assert!(decision.ack().steered);
    let status = child.0.wait().context("wait stopped child")?;
    assert!(!status.success());
    let leftover = registry.list(
        &multi_agent_coding_orchestrator::agent_lifecycle::AgentListFilter {
            run_id: Some("run-live".to_string()),
        },
    )?;
    assert!(leftover.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn lost_child_cannot_leave_an_unacknowledged_steered_state() -> Result<()> {
    let (temp, plane) = plane()?;
    let registry = AgentRegistry::open(temp.path())?;
    let mut child = SleepChild::spawn()?;
    let pid = child.0.id();
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-lost", "task-lost")?,
        pid,
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    plane.register_assignment(AssignmentBinding {
        run_id: "run-lost".to_string(),
        assignment_id: "task-lost".to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    })?;
    child.0.kill().context("kill lost child")?;
    child.0.wait().context("wait lost child")?;

    let now = plane.current_unix_ms()?;
    let decision = plane.submit(
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: "act-lost".to_string(),
            run_id: "run-lost".to_string(),
            assignment_id: "task-lost".to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::CancelAssignment {
                reason: "child already gone".to_string(),
            },
            deadline_unix_ms: now + 10_000,
        },
        now,
    )?;
    assert_eq!(decision.ack().outcome, SteeringOutcome::LostChild);
    assert!(!decision.ack().steered);

    let reopened = SteeringPlane::open(temp.path()).context("reopen")?;
    let evidence = reopened.evidence("run-lost")?;
    assert!(evidence
        .iter()
        .any(|record| record.event == "lost_child" && !record.steered));
    assert!(evidence.iter().all(|record| !record.steered));
    let ack = reopened.acknowledge("run-lost", "task-lost", "act-lost", now)?;
    assert_eq!(ack.outcome, SteeringOutcome::LostChild);
    assert!(!ack.steered);
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancel_stops_only_the_matching_run_when_assignment_ids_collide() -> Result<()> {
    let (temp, plane) = plane()?;
    let registry = AgentRegistry::open(temp.path())?;
    let mut child_a = SleepChild::spawn()?;
    let mut child_b = SleepChild::spawn()?;
    let shared_task = "shared-assignment";
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-a", shared_task)?,
        child_a.0.id(),
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-b", shared_task)?,
        child_b.0.id(),
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    for run_id in ["run-a", "run-b"] {
        plane.register_assignment(AssignmentBinding {
            run_id: run_id.to_string(),
            assignment_id: shared_task.to_string(),
            role_category: RoleCategory::NonDelegatingTerminalWorker,
            model_capability: Some(ModelCapabilityClass::WeakMechanical),
            parent_agent_id: Some("o1-1".to_string()),
            kind: AssignmentKind::Execution,
        })?;
    }

    let now = plane.current_unix_ms()?;
    let decision = plane.submit(
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: "act-run-a-only".to_string(),
            run_id: "run-a".to_string(),
            assignment_id: shared_task.to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::CancelAssignment {
                reason: "cancel run-a worker only".to_string(),
            },
            deadline_unix_ms: now + 10_000,
        },
        now,
    )?;
    assert_eq!(decision.ack().outcome, SteeringOutcome::Acknowledged);
    assert!(decision.ack().steered);

    let status = child_a.0.wait().context("wait stopped run-a child")?;
    assert!(!status.success());
    assert!(child_b.0.try_wait()?.is_none());

    let leftover = registry.list(
        &multi_agent_coding_orchestrator::agent_lifecycle::AgentListFilter {
            run_id: Some("run-b".to_string()),
        },
    )?;
    assert_eq!(leftover.len(), 1);
    assert_eq!(leftover[0].task_id, shared_task);
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancel_already_gone_target_does_not_stop_same_task_on_another_run() -> Result<()> {
    let (temp, plane) = plane()?;
    let registry = AgentRegistry::open(temp.path())?;
    let shared_task = "shared-assignment";
    let mut gone_child = SleepChild::spawn()?;
    let mut live_child = SleepChild::spawn()?;
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-gone", shared_task)?,
        gone_child.0.id(),
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    registry.register(
        &AgentLaunchMetadata::new(temp.path(), "worker", "run-live", shared_task)?,
        live_child.0.id(),
        vec!["sleep".to_string(), "60".to_string()],
    )?;
    plane.register_assignment(AssignmentBinding {
        run_id: "run-gone".to_string(),
        assignment_id: shared_task.to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    })?;
    plane.register_assignment(AssignmentBinding {
        run_id: "run-live".to_string(),
        assignment_id: shared_task.to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    })?;
    gone_child.0.kill().context("kill gone child")?;
    gone_child.0.wait().context("wait gone child")?;

    let now = plane.current_unix_ms()?;
    let decision = plane.submit(
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: "act-gone-only".to_string(),
            run_id: "run-gone".to_string(),
            assignment_id: shared_task.to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::CancelAssignment {
                reason: "gone child must not take down sibling run".to_string(),
            },
            deadline_unix_ms: now + 10_000,
        },
        now,
    )?;
    assert_eq!(decision.ack().outcome, SteeringOutcome::LostChild);
    assert!(!decision.ack().steered);
    assert!(live_child.0.try_wait()?.is_none());

    let sibling = registry.list(
        &multi_agent_coding_orchestrator::agent_lifecycle::AgentListFilter {
            run_id: Some("run-live".to_string()),
        },
    )?;
    assert_eq!(sibling.len(), 1);
    assert_eq!(sibling[0].task_id, shared_task);
    Ok(())
}
