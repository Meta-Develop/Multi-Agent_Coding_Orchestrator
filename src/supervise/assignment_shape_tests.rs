use super::*;
use crate::selection::{ContextSize, TaskHorizon};

fn frozen_policy() -> Result<crate::selection::routing_policy::FrozenRoutingPolicy> {
    let policy = serde_json::from_str(include_str!("../selection/data/routing-policy.json"))?;
    refreeze(policy)
}

fn refreeze(
    policy: crate::selection::routing_policy::LoadedRoutingPolicy,
) -> Result<crate::selection::routing_policy::FrozenRoutingPolicy> {
    policy.validate()?;
    Ok(crate::selection::routing_policy::FrozenRoutingPolicy {
        sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy)?),
        policy,
        source: "assignment-shape-test".to_string(),
    })
}

fn recursive_plan() -> Result<LoadedSupervisorPlan> {
    parse_supervisor_plan_with_consultant(
        &json!({
            "version": 1, "task": "Update documentation", "max_depth": 3,
            "max_child_assignments": 2,
            "resolved_routing_policy": frozen_policy()?,
            "assignments": [{
                "id": "parent", "phase": "planning", "role": "child_orchestrator",
                "assigned_paths": ["README.md"],
                "child_assignments": [{
                    "id": "leaf", "phase": "execution", "role": "worker",
                    "role_category": "non_delegating_terminal_worker",
                    "assigned_paths": ["README.md"], "task": "Fix a documentation typo"
                }]
            }]
        })
        .to_string(),
    )
}

fn declare(loaded: &mut LoadedSupervisorPlan, index: usize) -> Result<AssignmentShapeDeclaration> {
    let declaration = AssignmentShapeDeclaration::assess(
        &loaded.plan,
        index,
        &loaded.plan_metadata.assignment_schedule,
        loaded
            .plan_metadata
            .resolved_routing_policy
            .as_ref()
            .unwrap(),
        if loaded.plan.assignments[index].phase == AssignmentPhase::Planning {
            AssignmentEffects::ReadOnly
        } else {
            AssignmentEffects::RepositoryWrite
        },
    )?;
    loaded.plan.assignments[index].assignment_shape = Some(declaration.clone());
    Ok(declaration)
}

fn document(loaded: &LoadedSupervisorPlan) -> Result<Value> {
    supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

#[test]
fn assignment_shape_replay_rejects_task_and_path_drift() -> Result<()> {
    let mut loaded = recursive_plan()?;
    let declaration = declare(&mut loaded, 1)?;
    let wire = document(&loaded)?;
    let restored = parse_supervisor_plan_with_consultant(&wire.to_string())?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .unwrap();
    let validated = declaration.validate(
        &restored.plan,
        1,
        &restored.plan_metadata.assignment_schedule,
        frozen,
    )?;
    assert_eq!(validated.profile(), &declaration.profile);
    assert_eq!(validated.identity().sha256().len(), 64);
    assert_eq!(document(&restored)?, wire);
    for (pointer, changed) in [
        ("/assignments/1/task", json!("Fix a documentation typo ")),
        ("/assignments/1/assigned_paths", json!(["other.md"])),
        ("/assignments/1/semantic_modules", json!(["extra"])),
        ("/assignments/1/notes", json!("delete obsolete records")),
        ("/assignments/1/phase", json!("planning")),
    ] {
        let mut drift = wire.clone();
        // Notes is optional and may be absent in the canonical document.
        if pointer.ends_with("notes") {
            drift["assignments"][1]["notes"] = changed;
        } else {
            *drift.pointer_mut(pointer).unwrap() = changed;
        }
        assert!(
            parse_supervisor_plan_with_consultant(&drift.to_string()).is_err(),
            "{pointer}"
        );
    }
    let mut changed_policy = frozen.policy.clone();
    changed_policy.task_estimation.as_mut().unwrap().risk.base += 1;
    let changed_policy = refreeze(changed_policy)?;
    assert!(declaration
        .validate(
            &loaded.plan,
            1,
            &loaded.plan_metadata.assignment_schedule,
            &changed_policy
        )
        .is_err());
    let mut forged_policy = frozen.clone();
    forged_policy
        .policy
        .task_estimation
        .as_mut()
        .unwrap()
        .risk
        .base += 1;
    assert!(declaration
        .validate(
            &loaded.plan,
            1,
            &loaded.plan_metadata.assignment_schedule,
            &forged_policy
        )
        .is_err());
    // Routing a different candidate must not relabel the same assignment.
    loaded.plan.assignments[1].runtime = Some(RuntimeId::Grok);
    loaded.plan.assignments[1].selection_source = Some(AssignmentSelectionSource::Retry);
    assert_eq!(
        declaration.validate(
            &loaded.plan,
            1,
            &loaded.plan_metadata.assignment_schedule,
            frozen
        )?,
        validated
    );
    Ok(())
}

#[test]
fn assignment_shape_minimums_cover_each_dimension_and_unknown_policy_bands() -> Result<()> {
    let mut loaded = recursive_plan()?;
    let mut policy = frozen_policy()?.policy;
    let estimator = policy.task_estimation.as_mut().unwrap();
    for band in &mut estimator.risk_bands {
        band.value = RiskLevel::Critical;
    }
    for band in &mut estimator.boundedness_bands {
        band.value = Boundedness::CrossCutting;
    }
    for band in &mut estimator.context_bands {
        band.value = ContextSize::Long;
    }
    for band in &mut estimator.horizon_bands {
        band.value = TaskHorizon::Long;
    }
    loaded.plan_metadata.resolved_routing_policy = Some(refreeze(policy.clone())?);
    let declaration = declare(&mut loaded, 1)?;
    assert_eq!(declaration.profile.risk, RiskLevel::Critical);
    assert_eq!(declaration.profile.boundedness, Boundedness::CrossCutting);
    assert_eq!(declaration.profile.context, ContextSize::Long);
    assert_eq!(declaration.profile.horizon, TaskHorizon::Long);
    for (axis, understated) in [
        ("risk", json!("low")),
        ("boundedness", json!("tightly_bounded")),
        ("context", json!("small")),
        ("horizon", json!("short")),
        ("authority_role", json!("delegating")),
        ("task_class", json!("other")),
    ] {
        let mut drift = document(&loaded)?;
        drift["assignments"][1]["assignment_shape"]["profile"][axis] = understated;
        assert!(
            parse_supervisor_plan_with_consultant(&drift.to_string()).is_err(),
            "{axis}"
        );
    }
    for band in &mut policy.task_estimation.as_mut().unwrap().risk_bands {
        band.value = RiskLevel::Unknown;
    }
    loaded.plan.assignments[1].assignment_shape = None;
    loaded.plan_metadata.resolved_routing_policy = Some(refreeze(policy)?);
    let unknown = declare(&mut loaded, 1)?;
    assert_eq!(unknown.profile.risk, RiskLevel::Unknown);
    let mut drift = document(&loaded)?;
    drift["assignments"][1]["assignment_shape"]["profile"]["risk"] = json!("critical");
    assert!(parse_supervisor_plan_with_consultant(&drift.to_string()).is_err());
    Ok(())
}

#[test]
fn assignment_shape_effects_delegation_and_authority_cannot_be_lowered() -> Result<()> {
    let mut loaded = recursive_plan()?;
    let parent = declare(&mut loaded, 0)?;
    assert_eq!(parent.delegation, AssignmentDelegation::Delegating);
    assert_eq!(parent.profile.authority_role, AuthorityRole::Delegating);
    let mut drift = document(&loaded)?;
    drift["assignments"][0]["assignment_shape"]["delegation"] = json!("terminal");
    assert!(parse_supervisor_plan_with_consultant(&drift.to_string()).is_err());
    let mut drift = document(&loaded)?;
    drift["assignments"][0]["assignment_shape"]["profile"]["authority_role"] =
        json!("terminal_leaf");
    assert!(parse_supervisor_plan_with_consultant(&drift.to_string()).is_err());
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .unwrap();
    assert!(AssignmentShapeDeclaration::assess(
        &loaded.plan,
        1,
        &loaded.plan_metadata.assignment_schedule,
        frozen,
        AssignmentEffects::ReadOnly,
    )
    .is_err());
    let external = AssignmentShapeDeclaration::assess(
        &loaded.plan,
        1,
        &loaded.plan_metadata.assignment_schedule,
        frozen,
        AssignmentEffects::ExternalSideEffects,
    )?;
    assert!(external.profile.risk >= RiskLevel::High);
    assert!(external.profile.boundedness >= Boundedness::CrossCutting);
    loaded.plan.assignments[1].assignment_shape = Some(external);
    let mut drift = document(&loaded)?;
    drift["assignments"][1]["assignment_shape"]["profile"]["risk"] = json!("low");
    assert!(parse_supervisor_plan_with_consultant(&drift.to_string()).is_err());
    let publication = AssignmentShapeDeclaration::assess(
        &loaded.plan,
        1,
        &loaded.plan_metadata.assignment_schedule,
        frozen,
        AssignmentEffects::Publication,
    )?;
    assert_eq!(publication.profile.risk, RiskLevel::Critical);
    assert_eq!(
        publication.profile.authority_role,
        AuthorityRole::TerminalLeaf
    );
    // A designation override cannot masquerade as proven terminal fitness.
    loaded.plan.assignments[1].selection_source = Some(AssignmentSelectionSource::OperatorOverride);
    let overridden = AssignmentShapeDeclaration::assess(
        &loaded.plan,
        1,
        &loaded.plan_metadata.assignment_schedule,
        frozen,
        AssignmentEffects::RepositoryWrite,
    )?;
    assert_eq!(
        overridden.profile.authority_role,
        AuthorityRole::UnknownJudgment
    );
    Ok(())
}

#[test]
fn recursive_assignment_shapes_round_trip_and_legacy_stays_unproven() -> Result<()> {
    let mut loaded = recursive_plan()?;
    assert!(loaded
        .plan
        .assignments
        .iter()
        .all(|assignment| assignment.assignment_shape.is_none()));
    let legacy = document(&loaded)?;
    declare(&mut loaded, 0)?;
    let leaf = declare(&mut loaded, 1)?;
    let mut nested = document(&loaded)?;
    let leaf_value = nested["assignments"].as_array_mut().unwrap().pop().unwrap();
    nested["assignments"][0]["child_assignments"] = json!([leaf_value]);
    nested
        .as_object_mut()
        .unwrap()
        .remove("assignment_schedule");
    let restored = parse_supervisor_plan_with_consultant(&nested.to_string())?;
    assert_eq!(restored.plan, loaded.plan);
    assert_eq!(
        restored.plan.assignments[1].assignment_shape.as_ref(),
        Some(&leaf)
    );
    for (field, invalid) in [
        ("version", json!(2)),
        ("policy_sha256", json!("a".repeat(64))),
        ("assignment_input_sha256", json!("not-a-digest")),
        ("unknown", json!(true)),
    ] {
        let mut drift = nested.clone();
        drift["assignments"][0]["child_assignments"][0]["assignment_shape"][field] = invalid;
        assert!(
            parse_supervisor_plan_with_consultant(&drift.to_string()).is_err(),
            "{field}"
        );
    }
    let mut null = legacy.clone();
    null["assignments"][1]["assignment_shape"] = Value::Null;
    assert!(parse_supervisor_plan_with_consultant(&null.to_string()).is_err());
    let mut missing_policy = document(&loaded)?;
    missing_policy
        .as_object_mut()
        .unwrap()
        .remove("resolved_routing_policy");
    assert!(parse_supervisor_plan_with_consultant(&missing_policy.to_string()).is_err());
    let mut no_policy = legacy;
    no_policy
        .as_object_mut()
        .unwrap()
        .remove("resolved_routing_policy");
    let restored = parse_supervisor_plan_with_consultant(&no_policy.to_string())?;
    assert!(restored
        .plan
        .assignments
        .iter()
        .all(|assignment| assignment.assignment_shape.is_none()));
    Ok(())
}

#[test]
fn assignment_shape_bounds_and_fallback_task_are_revalidated() -> Result<()> {
    let mut loaded = recursive_plan()?;
    loaded.plan.assignments[1].task = None;
    declare(&mut loaded, 1)?;
    let mut drift = document(&loaded)?;
    drift["task"] = json!("A different fallback task");
    assert!(parse_supervisor_plan_with_consultant(&drift.to_string()).is_err());
    loaded.plan.assignments[1].assignment_shape = None;
    let mut policy = frozen_policy()?.policy;
    policy.task_estimation = None;
    loaded.plan_metadata.resolved_routing_policy = Some(refreeze(policy)?);
    assert!(declare(&mut loaded, 1).is_err());
    loaded.plan_metadata.resolved_routing_policy = Some(frozen_policy()?);
    loaded.plan.assignments[1].notes = Some("x".repeat(262145));
    assert!(declare(&mut loaded, 1).is_err());
    loaded.plan.assignments[1].notes = None;
    loaded.plan_metadata.assignment_schedule.pop();
    assert!(declare(&mut loaded, 1).is_err());
    Ok(())
}

#[test]
fn assignment_shape_binds_nested_worker_text_scope_and_effects() -> Result<()> {
    let mut loaded = recursive_plan()?;
    loaded.plan.assignments.truncate(1);
    loaded.plan_metadata.assignment_schedule.truncate(1);
    loaded.plan.assignments[0].phase = AssignmentPhase::Execution;
    loaded.plan.assignments[0].worker_assignments = vec![serde_json::from_value(json!({
        "id": "nested", "role": "worker", "assigned_paths": ["README.md"],
        "task": "Fix a documentation typo"
    }))?];
    let declaration = declare(&mut loaded, 0)?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .unwrap();
    let schedule = &loaded.plan_metadata.assignment_schedule;
    let original = declaration.validate(&loaded.plan, 0, schedule, frozen)?;
    let mut expanded = loaded.plan.clone();
    expanded.assignments[0].licensed_breakage = Some(LicensedBreakageDeclaration {
        migration_rationale: "x".repeat(30000),
        dependents: vec![LicensedBreakageDependentScope {
            dependent_id: "client".into(),
            paths: vec!["client.rs".into()],
            interfaces: Vec::new(),
        }],
    });
    let expanded = AssignmentShapeDeclaration::assess(
        &expanded,
        0,
        schedule,
        frozen,
        AssignmentEffects::RepositoryWrite,
    )?;
    assert!(expanded.profile.context > original.profile().context);
    assert!(expanded.profile.risk >= RiskLevel::High);
    for axis in ["task", "path", "effects"] {
        let mut changed = loaded.plan.clone();
        let mut shape = declaration.clone();
        match axis {
            "task" => {
                changed.assignments[0].worker_assignments[0].task = Some("Different work".into())
            }
            "path" => {
                changed.assignments[0].worker_assignments[0].assigned_paths =
                    vec!["other.md".into()]
            }
            "effects" => shape.effects = AssignmentEffects::ExternalSideEffects,
            _ => unreachable!(),
        }
        assert!(
            shape.validate(&changed, 0, schedule, frozen).is_err(),
            "{axis}"
        );
    }
    let mut raised = declaration;
    raised.profile.risk = RiskLevel::Critical;
    let raised = raised.validate(&loaded.plan, 0, schedule, frozen)?;
    assert_eq!(raised.profile().risk, RiskLevel::Critical);
    assert_ne!(raised.identity(), original.identity());
    Ok(())
}

fn nested_path_plan() -> Result<LoadedSupervisorPlan> {
    let mut loaded = recursive_plan()?;
    loaded.plan.assignments.truncate(1);
    loaded.plan_metadata.assignment_schedule.truncate(1);
    let assignment = &mut loaded.plan.assignments[0];
    assignment.phase = AssignmentPhase::Execution;
    assignment.assigned_paths = vec!["src/main.rs".into()];
    assignment.worker_assignments = vec![serde_json::from_value(json!({
        "id": "nested", "role": "worker",
        "role_category": "non_delegating_terminal_worker",
        "assigned_paths": ["src/main.rs"], "report_path": "reports/nested/report.json",
        "task": "Fix a documentation typo"
    }))?];
    assignment.licensed_breakage = Some(LicensedBreakageDeclaration {
        migration_rationale: "Update the dependent interface".into(),
        dependents: vec![LicensedBreakageDependentScope {
            dependent_id: "client".into(),
            paths: vec!["clients/app/main.rs".into()],
            interfaces: Vec::new(),
        }],
    });
    Ok(loaded)
}

#[test]
fn assignment_shape_nested_paths_use_portable_binding_and_profile() -> Result<()> {
    let mut loaded = nested_path_plan()?;
    let declaration = declare(&mut loaded, 0)?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .unwrap();
    let schedule = &loaded.plan_metadata.assignment_schedule;
    let original = declaration.validate(&loaded.plan, 0, schedule, frozen)?;
    // Spell every path explicitly in the reference input, independently of the
    // native PathBuf serializer, so Windows must produce the same binding.
    let mut expected_assignment = serde_json::to_value(&loaded.plan.assignments[0])?;
    expected_assignment
        .as_object_mut()
        .unwrap()
        .remove("assignment_shape");
    expected_assignment["assigned_paths"] = json!(["src/main.rs"]);
    expected_assignment["worker_assignments"][0]["assigned_paths"] = json!(["src/main.rs"]);
    expected_assignment["worker_assignments"][0]["report_path"] =
        json!("reports/nested/report.json");
    expected_assignment["licensed_breakage"]["dependents"][0]["paths"] =
        json!(["clients/app/main.rs"]);
    let expected_input = serde_json::to_vec(&json!({
        "task": loaded.plan.task, "assignment": expected_assignment,
        "schedule": schedule[0], "children": [],
        "effects": "repository_write", "delegation": "delegating"
    }))?;
    assert_eq!(
        declaration.assignment_input_sha256,
        crate::artifacts::state_auth::sha256_hex(&expected_input)
    );
    for axis in 0..=4 {
        let mut changed = loaded.plan.clone();
        let assignment = &mut changed.assignments[0];
        if axis == 0 || axis == 4 {
            assignment.assigned_paths = vec![r"src\main.rs".into()];
        }
        if axis == 1 || axis == 4 {
            assignment.worker_assignments[0].assigned_paths = vec![r"src\main.rs".into()];
        }
        if axis == 2 || axis == 4 {
            assignment.worker_assignments[0].report_path =
                Some(r"reports\nested\report.json".into());
        }
        if axis == 3 || axis == 4 {
            assignment.licensed_breakage.as_mut().unwrap().dependents[0].paths =
                vec![r"clients\app\main.rs".into()];
        }
        assert_eq!(
            AssignmentShapeDeclaration::assess(
                &changed,
                0,
                schedule,
                frozen,
                AssignmentEffects::RepositoryWrite
            )?,
            declaration,
            "path field {axis}"
        );
        assert_eq!(
            declaration.validate(&changed, 0, schedule, frozen)?,
            original
        );
    }
    Ok(())
}

#[test]
fn assignment_shape_binds_nested_operator_designation_but_not_retry_sources() -> Result<()> {
    let mut loaded = nested_path_plan()?;
    let declaration = declare(&mut loaded, 0)?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .unwrap();
    let schedule = &loaded.plan_metadata.assignment_schedule;
    let original = declaration.validate(&loaded.plan, 0, schedule, frozen)?;
    for source in [
        AssignmentSelectionSource::Automatic,
        AssignmentSelectionSource::Retry,
        AssignmentSelectionSource::PlanRoleModels,
    ] {
        let mut changed = loaded.plan.clone();
        changed.assignments[0].runtime = Some(RuntimeId::Grok);
        changed.assignments[0].worker_assignments[0].selection_source = Some(source);
        assert_eq!(
            declaration.validate(&changed, 0, schedule, frozen)?,
            original
        );
    }
    let mut changed = loaded.plan.clone();
    let worker = &mut changed.assignments[0].worker_assignments[0];
    assert_eq!(worker.role_category, Some(worker.role.authority_category()));
    worker.selection_source = Some(AssignmentSelectionSource::OperatorOverride);
    assert!(declaration.validate(&changed, 0, schedule, frozen).is_err());
    let designated = AssignmentShapeDeclaration::assess(
        &changed,
        0,
        schedule,
        frozen,
        AssignmentEffects::RepositoryWrite,
    )?;
    assert_ne!(
        designated.assignment_input_sha256,
        declaration.assignment_input_sha256
    );
    assert_ne!(
        designated
            .validate(&changed, 0, schedule, frozen)?
            .identity(),
        original.identity()
    );
    changed.assignments[0].worker_assignments[0].selection_source =
        Some(AssignmentSelectionSource::Retry);
    assert!(designated.validate(&changed, 0, schedule, frozen).is_err());
    Ok(())
}
