use super::*;

#[test]
fn old_and_new_supervisor_model_economics_schema_round_trip() {
    let old_json = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
        .expect("parse old plan fixture");
    let old = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&old_json).expect("serialize old plan"),
    )
    .expect("old plan remains valid");
    assert!(old.plan.role_models.is_empty());
    assert!(old.plan.model_pricing.is_empty());
    let old_round_trip = supervisor_plan_value(
        &old.plan,
        &old.consultant,
        &old.assignment_metadata,
        &old.plan_metadata,
    )
    .expect("serialize old plan");
    assert!(old_round_trip.get("role_models").is_none());
    assert!(old_round_trip.get("model_pricing").is_none());

    let mut new_json = old_json;
    let object = new_json.as_object_mut().expect("plan object");
    object.insert(
        "role_models".to_string(),
        json!({
            "supervisor": {
                "model": "supervisor-model",
                "reasoning_effort": "xhigh"
            },
            "child_orchestrator": {
                "model": " planner-model ",
                "reasoning_effort": " high "
            },
            "worker": {
                "model": "worker-model",
                "reasoning_effort": "low"
            },
            "auditor": {
                "model": "auditor-model",
                "reasoning_effort": "xhigh"
            }
        }),
    );
    object.insert(
        "model_pricing".to_string(),
        json!({
            "planner-model": {
                "input_usd_per_million_tokens": 2.5,
                "output_usd_per_million_tokens": 10.0
            },
            "worker-model": {
                "input_usd_per_million_tokens": 0.25,
                "output_usd_per_million_tokens": 1.0
            }
        }),
    );
    let new = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&new_json).expect("serialize new plan"),
    )
    .expect("new model economics plan");
    assert_eq!(
        new.plan.role_models[&AgentRole::Supervisor]
            .model
            .as_deref(),
        Some("supervisor-model")
    );
    assert_eq!(
        new.plan.role_models[&AgentRole::Supervisor]
            .reasoning_effort
            .as_deref(),
        Some("xhigh")
    );
    assert_eq!(new.plan.role_models.len(), 4);
    assert_eq!(
        new.plan.role_models[&AgentRole::ChildOrchestrator]
            .model
            .as_deref(),
        Some("planner-model")
    );
    assert_eq!(
        new.plan.role_models[&AgentRole::ChildOrchestrator]
            .reasoning_effort
            .as_deref(),
        Some("high")
    );
    let normalized = supervisor_plan_value(
        &new.plan,
        &new.consultant,
        &new.assignment_metadata,
        &new.plan_metadata,
    )
    .expect("serialize new plan");
    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized new plan"),
    )
    .expect("reparse normalized new plan");
    assert_eq!(reparsed, new);

    let mut empty_model = new.plan.clone();
    empty_model
        .role_models
        .get_mut(&AgentRole::Worker)
        .expect("worker selection")
        .model = Some("  ".to_string());
    assert!(validate_legacy_supervisor_plan(empty_model)
        .expect_err("empty present model must fail")
        .to_string()
        .contains("role_models.worker.model cannot be empty"));

    let mut invalid_pricing = new.plan;
    invalid_pricing.model_pricing.insert(
        "bad-model".to_string(),
        ModelPricing {
            input_usd_per_million_tokens: f64::INFINITY,
            output_usd_per_million_tokens: 1.0,
        },
    );
    assert!(validate_legacy_supervisor_plan(invalid_pricing)
        .expect_err("non-finite pricing must fail")
        .to_string()
        .contains("finite, non-negative"));
}

#[test]
fn recursive_supervisor_plan_flattens_and_preserves_schedule_on_round_trip() {
    let source = json!({
        "version": 1,
        "task": "recursive plan",
        "max_depth": 3,
        "max_child_assignments": 2,
        "spec_fragment_ids": ["SPEC-root", "SPEC-child", "SPEC-gap"],
        "assignments": [{
            "id": "root-child",
            "assigned_paths": ["src/root.rs"],
            "spec_fragment_ids": ["SPEC-root"],
            "worker_assignments": [],
            "child_assignments": [{
                "id": "nested-child",
                "assigned_paths": ["src/nested.rs"],
                "spec_fragment_ids": ["SPEC-child"],
                "worker_assignments": []
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&source).expect("serialize recursive source"),
    )
    .expect("parse recursive plan");
    assert_eq!(
        loaded
            .plan
            .assignments
            .iter()
            .map(|assignment| assignment.id.as_str())
            .collect::<Vec<_>>(),
        vec!["root-child", "nested-child"]
    );
    assert_eq!(
        loaded.plan_metadata.assignment_schedule,
        vec![
            AssignmentScheduleEntry {
                assignment_id: "root-child".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "nested-child".to_string(),
                parent_assignment_id: Some("root-child".to_string()),
                depth: 3,
                flattened_index: 1,
            },
        ]
    );
    assert_eq!(
        loaded.plan_metadata.coverage_gaps,
        vec![SupervisorCoverageGap {
            kind: CoverageGapKind::UnassignedSpecFragment,
            spec_fragment_id: Some("SPEC-gap".to_string()),
            assignment_id: None,
            message: "spec fragment 'SPEC-gap' is not mapped to an assignment".to_string(),
        }]
    );

    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize recursive plan");
    assert_eq!(
        normalized["assignments"]
            .as_array()
            .expect("normalized assignments")
            .len(),
        2
    );
    assert!(normalized["assignments"][0]
        .get("child_assignments")
        .is_none());
    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized plan"),
    )
    .expect("reparse normalized recursive plan");
    assert_eq!(reparsed, loaded);
}

#[test]
fn goal_spec_planning_emits_nested_workstream_hierarchies_with_workers_and_gaps() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    Repository::init(repo).expect("initialize repository");
    fs::create_dir_all(repo.join("src")).expect("create src");
    fs::write(repo.join("src/alpha.rs"), "pub struct AlphaHandler;\n").expect("write alpha");
    fs::write(repo.join("src/beta.rs"), "pub struct BetaHandler;\n").expect("write beta");

    let document = supervisor_plan_document_from_goal_spec(
        repo,
        "Implement the requested changes.",
        "- Update AlphaHandler.\n- Update BetaHandler.\n- Explain the unmatched frobnicator.",
    )
    .expect("plan goal/spec");
    let assignments = document["assignments"]
        .as_array()
        .expect("assignments array");
    assert_eq!(document["max_depth"], 3);
    assert_eq!(document["max_child_assignments"], 4);
    assert_eq!(assignments.len(), 4);
    assert_eq!(assignments[0]["id"], "assignment-001-planning");
    assert_eq!(assignments[0]["assigned_paths"], json!(["src/alpha.rs"]));
    assert_eq!(
        assignments[0]["semantic_symbols"],
        json!(["crate::alpha::AlphaHandler"])
    );
    assert!(assignments[0]["worker_assignments"]
        .as_array()
        .expect("planning workers")
        .is_empty());
    assert!(assignments[0].get("spec_fragment_ids").is_none());
    assert!(assignments[0]["task"]
        .as_str()
        .expect("planning task")
        .contains("Read-only planning gate"));
    assert_eq!(assignments[1]["id"], "assignment-001");
    assert_eq!(assignments[1]["assigned_paths"], json!(["src/alpha.rs"]));
    assert_eq!(assignments[1]["spec_fragment_ids"], json!(["fragment-002"]));
    assert_eq!(
        assignments[1]["worker_assignments"][0]["id"],
        "assignment-001-worker"
    );
    assert_eq!(
        assignments[1]["worker_assignments"][0]["task"],
        "Update AlphaHandler."
    );
    assert_eq!(assignments[2]["id"], "assignment-002-planning");
    assert_eq!(assignments[2]["assigned_paths"], json!(["src/beta.rs"]));
    assert!(assignments[2]["worker_assignments"]
        .as_array()
        .expect("planning workers")
        .is_empty());
    assert_eq!(assignments[3]["id"], "assignment-002");
    assert_eq!(assignments[3]["assigned_paths"], json!(["src/beta.rs"]));
    assert_eq!(assignments[3]["spec_fragment_ids"], json!(["fragment-003"]));
    assert_eq!(
        document["assignment_schedule"],
        json!([
            {
                "assignment_id": "assignment-001-planning",
                "depth": 2,
                "flattened_index": 0
            },
            {
                "assignment_id": "assignment-001",
                "parent_assignment_id": "assignment-001-planning",
                "depth": 3,
                "flattened_index": 1
            },
            {
                "assignment_id": "assignment-002-planning",
                "depth": 2,
                "flattened_index": 2
            },
            {
                "assignment_id": "assignment-002",
                "parent_assignment_id": "assignment-002-planning",
                "depth": 3,
                "flattened_index": 3
            }
        ])
    );
    assert_eq!(
        document["coverage_gaps"]
            .as_array()
            .expect("coverage gaps")
            .iter()
            .map(|gap| gap["spec_fragment_id"].as_str().expect("fragment id"))
            .collect::<Vec<_>>(),
        vec!["fragment-001", "fragment-004"]
    );

    let repeated = supervisor_plan_document_from_goal_spec(
        repo,
        "Implement the requested changes.",
        "- Update AlphaHandler.\n- Update BetaHandler.\n- Explain the unmatched frobnicator.",
    )
    .expect("repeat goal/spec planning");
    assert_eq!(repeated, document);

    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&document).expect("serialize generated plan"),
    )
    .expect("reparse generated plan");
    let renormalized = supervisor_plan_value(
        &reparsed.plan,
        &reparsed.consultant,
        &reparsed.assignment_metadata,
        &reparsed.plan_metadata,
    )
    .expect("renormalize generated plan");
    assert_eq!(renormalized, document);
}

#[test]
fn plain_text_task_without_actionable_scope_returns_guidance() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# fixture\n").expect("write readme");
    let task_file = temp.path().join("task.txt");
    fs::write(&task_file, "Explain the unmatched frobnicator.\n").expect("write task");

    let error = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect_err("scope-free task must fail")
        .to_string();
    assert!(error.contains("produced no actionable workstreams"));
    assert!(error.contains("repository path, Rust module, or Rust symbol"));
}

#[test]
fn supervisor_depth_bounds_are_configurable_and_enforced() {
    let recursive = |max_depth| {
        json!({
            "version": 1,
            "task": "depth bounds",
            "max_depth": max_depth,
            "max_child_assignments": 2,
            "assignments": [{
                "id": "root-child",
                "assigned_paths": ["src/root.rs"],
                "child_assignments": [{
                    "id": "nested-child",
                    "assigned_paths": ["src/nested.rs"]
                }]
            }]
        })
    };
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&recursive(3)).expect("serialize depth-three plan")
    )
    .is_ok());
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&recursive(2)).expect("serialize shallow plan")
    )
    .expect_err("nested assignment must exceed max depth two")
    .to_string()
    .contains("depth 3"));

    for invalid_depth in [1, MAX_SUPERVISOR_DEPTH.saturating_add(1)] {
        let source = json!({
            "version": 1,
            "task": "invalid depth",
            "max_depth": invalid_depth,
            "max_child_assignments": 1,
            "assignments": [{
                "id": "child-a",
                "assigned_paths": ["README.md"]
            }]
        });
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize invalid depth")
        )
        .is_err());
    }
}

#[test]
fn supervisor_represents_and_validates_assignment_trees_to_arbitrary_configured_depth() {
    let source = json!({
        "version": 1,
        "task": "deep recursive plan",
        "max_depth": 5,
        "max_child_assignments": 4,
        "assignments": [{
            "id": "depth-2",
            "assigned_paths": ["src/depth_2.rs"],
            "child_assignments": [{
                "id": "depth-3",
                "assigned_paths": ["src/depth_3.rs"],
                "child_assignments": [{
                    "id": "depth-4",
                    "assigned_paths": ["src/depth_4.rs"],
                    "child_assignments": [{
                        "id": "depth-5",
                        "assigned_paths": ["src/depth_5.rs"]
                    }]
                }]
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&source).expect("serialize deep plan"),
    )
    .expect("parse deep plan");
    assert_eq!(
        loaded
            .plan_metadata
            .assignment_schedule
            .iter()
            .map(|entry| {
                (
                    entry.assignment_id.as_str(),
                    entry.parent_assignment_id.as_deref(),
                    entry.depth,
                    entry.flattened_index,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("depth-2", None, 2, 0),
            ("depth-3", Some("depth-2"), 3, 1),
            ("depth-4", Some("depth-3"), 4, 2),
            ("depth-5", Some("depth-4"), 5, 3),
        ]
    );

    let mut too_shallow = source;
    too_shallow["max_depth"] = json!(4);
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&too_shallow).expect("serialize shallow bound")
    )
    .expect_err("deepest assignment must exceed configured bound")
    .to_string()
    .contains("depth 5"));
}

#[test]
fn supervisor_allows_overlapping_scopes_only_across_strict_lineage() {
    let ancestor_overlap = json!({
        "version": 1,
        "task": "lineage overlap",
        "max_depth": 3,
        "max_child_assignments": 2,
        "assignments": [{
            "id": "planning-root",
            "assigned_paths": ["src/shared.rs"],
            "semantic_symbols": ["crate::shared::Shared"],
            "child_assignments": [{
                "id": "execution-child",
                "assigned_paths": ["src/shared.rs"],
                "semantic_symbols": ["crate::shared::Shared"]
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&ancestor_overlap).expect("serialize lineage overlap"),
    )
    .expect("strict ancestor overlap is dependency-gated");
    assert!(schedule_entries_share_strict_lineage(
        &loaded.plan_metadata.assignment_schedule,
        0,
        1
    ));

    let sibling_overlap = json!({
        "version": 1,
        "task": "sibling overlap",
        "max_depth": 3,
        "max_child_assignments": 3,
        "assignments": [{
            "id": "planning-root",
            "assigned_paths": ["src"],
            "child_assignments": [
                {
                    "id": "execution-a",
                    "assigned_paths": ["src/shared.rs"]
                },
                {
                    "id": "execution-b",
                    "assigned_paths": ["src/shared.rs"]
                }
            ]
        }]
    });
    let error = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&sibling_overlap).expect("serialize sibling overlap"),
    )
    .expect_err("sibling overlap remains concurrent and must be rejected")
    .to_string();
    assert!(error.contains("assignments 'execution-a'"));
    assert!(error.contains("'execution-b'"));
    assert!(error.contains("overlap after normalization"));
}

#[test]
fn hierarchy_admission_waits_for_accepted_successful_parent() {
    let assignments = [
        injected_named_assignment("planning-root", "src/shared.rs"),
        injected_named_assignment("execution-child", "src/shared.rs"),
    ];
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "planning-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "execution-child".to_string(),
            parent_assignment_id: Some("planning-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
    ];
    let mut outcomes = vec![None, None];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)
            .expect("classify waiting execution child"),
        AssignmentAdmissionState::Waiting
    );

    outcomes[0] = Some(AssignmentExecutionOutcome {
        report: Some(injected_child_report(&assignments[0])),
        ..AssignmentExecutionOutcome::default()
    });
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)
            .expect("classify ready execution child"),
        AssignmentAdmissionState::Ready
    );
    assert!(assignment_outcome_succeeded(
        outcomes[0].as_ref().expect("successful parent outcome")
    ));
}

#[test]
fn failed_parent_suppresses_descendants_but_not_independent_roots() {
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "failed-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "suppressed-child".to_string(),
            parent_assignment_id: Some("failed-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
        AssignmentScheduleEntry {
            assignment_id: "suppressed-grandchild".to_string(),
            parent_assignment_id: Some("suppressed-child".to_string()),
            depth: 4,
            flattened_index: 2,
        },
        AssignmentScheduleEntry {
            assignment_id: "independent-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 3,
        },
    ];
    let mut outcomes = vec![
        Some(AssignmentExecutionOutcome {
            assignment_failed: true,
            ..AssignmentExecutionOutcome::default()
        }),
        None,
        None,
        None,
    ];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes).expect("classify failed-parent child"),
        AssignmentAdmissionState::Suppressed {
            parent_assignment_id: "failed-root".to_string()
        }
    );
    assert_eq!(
        assignment_admission_state(2, &schedule, &outcomes).expect("classify waiting grandchild"),
        AssignmentAdmissionState::Waiting
    );
    assert_eq!(
        assignment_admission_state(3, &schedule, &outcomes).expect("classify independent root"),
        AssignmentAdmissionState::Ready
    );

    let suppressed = injected_named_assignment("suppressed-child", "src/suppressed.rs");
    outcomes[1] = Some(suppressed_descendant_outcome(&suppressed, "failed-root"));
    assert_eq!(
        assignment_admission_state(2, &schedule, &outcomes)
            .expect("classify transitively suppressed grandchild"),
        AssignmentAdmissionState::Suppressed {
            parent_assignment_id: "suppressed-child".to_string()
        }
    );
}

#[test]
fn same_lineage_semantic_preview_excludes_ancestor_but_retains_independent_root() {
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "planning-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "execution-child".to_string(),
            parent_assignment_id: Some("planning-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
        AssignmentScheduleEntry {
            assignment_id: "independent-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 2,
        },
    ];
    let intent = |token, agent_id: &str| SemanticIntent {
        token: crate::semantic_coord::SemanticIntentToken::from_u64(token),
        agent_id: agent_id.to_string(),
        paths: vec![PathBuf::from("src/shared.rs")],
        symbols: Vec::new(),
        modules: vec!["crate::shared".to_string()],
        impacted_files: Vec::new(),
        task_digest: None,
        task_excerpt: None,
        notes: Vec::new(),
        warnings: Vec::new(),
    };
    let planned = vec![
        (0, intent(1, "planning-root")),
        (2, intent(2, "independent-root")),
    ];

    let relevant = semantic_preview_intents_for_assignment(1, &schedule, &planned);
    assert_eq!(
        relevant
            .iter()
            .map(|intent| intent.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["independent-root"]
    );
}

#[test]
fn supervisor_rejects_normalized_path_symbol_and_module_collisions() {
    let collision_error = |left: Value, right: Value| {
        let source = json!({
            "version": 1,
            "task": "collision",
            "max_depth": 2,
            "max_child_assignments": 2,
            "assignments": [left, right]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize collision plan"),
        )
        .expect_err("collision must fail before launch")
        .to_string()
    };
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/generated/../lib.rs"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/lib.rs"]
        }),
    )
    .contains("path 'src/lib.rs'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/nested/lib.rs"]
        }),
    )
    .contains("overlap after normalization"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_symbols": [" crate :: SharedSymbol "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::SharedSymbol"]
        }),
    )
    .contains("semantic symbol 'crate::SharedSymbol'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate :: shared"]
        }),
    )
    .contains("semantic module 'crate::shared'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": ["crate::shared"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate::shared::nested"]
        }),
    )
    .contains("semantic module hierarchy 'crate::shared' and 'crate::shared::nested'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": ["crate::shared"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::shared::SharedSymbol"]
        }),
    )
    .contains("semantic module 'crate::shared' and symbol 'crate::shared::SharedSymbol'"));
}

#[test]
fn supervisor_rejects_normalized_worker_semantic_collisions() {
    let worker_collision_error = |first: Value, second: Value| {
        let source = json!({
            "version": 1,
            "task": "worker collision",
            "max_depth": 2,
            "max_child_assignments": 1,
            "assignments": [{
                "id": "child-a",
                "assigned_paths": ["src"],
                "worker_assignments": [first, second]
            }]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize worker collision"),
        )
        .expect_err("worker collision must fail")
        .to_string()
    };
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate :: shared"]
        }),
    )
    .contains("workers 'worker-a' and 'worker-b'"));
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_symbols": [" crate :: SharedSymbol "]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::SharedSymbol"]
        }),
    )
    .contains("semantic symbol 'crate::SharedSymbol'"));
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/generated/../lib.rs"]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/lib.rs"]
        }),
    )
    .contains("overlaps worker"));
}

#[test]
fn supervisor_rejects_cross_assignment_worker_semantic_collisions() {
    let collision_error = |left: Value, right: Value| {
        let source = json!({
            "version": 1,
            "task": "cross assignment worker collision",
            "max_depth": 2,
            "max_child_assignments": 2,
            "assignments": [left, right]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize cross assignment collision"),
        )
        .expect_err("cross assignment worker semantics must fail")
        .to_string()
    };
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a"],
            "worker_assignments": [{
                "id": "worker-a",
                "assigned_paths": ["src/a/worker.rs"],
                "semantic_symbols": [" crate :: SharedSymbol "]
            }]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b"],
            "worker_assignments": [{
                "id": "worker-b",
                "assigned_paths": ["src/b/worker.rs"],
                "semantic_symbols": ["crate::SharedSymbol"]
            }]
        }),
    )
    .contains("worker 'worker-a' under assignment 'child-a' and worker 'worker-b'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b"],
            "worker_assignments": [{
                "id": "worker-b",
                "assigned_paths": ["src/b/worker.rs"],
                "semantic_modules": ["crate :: shared"]
            }]
        }),
    )
    .contains("assignment 'child-a' and worker 'worker-b'"));
}

#[test]
fn supervisor_traceability_reports_missing_changes_and_diff_binding() {
    let plan = injected_multi_plan(
        vec![
            injected_named_assignment("child-a", "src/a.rs"),
            injected_named_assignment("child-b", "src/b.rs"),
        ],
        0,
    );
    let metadata = SupervisorPlanMetadata {
        spec_fragment_ids: vec!["SPEC-a".to_string(), "SPEC-b".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([
            ("child-a".to_string(), vec!["SPEC-a".to_string()]),
            ("child-b".to_string(), vec!["SPEC-b".to_string()]),
        ]),
        assignment_schedule: vec![
            AssignmentScheduleEntry {
                assignment_id: "child-a".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "child-b".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 1,
            },
        ],
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
    };
    let mut report_a = injected_child_report(&plan.assignments[0]);
    report_a.files_changed = vec![PathBuf::from("src/a.rs")];
    let mut report_b = injected_child_report(&plan.assignments[1]);
    report_b.files_changed.clear();
    let (traceability, gaps) = supervisor_assignment_traceability(
        &plan,
        &metadata,
        &[report_a, report_b],
        &BTreeMap::new(),
    );
    assert_eq!(traceability.len(), 2);
    assert_eq!(
        traceability[0].produced_changed_paths,
        vec![PathBuf::from("src/a.rs")]
    );
    assert!(traceability[0].produced_diff_binding.is_none());
    assert!(gaps.iter().any(|gap| {
        gap.kind == CoverageGapKind::MissingDiffBinding
            && gap.assignment_id.as_deref() == Some("child-a")
            && gap.spec_fragment_id.as_deref() == Some("SPEC-a")
    }));
    assert!(gaps.iter().any(|gap| {
        gap.kind == CoverageGapKind::NoProducedChanges
            && gap.assignment_id.as_deref() == Some("child-b")
            && gap.spec_fragment_id.as_deref() == Some("SPEC-b")
    }));
}

#[test]
fn supervisor_traceability_binds_ordinary_success_to_observed_paths_and_diff() {
    let plan = injected_multi_plan(vec![injected_named_assignment("child-a", "src/a.rs")], 0);
    let metadata = SupervisorPlanMetadata {
        spec_fragment_ids: vec!["SPEC-a".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([(
            "child-a".to_string(),
            vec!["SPEC-a".to_string()],
        )]),
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: "child-a".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        }],
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
    };
    let mut report = injected_child_report(&plan.assignments[0]);
    report.files_changed = vec![PathBuf::from("src/a.rs")];
    let binding = CandidateValidationBinding {
        version: 1,
        agent_id: "child-a".to_string(),
        primary_head: Some("1111111111111111111111111111111111111111".to_string()),
        agent_head: Some("2222222222222222222222222222222222222222".to_string()),
        merge_base: Some("1111111111111111111111111111111111111111".to_string()),
        diff_oid: "3333333333333333333333333333333333333333".to_string(),
    };
    let inspections = BTreeMap::from([(
        "child-a".to_string(),
        SupervisorCandidateInspection {
            binding: binding.clone(),
            changed_paths: vec![PathBuf::from("src/a.rs")],
        },
    )]);

    let (traceability, gaps) =
        supervisor_assignment_traceability(&plan, &metadata, &[report], &inspections);

    assert!(gaps.is_empty());
    assert_eq!(traceability.len(), 1);
    assert_eq!(traceability[0].spec_fragment_ids, vec!["SPEC-a"]);
    assert_eq!(
        traceability[0].produced_changed_paths,
        vec![PathBuf::from("src/a.rs")]
    );
    assert_eq!(traceability[0].produced_diff_binding, Some(binding));
    assert_eq!(traceability[0].report_status, Some(ReviewStatus::Succeeded));
}

#[test]
fn admitted_nested_assignment_retains_ordinary_pipeline_and_acceptance_evidence() {
    let planning = injected_named_assignment("planning-root", "src/shared.rs");
    let mut execution = injected_named_assignment("execution-child", "src/shared.rs");
    execution.worker_assignments.push(WorkerAssignment {
        id: "execution-child-worker".to_string(),
        role: AgentRole::Worker,
        assigned_paths: execution.assigned_paths.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: Some("implement the nested execution task".to_string()),
        environment_requirements: Vec::new(),
        report_path: None,
    });
    let mut plan = injected_multi_plan(vec![planning.clone(), execution.clone()], 0);
    plan.max_depth = 3;
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: planning.id.clone(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: execution.id.clone(),
            parent_assignment_id: Some(planning.id.clone()),
            depth: 3,
            flattened_index: 1,
        },
    ];
    let outcomes = vec![
        Some(AssignmentExecutionOutcome {
            report: Some(injected_child_report(&planning)),
            ..AssignmentExecutionOutcome::default()
        }),
        None,
    ];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes).expect("admit execution child"),
        AssignmentAdmissionState::Ready
    );
    assert!(release_assignment_resources_after_completion(
        &plan, &schedule, 1
    ));

    let worktree = WorktreeRecord {
        name: execution.id.clone(),
        path: PathBuf::from("/tmp/maco-nested-execution"),
        branch: "maco/execution-child".to_string(),
    };
    let claim = PathClaim {
        token: ClaimToken::from_u64(41),
        agent_id: execution.id.clone(),
        paths: execution.assigned_paths.clone(),
    };
    let prompt = child_orchestrator_prompt(ChildOrchestratorPromptContext {
        plan: &plan,
        assignment: &execution,
        run_dir: Path::new("/tmp/maco-run"),
        worktree: &worktree,
        report_path: Path::new("/tmp/maco-run/incoming/execution-child.json"),
        schema_path: Path::new("/tmp/maco-run/schemas/orchestrator-review-report.schema.json"),
        worker_schema_path: Path::new("/tmp/maco-run/schemas/worker-report.schema.json"),
        auditor_schema_path: Path::new("/tmp/maco-run/schemas/auditor-report.schema.json"),
        consultant: &SupervisorConsultantPlan::default(),
        claim_context: ChildPromptClaimContext {
            claim: &claim,
            semantic_intent_token: Some(43),
        },
    })
    .expect("render ordinary nested execution prompt");
    assert!(prompt.contains("Path claim token: 41"));
    assert!(prompt.contains("Semantic intent token: 43"));
    assert!(prompt.contains("/tmp/maco-run/incoming/worker-journals/execution-child-worker.jsonl"));
    assert!(prompt.contains("Return your OrchestratorReviewReport JSON"));
    assert!(prompt.contains("Review auditor prompt template:"));

    let mut accepted_report = injected_child_report(&execution);
    accepted_report.files_changed = vec![PathBuf::from("src/shared.rs")];
    let accepted_audit = injected_auditor_report(&execution, &accepted_report);
    accepted_report.audit_reports.push(accepted_audit);
    let binding = CandidateValidationBinding {
        version: 1,
        agent_id: execution.id.clone(),
        primary_head: Some("1111111111111111111111111111111111111111".to_string()),
        agent_head: Some("2222222222222222222222222222222222222222".to_string()),
        merge_base: Some("1111111111111111111111111111111111111111".to_string()),
        diff_oid: "3333333333333333333333333333333333333333".to_string(),
    };
    let metadata = SupervisorPlanMetadata {
        spec_fragment_ids: vec!["SPEC-execution".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([(
            execution.id.clone(),
            vec!["SPEC-execution".to_string()],
        )]),
        assignment_schedule: schedule,
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
    };
    let inspections = BTreeMap::from([(
        execution.id.clone(),
        SupervisorCandidateInspection {
            binding: binding.clone(),
            changed_paths: vec![PathBuf::from("src/shared.rs")],
        },
    )]);
    let (traceability, gaps) =
        supervisor_assignment_traceability(&plan, &metadata, &[accepted_report], &inspections);
    assert!(gaps.iter().any(|gap| {
        gap.assignment_id.as_deref() == Some("planning-root")
            && gap.kind == CoverageGapKind::MissingAssignmentReport
    }));
    let execution_trace = traceability
        .iter()
        .find(|entry| entry.assignment_id == execution.id)
        .expect("execution traceability entry");
    assert_eq!(
        execution_trace.parent_assignment_id.as_deref(),
        Some("planning-root")
    );
    assert_eq!(execution_trace.produced_diff_binding, Some(binding));
    assert_eq!(execution_trace.report_status, Some(ReviewStatus::Succeeded));
}

#[test]
fn role_selection_produces_distinct_launched_role_argv() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models = BTreeMap::from([
        (
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("planner-model".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Worker,
            RoleModelSelection {
                model: Some("worker-model".to_string()),
                reasoning_effort: Some("low".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Auditor,
            RoleModelSelection {
                model: Some("auditor-model".to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
    ]);
    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let catalog =
        injected_codex_runtime_catalog(&["planner-model", "worker-model", "auditor-model"]);
    let child = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("runtime catalog contains the configured child selection");
    let auditor = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::Auditor,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("runtime catalog contains the configured auditor selection");
    let child_argv = crate::external_agent::command_argv(&child)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let auditor_argv = crate::external_agent::command_argv(&auditor)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(child_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", "planner-model"]));
    assert!(child_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"high\""] }));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", "auditor-model"]));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
    assert!(!child_argv
        .iter()
        .any(|argument| argument.contains("worker-model")));
    assert_ne!(child_argv, auditor_argv);
}

#[test]
fn no_override_selects_named_provisional_hybrid_profile_in_launched_argv() {
    let plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let profile = plan.effective_role_economics_profile();
    assert_eq!(profile.name, PROVISIONAL_DEFAULT_HYBRID_PROFILE_NAME);
    assert_eq!(
        profile.evidence,
        PROVISIONAL_DEFAULT_HYBRID_PROFILE_EVIDENCE
    );
    assert!(profile.evidence_notice.contains("production-ineligible"));
    assert!(!profile.production_eligible);
    assert_eq!(profile.model_availability, RoleModelAvailability::Unknown);
    assert!(profile.overridden_roles.is_empty());
    assert_eq!(profile.role_models.len(), 5);
    assert_eq!(
        profile.role_models[&AgentRole::ChildOrchestrator]
            .reasoning_effort
            .as_deref(),
        Some("xhigh")
    );
    assert_eq!(
        profile.role_models[&AgentRole::Worker]
            .reasoning_effort
            .as_deref(),
        Some("medium")
    );
    assert_eq!(
        profile.role_models[&AgentRole::GateClassifier].unavailable_model_fallback,
        UnavailableModelFallback::LocalDeterministicFake
    );
    assert_eq!(
        profile.role_models[&AgentRole::Auditor].unavailable_model_fallback,
        UnavailableModelFallback::RuntimeDefault
    );

    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let catalog = injected_codex_runtime_catalog(&[DEFAULT_PROFILE_MODEL]);
    let runtime_profile = plan.effective_role_economics_profile_for_runtime(&catalog);
    assert_eq!(
        runtime_profile.model_availability,
        RoleModelAvailability::Available
    );
    let child = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("apply no-override child selection");
    let child_argv = crate::external_agent::app_server_command_argv(&child)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        child_argv
            .windows(2)
            .any(|arguments| arguments == ["-c", "model=\"gpt-5.6-sol\""]),
        "writable child app-server argv did not select the provisional model: {child_argv:?}"
    );
    assert!(child_argv
        .windows(2)
        .any(|arguments| arguments == ["-c", "model_reasoning_effort=\"xhigh\""]));

    let auditor = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::Auditor,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("apply no-override auditor selection");
    let auditor_argv = crate::external_agent::command_argv(&auditor)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", DEFAULT_PROFILE_MODEL]));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-c", "model_reasoning_effort=\"xhigh\""]));
}

#[test]
fn gate_classifier_override_and_unavailable_fallback_are_independent() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models.insert(
        AgentRole::GateClassifier,
        RoleModelSelection {
            model: Some("classifier-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let profile = plan.effective_role_economics_profile();
    assert_eq!(
        profile.role_models[&AgentRole::GateClassifier]
            .model
            .as_deref(),
        Some("classifier-model")
    );
    assert_eq!(
        profile.role_models[&AgentRole::Auditor].model.as_deref(),
        Some(DEFAULT_PROFILE_MODEL)
    );
    assert_eq!(profile.overridden_roles, vec![AgentRole::GateClassifier]);

    let fallback = profile.role_models[&AgentRole::GateClassifier]
        .resolve_for_availability(RoleModelAvailability::Unavailable, SupervisorRuntime::Codex)
        .expect("runtime-default fallback");
    assert!(fallback.model.is_none());
    assert_eq!(fallback.reasoning_effort.as_deref(), Some("high"));
    let local_fake = provisional_default_role_model_selection(AgentRole::GateClassifier)
        .resolve_for_availability(RoleModelAvailability::Unavailable, SupervisorRuntime::Fake)
        .expect("local fake fallback");
    assert_eq!(local_fake, RoleModelSelection::default());
    let unknown_local_fake = provisional_default_role_model_selection(AgentRole::GateClassifier)
        .resolve_for_availability(RoleModelAvailability::Unknown, SupervisorRuntime::Fake)
        .expect("known fake runtime uses local deterministic fallback");
    assert_eq!(unknown_local_fake, RoleModelSelection::default());
    assert!(
        provisional_default_role_model_selection(AgentRole::GateClassifier)
            .resolve_for_availability(RoleModelAvailability::Unavailable, SupervisorRuntime::Codex,)
            .expect_err("local fake cannot replace a Codex model")
            .to_string()
            .contains("valid only for the fake runtime")
    );
}

#[test]
fn unavailable_model_fallback_is_a_runtime_aware_command_contract() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("preferred-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let missing_catalog = injected_codex_runtime_catalog(&["different-model"]);

    let runtime_default = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect("known unavailable model uses the configured runtime default");
    assert_eq!(runtime_default.model, None);
    assert_eq!(runtime_default.reasoning_effort.as_deref(), Some("high"));

    plan.role_models
        .get_mut(&AgentRole::ChildOrchestrator)
        .expect("child selection")
        .unavailable_model_fallback = UnavailableModelFallback::FailClosed;
    let fail_closed_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("fail_closed rejects runtime-advertised unavailability");
    assert!(format!("{fail_closed_error:#}").contains("fallback is fail_closed"));

    plan.role_models
        .get_mut(&AgentRole::ChildOrchestrator)
        .expect("child selection")
        .unavailable_model_fallback = UnavailableModelFallback::LocalDeterministicFake;
    let local_fake = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Fake,
        &RuntimeModelCatalog::LocalDeterministicFake,
    )
    .expect("the fake runtime may use its deterministic local fallback");
    assert_eq!(local_fake.model, None);
    let invalid_runtime_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("known-unavailable Codex cannot use the deterministic local fallback");
    assert!(format!("{invalid_runtime_error:#}").contains("valid only for the fake runtime"));
}

#[test]
fn known_unavailable_child_runtime_default_reaches_production_app_server_argv_before_dispatch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("unavailable-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    plan.role_models.insert(
        AgentRole::Auditor,
        RoleModelSelection {
            model: Some("available-auditor-model".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let options = injected_options(
        &repo_path,
        temp.path(),
        "known-unavailable-child-runtime-default",
    );
    let catalog = injected_codex_runtime_catalog(&["available-auditor-model"]);
    let mut child_seen = false;
    let mut auditor_seen = false;
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            auditor_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            let argv = crate::external_agent::command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(argv
                .windows(2)
                .any(|arguments| arguments == ["-m", "available-auditor-model"]));
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            child_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadWrite);
            assert!(command.model.is_none());
            let argv = crate::external_agent::app_server_command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(
                !argv.iter().any(|argument| argument.starts_with("model=")),
                "known-unavailable child model remained pinned in app-server argv: {argv:?}"
            );
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"high\""] }));
            write_injected_assignment_report(command, &assignment);
        }
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("run production command path with unavailable child model");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert!(child_seen);
    assert!(auditor_seen);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
    );
}

#[test]
fn known_unavailable_auditor_runtime_default_reaches_production_exec_argv_before_dispatch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("available-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    plan.role_models.insert(
        AgentRole::Auditor,
        RoleModelSelection {
            model: Some("unavailable-auditor-model".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let options = injected_options(
        &repo_path,
        temp.path(),
        "known-unavailable-auditor-runtime-default",
    );
    let catalog = injected_codex_runtime_catalog(&["available-child-model"]);
    let mut child_seen = false;
    let mut auditor_seen = false;
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            auditor_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            assert!(command.model.is_none());
            let argv = crate::external_agent::command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(
                !argv.iter().any(|argument| argument == "-m"),
                "known-unavailable auditor model remained pinned in exec argv: {argv:?}"
            );
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            child_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadWrite);
            let argv = crate::external_agent::app_server_command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model=\"available-child-model\""] }));
            write_injected_assignment_report(command, &assignment);
        }
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("run production command path with unavailable auditor model");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert!(child_seen);
    assert!(auditor_seen);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
    );
}

#[test]
fn known_unavailable_child_fail_closed_reaches_production_core_without_dispatch_or_scratch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("unavailable-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let run_id = "known-unavailable-child-fail-closed";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let catalog = injected_codex_runtime_catalog(&["different-model"]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("known-unavailable fail_closed selection must prevent dispatch")
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("fail_closed selection should produce a finalized rejection report");

    assert_eq!(invocations, 0);
    assert!(!report.success);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("fallback is fail_closed")));
    let run_root = repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id);
    let scratch_entries = fs::read_dir(&run_root)
        .expect("read finalized fail_closed artifact root")
        .map(|entry| {
            entry
                .expect("read fail_closed artifact entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("incoming") || name.starts_with("capture"))
        .collect::<Vec<_>>();
    assert!(
        scratch_entries.is_empty(),
        "fail_closed command construction leaked invocation scratch: {scratch_entries:?}"
    );
    assert!(run_root.join(ARTIFACT_FINALIZATION_MARKER).exists());
}

#[test]
fn local_deterministic_fake_fallback_reaches_shared_supervisor_core_without_external_dispatch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    for role in [AgentRole::ChildOrchestrator, AgentRole::Auditor] {
        plan.role_models.insert(
            role,
            RoleModelSelection {
                model: Some("codex-only-model".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::LocalDeterministicFake,
            },
        );
    }
    let mut options = injected_options(&repo_path, temp.path(), "local-fake-fallback-shared-core");
    options.runtime = SupervisorRuntime::Fake;
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("deterministic fake fallback must not invoke the external runner")
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(RuntimeModelCatalog::LocalDeterministicFake),
        &mut runner,
    )
    .expect("run deterministic fake fallback through the shared supervisor core");

    assert_eq!(invocations, 0);
    assert!(report.success, "unexpected fake-core failure: {report:#?}");
    assert!(!report.publishable);
    assert_eq!(report.commands_run.len(), 2);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
    );
}

#[test]
fn model_catalog_failure_fails_closed_before_any_production_dispatch() {
    let (temp, repo_path) = injected_repository();
    let plan = injected_plan(injected_assignment(true), 0);
    let options = injected_options(
        &repo_path,
        temp.path(),
        "model-catalog-failure-before-dispatch",
    );
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("catalog acquisition failure must prevent assignment dispatch")
    };

    let error = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Err(anyhow!("injected catalog acquisition failure")),
        &mut runner,
    )
    .expect_err("missing catalog must fail closed");

    assert_eq!(invocations, 0);
    assert!(format!("{error:#}").contains("runtime model availability could not be established"));
    assert!(format!("{error:#}").contains("injected catalog acquisition failure"));
}

#[test]
fn process_role_usage_aggregation_prices_children_and_auditors() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.model_pricing = BTreeMap::from([
        (
            "planner-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 2.0,
                output_usd_per_million_tokens: 8.0,
            },
        ),
        (
            "auditor-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 4.0,
            },
        ),
    ]);
    let samples = vec![
        RoleUsageSample {
            role: AgentRole::ChildOrchestrator,
            model: Some("planner-model".to_string()),
            usage: Usage {
                input_tokens: 1_000,
                output_tokens: 200,
                total_tokens: 1_200,
            },
        },
        RoleUsageSample {
            role: AgentRole::ChildOrchestrator,
            model: Some("planner-model".to_string()),
            usage: Usage {
                input_tokens: 500,
                output_tokens: 100,
                total_tokens: 600,
            },
        },
        RoleUsageSample {
            role: AgentRole::Auditor,
            model: Some("auditor-model".to_string()),
            usage: Usage {
                input_tokens: 500,
                output_tokens: 100,
                total_tokens: 600,
            },
        },
        RoleUsageSample {
            role: AgentRole::Auditor,
            model: Some("auditor-model".to_string()),
            usage: Usage {
                input_tokens: 250,
                output_tokens: 50,
                total_tokens: 300,
            },
        },
    ];
    let RoleUsageAggregation {
        reports: by_role,
        total_usage: total,
        total_cost_usd: cost,
    } = role_usage_report(&plan, samples.clone()).expect("aggregate process usage");
    assert_eq!(
        by_role[&AgentRole::ChildOrchestrator].usage,
        Some(Usage {
            input_tokens: 1_500,
            output_tokens: 300,
            total_tokens: 1_800,
        })
    );
    assert_eq!(
        total,
        Some(Usage {
            input_tokens: 2_250,
            output_tokens: 450,
            total_tokens: 2_700,
        })
    );
    let expected_cost = 0.0054 + 0.00135;
    assert!((cost.expect("fully priced total") - expected_cost).abs() < 1e-12);
    assert_eq!(
        by_role[&AgentRole::Worker].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(by_role[&AgentRole::Worker].usage.is_none());
    assert!(by_role[&AgentRole::Worker]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
    assert_eq!(
        by_role[&AgentRole::GateClassifier].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(by_role[&AgentRole::GateClassifier].usage.is_none());
    assert!(by_role[&AgentRole::GateClassifier]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("deterministic local broker")));
    let serialized_worker =
        serde_json::to_value(&by_role[&AgentRole::Worker]).expect("serialize worker marker");
    assert_eq!(serialized_worker["observation"], "not_process_observable");
    assert!(serialized_worker.get("usage").is_none());
    assert!(serialized_worker["unavailable_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
    assert_eq!(
        by_role[&AgentRole::Supervisor].observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(by_role[&AgentRole::Supervisor].usage, total);

    plan.model_pricing.clear();
    let RoleUsageAggregation {
        reports: unpriced,
        total_usage: unpriced_total,
        total_cost_usd: unpriced_cost,
    } = role_usage_report(&plan, samples).expect("aggregate unpriced process usage");
    assert_eq!(unpriced_total, total);
    assert!(unpriced.values().all(|report| report.cost_usd.is_none()));
    assert!(unpriced_cost.is_none());

    let mut incomplete = by_role;
    assert!(finalize_supervisor_cost(false, &mut incomplete, cost).is_none());
    assert!(incomplete[&AgentRole::Supervisor].cost_usd.is_none());
    assert!(incomplete[&AgentRole::Supervisor]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("at least one MACO-launched process")));
}

#[test]
fn empty_process_usage_has_no_synthetic_supervisor_or_worker_totals() {
    let plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let RoleUsageAggregation {
        reports: by_role,
        total_usage: total,
        total_cost_usd: cost,
    } = role_usage_report(&plan, Vec::new()).expect("empty process aggregation");
    assert!(total.is_none());
    assert!(cost.is_none());
    assert!(by_role[&AgentRole::Supervisor].usage.is_none());
    assert!(by_role[&AgentRole::Supervisor].cost_usd.is_none());
    assert!(by_role[&AgentRole::Worker].usage.is_none());
    assert_eq!(
        by_role[&AgentRole::Worker].observation,
        RoleUsageObservation::NotProcessObservable
    );
}

#[cfg(unix)]
#[test]
fn supervisor_input_loader_accepts_direct_regular_files_and_refuses_unsafe_inputs() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# test\n").expect("write readme");

    let plain = temp.path().join("task.txt");
    fs::write(&plain, "Update README.md.\n").expect("write plain task");
    let loaded =
        supervisor_plan_and_consultant_from_task_file(&repo, &plain).expect("load plain task");
    assert_eq!(loaded.plan.task, "Update README.md.\n");
    assert_eq!(
        loaded
            .plan
            .assignments
            .iter()
            .map(|assignment| assignment.id.as_str())
            .collect::<Vec<_>>(),
        vec!["assignment-001-planning", "assignment-001"]
    );
    assert_eq!(
        loaded.plan.assignments[0].assigned_paths,
        vec![PathBuf::from("README.md")]
    );
    assert!(loaded.plan.assignments[0].worker_assignments.is_empty());
    assert_eq!(
        loaded.plan.assignments[1].assigned_paths,
        vec![PathBuf::from("README.md")]
    );
    assert_eq!(loaded.plan.assignments[1].worker_assignments.len(), 1);
    assert_eq!(
        loaded.plan_metadata.assignment_schedule,
        vec![
            AssignmentScheduleEntry {
                assignment_id: "assignment-001-planning".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "assignment-001".to_string(),
                parent_assignment_id: Some("assignment-001-planning".to_string()),
                depth: 3,
                flattened_index: 1,
            },
        ]
    );

    let plan = temp.path().join("plan.json");
    fs::write(&plan, bounded_loader_plan_json()).expect("write plan");
    assert_eq!(
        load_supervisor_plan_file(&plan)
            .expect("load direct regular plan")
            .task,
        "bounded loader"
    );

    let invalid_utf8 = temp.path().join("invalid.json");
    fs::write(&invalid_utf8, [0xff, 0xfe]).expect("write invalid utf8");
    assert!(load_supervisor_plan_file(&invalid_utf8)
        .expect_err("invalid UTF-8 must fail")
        .to_string()
        .contains("not valid UTF-8"));

    let oversized = temp.path().join("oversized.json");
    fs::write(
        &oversized,
        vec![b' '; usize::try_from(MAX_SUPERVISOR_INPUT_BYTES).unwrap_or(usize::MAX) + 1],
    )
    .expect("write oversized input");
    assert!(load_supervisor_plan_file(&oversized).is_err());

    let symlinked = temp.path().join("symlinked.json");
    symlink(&plan, &symlinked).expect("create plan symlink");
    assert!(load_supervisor_plan_file(&symlinked).is_err());

    let hardlinked = temp.path().join("hardlinked.json");
    fs::hard_link(&plan, &hardlinked).expect("create plan hardlink");
    assert!(load_supervisor_plan_file(&hardlinked).is_err());

    let fifo = temp.path().join("plan.fifo");
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(load_supervisor_plan_file(&fifo).is_err());
}
