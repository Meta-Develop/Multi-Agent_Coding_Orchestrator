use super::*;

fn suitability_test_plan(assignments: serde_json::Value, max_depth: u8) -> serde_json::Value {
    json!({
        "version": SUPERVISOR_SCHEMA_VERSION,
        "task": "exercise the pre-claim assignment suitability gate",
        "max_depth": max_depth,
        "max_child_assignments": 4,
        "max_child_retries": 0,
        "max_gate_corrections": 0,
        "child_timeout_seconds": 60,
        "assignments": assignments
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ByteTreeEntry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

fn snapshot_byte_tree(root: &Path) -> Result<Option<BTreeMap<PathBuf, ByteTreeEntry>>> {
    fn collect(
        root: &Path,
        current: &Path,
        snapshot: &mut BTreeMap<PathBuf, ByteTreeEntry>,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(current)
            .with_context(|| format!("failed to inspect byte-tree entry {}", current.display()))?;
        let relative = current
            .strip_prefix(root)
            .with_context(|| {
                format!(
                    "byte-tree entry {} escaped root {}",
                    current.display(),
                    root.display()
                )
            })?
            .to_path_buf();
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            snapshot.insert(relative, ByteTreeEntry::Directory);
            let entries = fs::read_dir(current).with_context(|| {
                format!("failed to read byte-tree directory {}", current.display())
            })?;
            let mut entries = entries
                .collect::<std::io::Result<Vec<_>>>()
                .with_context(|| {
                    format!(
                        "failed to enumerate byte-tree directory {}",
                        current.display()
                    )
                })?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                collect(root, &entry.path(), snapshot)?;
            }
        } else if file_type.is_file() {
            snapshot.insert(
                relative,
                ByteTreeEntry::File(fs::read(current).with_context(|| {
                    format!("failed to read byte-tree file {}", current.display())
                })?),
            );
        } else if file_type.is_symlink() {
            snapshot.insert(
                relative,
                ByteTreeEntry::Symlink(fs::read_link(current).with_context(|| {
                    format!("failed to read byte-tree symlink {}", current.display())
                })?),
            );
        } else {
            snapshot.insert(relative, ByteTreeEntry::Other);
        }
        Ok(())
    }

    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect byte-tree root {}", root.display()))
        }
    }
    let mut snapshot = BTreeMap::new();
    collect(root, root, &mut snapshot)?;
    Ok(Some(snapshot))
}

fn snapshot_git_mutation_surfaces(
    common_dir: &Path,
) -> Result<BTreeMap<PathBuf, Option<BTreeMap<PathBuf, ByteTreeEntry>>>> {
    [
        "HEAD",
        "index",
        "config",
        "packed-refs",
        "refs",
        "logs",
        "worktrees",
    ]
    .into_iter()
    .map(|relative| {
        let relative = PathBuf::from(relative);
        let snapshot = snapshot_byte_tree(&common_dir.join(&relative))?;
        Ok((relative, snapshot))
    })
    .collect()
}

fn relative_regular_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    Ok(snapshot_byte_tree(root)?
        .with_context(|| format!("byte-tree root {} did not exist", root.display()))?
        .into_iter()
        .filter_map(|(path, entry)| matches!(entry, ByteTreeEntry::File(_)).then_some(path))
        .collect())
}

fn primary_worktree_byte_tree_without_git_or_refusal_artifacts(
    repo: &Path,
    run_id: &RunId,
) -> Result<BTreeMap<PathBuf, ByteTreeEntry>> {
    let run_relative = PathBuf::from(".maco/o2/runs").join(run_id.as_str());
    let excluded_exact = BTreeSet::from([
        PathBuf::from(".maco"),
        PathBuf::from(".maco/o2"),
        PathBuf::from(".maco/o2/runs"),
        PathBuf::from(".maco/o2/runs/.runs.lock"),
    ]);
    let snapshot = snapshot_byte_tree(repo)?
        .with_context(|| format!("primary worktree {} did not exist", repo.display()))?;
    Ok(snapshot
        .into_iter()
        .filter(|(path, _)| {
            !path.starts_with(".git")
                && !excluded_exact.contains(path)
                && !path.starts_with(&run_relative)
        })
        .collect())
}

#[test]
fn parked_assignment_is_classified_before_claim_worktree_checkpoint_or_dispatch() {
    let (temp, repo) = injected_repository();
    let plan_document = serde_json::to_string(&suitability_test_plan(
            json!([
                {
                    "id": "parked-parent",
                    "assigned_paths": ["README.md"],
                    "suitability": {
                        "classification": "unclear",
                        "bounded_scope": true,
                        "max_scope_paths": 8,
                        "verification_path": "supervisor_validation_floor",
                        "autonomous_completion": true,
                        "rationale": "operator decision is required before this assignment may claim resources"
                    },
                    "child_assignments": [{
                        "id": "suppressed-descendant",
                        "assigned_paths": ["README.md"]
                    }]
                },
                {
                    "id": "refused-duplicate",
                    "assigned_paths": ["docs/refused.md"],
                    "suitability": {
                        "classification": "duplicate",
                        "bounded_scope": true,
                        "max_scope_paths": 8,
                        "verification_path": "supervisor_validation_floor",
                        "autonomous_completion": true,
                        "rationale": "this assignment duplicates already planned work"
                    }
                }
            ]),
            3,
        ))
        .expect("serialize parked suitability plan");

    let git = crate::git_repository::open(&repo).expect("open injected Git repository");
    let authenticated_state_root = git.commondir().join("maco/state");
    let claims_root = authenticated_state_root.join("authenticated-claims-state-v1");
    let semantic_root = authenticated_state_root.join("authenticated-semantic-state-v1");
    let field_guide_root = authenticated_state_root.join("authenticated-field-guide-state-v1");
    let managed_registry_root = authenticated_state_root.join("authenticated-managed-worktrees-v1");
    let execution_state_lock_paths = [
        authenticated_state_root.join(".authenticated-claims.lock"),
        authenticated_state_root.join(".authenticated-semantic.lock"),
        authenticated_state_root.join(".authenticated-field-guide.lock"),
        authenticated_state_root.join(".authenticated-managed-worktrees.lock"),
    ];
    let claims_before = snapshot_byte_tree(&claims_root).expect("snapshot claims byte tree");
    let semantic_before =
        snapshot_byte_tree(&semantic_root).expect("snapshot semantic-intent byte tree");
    let field_guide_before =
        snapshot_byte_tree(&field_guide_root).expect("snapshot field-guide byte tree");
    let managed_registry_before =
        snapshot_byte_tree(&managed_registry_root).expect("snapshot managed-worktree registry");
    let execution_state_locks_before = execution_state_lock_paths
        .iter()
        .map(|path| snapshot_byte_tree(path).expect("snapshot execution-state lock"))
        .collect::<Vec<_>>();
    let git_mutation_surfaces_before =
        snapshot_git_mutation_surfaces(git.commondir()).expect("snapshot Git mutation surfaces");
    let head_before = current_head_oid(&repo).expect("capture initial HEAD");
    let index_before = fs::read(git.path().join("index")).expect("capture initial index bytes");
    let readme_before = fs::read(repo.join("README.md")).expect("capture initial tracked file");
    let run_id = RunId::new("preclaim-suitability-parked").expect("valid run id");
    let primary_worktree_before =
        primary_worktree_byte_tree_without_git_or_refusal_artifacts(&repo, &run_id)
            .expect("capture initial in-process primary byte tree");

    let run_root = repo.join(".maco/o2/runs").join(run_id.as_str());
    let checkpoint_run_root = authenticated_state_root
        .join(crate::state_journal::JOURNAL_ROOT_NAME)
        .join(run_id.as_str());
    let classification_run_root = run_root.clone();
    let classification_checkpoint_root = checkpoint_run_root.clone();
    let classification_claims_root = claims_root.clone();
    let classification_semantic_root = semantic_root.clone();
    let classification_field_guide_root = field_guide_root.clone();
    let classification_managed_root = managed_registry_root.clone();
    set_after_assignment_suitability_classification_hook(move |outcomes| {
        assert!(!outcomes.is_empty());
        assert!(outcomes
            .iter()
            .all(|outcome| { outcome.disposition != AssignmentSuitabilityDisposition::Admitted }));
        for path in [
            &classification_run_root,
            &classification_checkpoint_root,
            &classification_claims_root,
            &classification_semantic_root,
            &classification_field_guide_root,
            &classification_managed_root,
        ] {
            assert!(
                !path.exists(),
                "suitability classification ran after mutation-capable state creation: {}",
                path.display()
            );
        }
    });
    set_before_scheduler_execution_state_initialization_hook(|| {
        panic!("a wholly non-admitted plan reached execution-state initialization")
    });
    let options = injected_options(&repo, temp.path(), run_id.as_str());
    fs::write(&options.plan_file, plan_document).expect("write production-boundary plan file");
    let cascade = run_supervisor_plan_file_cascade_with_concurrency_policy(
        options,
        SupervisorConcurrencyPolicy::Auto,
    )
    .expect("finalize parked suitability outcome through the production cascade entrypoint");
    let report = cascade.source_report;
    clear_before_scheduler_execution_state_initialization_hook();

    assert!(!report.success);
    assert!(report
        .next_safe_action
        .contains("assignment_suitability_outcomes"));
    let parked = report
        .assignment_suitability_outcomes
        .iter()
        .filter(|outcome| outcome.disposition == AssignmentSuitabilityDisposition::Parked)
        .collect::<Vec<_>>();
    assert_eq!(parked.len(), 2);
    let parked_parent = parked
        .iter()
        .find(|outcome| outcome.assignment_id == "parked-parent")
        .expect("parked parent outcome");
    assert_eq!(
        parked_parent.assessment_source,
        AssignmentSuitabilityAssessmentSource::ExplicitAssignmentAuthority
    );
    assert_eq!(
        parked_parent.reasons,
        vec![AssignmentSuitabilityReason::ClassificationUnclear]
    );
    let suppressed_descendant = parked
        .iter()
        .find(|outcome| outcome.assignment_id == "suppressed-descendant")
        .expect("dependency-suppressed descendant outcome");
    assert_eq!(
        suppressed_descendant.assessment_source,
        AssignmentSuitabilityAssessmentSource::HistoricalCompatibilityDefault,
        "the descriptive origin remains historical even though the validated hierarchy suppresses dispatch"
    );
    assert_eq!(
        suppressed_descendant.reasons,
        vec![AssignmentSuitabilityReason::AncestorNotAdmitted]
    );
    assert!(report.findings.iter().any(|finding| {
        finding
            .message
            .contains("'suppressed-descendant' was dependency-suppressed")
    }));
    let refused = report
        .assignment_suitability_outcomes
        .iter()
        .filter(|outcome| outcome.disposition == AssignmentSuitabilityDisposition::Refused)
        .collect::<Vec<_>>();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].assignment_id, "refused-duplicate");
    assert_eq!(
        refused[0].assessment_source,
        AssignmentSuitabilityAssessmentSource::ExplicitAssignmentAuthority
    );
    assert_eq!(
        refused[0].reasons,
        vec![AssignmentSuitabilityReason::ClassificationDuplicate]
    );
    assert!(report.orchestrator_reports.is_empty());
    assert!(report.commands_run.is_empty());
    assert!(report.claim_tokens.is_empty());
    assert!(report.semantic_intent_tokens.is_empty());
    assert!(report.released_claims.is_empty());
    assert!(report.released_semantic_intents.is_empty());
    assert!(report.release_errors.is_empty());
    assert!(report.semantic_release_errors.is_empty());
    assert!(report.breaker_trip.is_none());
    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("scheduler execution telemetry");
    assert_eq!(execution.started_assignment_count, 0);
    assert_eq!(execution.completed_assignment_count, 0);

    assert_eq!(
        snapshot_byte_tree(&claims_root).expect("resnapshot claims byte tree"),
        claims_before,
        "the refusal path created authenticated claim state"
    );
    assert_eq!(
        snapshot_byte_tree(&semantic_root).expect("resnapshot semantic-intent byte tree"),
        semantic_before,
        "the refusal path created authenticated semantic-intent state"
    );
    assert_eq!(
        snapshot_byte_tree(&field_guide_root).expect("resnapshot field-guide byte tree"),
        field_guide_before,
        "the refusal path created authenticated field-guide state"
    );
    assert_eq!(
        snapshot_byte_tree(&managed_registry_root).expect("resnapshot managed-worktree registry"),
        managed_registry_before,
        "the refusal path created authenticated managed-worktree state"
    );
    assert_eq!(
        execution_state_lock_paths
            .iter()
            .map(|path| snapshot_byte_tree(path).expect("resnapshot execution-state lock"))
            .collect::<Vec<_>>(),
        execution_state_locks_before,
        "the refusal path acquired an execution-state lock"
    );
    assert_eq!(
        snapshot_git_mutation_surfaces(git.commondir()).expect("resnapshot Git mutation surfaces"),
        git_mutation_surfaces_before,
        "Git HEAD/index/config/ref/log/worktree metadata changed before the suitability refusal"
    );
    assert!(git
        .find_branch("maco/parked-parent", git2::BranchType::Local)
        .is_err());
    assert!(git
        .find_branch("maco/suppressed-descendant", git2::BranchType::Local)
        .is_err());
    assert!(git
        .find_branch("maco/refused-duplicate", git2::BranchType::Local)
        .is_err());
    assert_eq!(
        current_head_oid(&repo).expect("HEAD after parked run"),
        head_before
    );
    assert_eq!(
        fs::read(git.path().join("index")).expect("index bytes after parked run"),
        index_before
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("tracked file after parked run"),
        readme_before
    );
    assert_eq!(
        primary_worktree_byte_tree_without_git_or_refusal_artifacts(&repo, &run_id)
            .expect("capture final in-process primary byte tree"),
        primary_worktree_before,
        "the verified refusal changed the primary worktree outside the exact durable refusal artifacts"
    );
    let authenticator =
        repository_authenticator_key_only(&repo).expect("open checkpoint authenticator");
    let checkpoint =
        crate::state_journal::StateJournal::open_instance(authenticator, run_id.as_str())
            .expect("authenticate finalized checkpoint records");
    assert_eq!(
        checkpoint
            .records()
            .iter()
            .map(|record| record.phase.as_str())
            .collect::<Vec<_>>(),
        vec![
            "supervise_prepared",
            "scheduler_closed",
            "final_report_planned",
            "final_report_committed",
            "artifact_finalization_started",
            "artifact_finalized"
        ],
        "the verified refusal path must not add an execution-capable checkpoint phase"
    );
    let scheduler_closed = checkpoint
        .records()
        .iter()
        .find(|record| record.phase == "scheduler_closed")
        .expect("durable scheduler closure");
    assert_eq!(
        scheduler_closed.payload["pending_assignments"],
        json!([
            "parked-parent",
            "refused-duplicate",
            "suppressed-descendant"
        ])
    );

    let _reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open parked run artifacts");
    let artifact_run_dir = repo.join(".maco/o2/runs").join(run_id.as_str());
    assert!(!artifact_run_dir.join(ORCHESTRATION_EVENT_PATH).exists());
    let artifact_files = relative_regular_files(&artifact_run_dir)
        .expect("snapshot finalized run-owned artifact files");
    assert_eq!(
        artifact_files,
        BTreeSet::from([
            PathBuf::from(".artifact.lock"),
            PathBuf::from(".maco-artifact-final.json"),
            PathBuf::from("reports/supervisor-final.json")
        ]),
        "the verified refusal path created an unexpected run-owned artifact"
    );
}

#[test]
fn refused_primary_target_uses_verified_refusal_capability_before_cleanliness_or_runtime() {
    let (temp, repo) = injected_repository();
    fs::write(
        repo.join("README.md"),
        "dirty primary state that cleanliness would reject\n",
    )
    .expect("dirty tracked primary file");
    let mut plan_document = suitability_test_plan(
        json!([{
            "id": "refused-primary",
            "assigned_paths": ["docs/refused.md"],
            "suitability": {
                "classification": "out_of_scope",
                "bounded_scope": true,
                "max_scope_paths": 1,
                "verification_path": "supervisor_validation_floor",
                "autonomous_completion": true,
                "rationale": "the requested primary mutation lies outside approved scope"
            }
        }]),
        2,
    );
    plan_document["execution_target"] = json!({
        "kind": "primary_worktree",
        "claim_paths": ["docs/refused.md"]
    });
    let options = injected_options(&repo, temp.path(), "refused-primary-target");
    fs::write(
        &options.plan_file,
        serde_json::to_vec(&plan_document).expect("serialize refused primary plan"),
    )
    .expect("write refused primary plan file");
    set_before_scheduler_execution_state_initialization_hook(|| {
        panic!("verified primary-target refusal reached execution-state initialization")
    });
    let cascade =
        run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
            options,
            SupervisorConcurrencyPolicy::Auto,
            true,
        )
        .expect("verified refusal capability accepts a non-mutating primary target");
    let report = cascade.source_report;
    clear_before_scheduler_execution_state_initialization_hook();

    assert!(!report.success);
    assert_eq!(report.assignment_suitability_outcomes.len(), 1);
    assert_eq!(
        report.assignment_suitability_outcomes[0].reasons,
        vec![AssignmentSuitabilityReason::ClassificationOutOfScope]
    );
    assert!(report.claim_tokens.is_empty());
    assert!(report.orchestrator_reports.is_empty());
}

#[test]
fn suitability_legacy_default_recursive_roundtrip_and_bounds_are_strict() {
    let legacy_value = suitability_test_plan(
        json!([{"id": "legacy", "assigned_paths": ["README.md"]}]),
        2,
    );
    let legacy = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&legacy_value).expect("serialize legacy plan"),
    )
    .expect("historical plan without suitability remains readable");
    assert_eq!(
        legacy.assignment_metadata.suitability("legacy"),
        AssignmentSuitabilityConfig::default()
    );
    assert_eq!(
        legacy.assignment_metadata.suitability_source("legacy"),
        AssignmentSuitabilityAssessmentSource::HistoricalCompatibilityDefault
    );
    let normalized_legacy = supervisor_plan_value(
        &legacy.plan,
        &legacy.consultant,
        &legacy.assignment_metadata,
        &legacy.plan_metadata,
    )
    .expect("normalize historical plan without fabricating explicit authority");
    assert!(normalized_legacy["assignments"][0]
        .get("suitability")
        .is_none());
    assert!(normalized_legacy["assignments"][0]
        .get("suitability_assessment_source")
        .is_none());

    let planned_assignment = injected_assignment(false);
    let planned_assignment_id = planned_assignment.id.clone();
    let planned_plan = injected_plan(planned_assignment, 0);
    let mut planned_assignment_metadata = AssignmentMetadata::new();
    insert_generated_planner_suitability(
        &mut planned_assignment_metadata,
        planned_assignment_id.clone(),
    );
    let planned = LoadedSupervisorPlan {
        plan: planned_plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: planned_assignment_metadata,
        plan_metadata: SupervisorPlanMetadata {
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id: planned_assignment_id,
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }],
            ..SupervisorPlanMetadata::default()
        },
    };
    assert!(!planned.plan.assignments.is_empty());
    assert!(planned
        .assignment_metadata
        .suitability_sources
        .values()
        .all(|source| {
            *source == AssignmentSuitabilityAssessmentSource::GeneratedPlannerAuthority
        }));
    let normalized_planned = supervisor_plan_value(
        &planned.plan,
        &planned.consultant,
        &planned.assignment_metadata,
        &planned.plan_metadata,
    )
    .expect("normalize generated planner authority");
    assert!(normalized_planned["assignments"]
        .as_array()
        .expect("normalized generated assignments")
        .iter()
        .all(|assignment| {
            assignment["suitability_assessment_source"] == "generated_planner_authority"
                && assignment.get("suitability").is_none()
        }));
    let reloaded_planned = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized_planned)
            .expect("serialize normalized generated planner authority"),
    )
    .expect("reload generated planner authority");
    assert_eq!(
        reloaded_planned.assignment_metadata.suitability_sources,
        planned.assignment_metadata.suitability_sources
    );

    // Historical plans commonly used one broad directory claim. Keep that
    // input dispatch-compatible, but report that its optimistic default is a
    // compatibility decision rather than explicit operator classification.
    let broad_legacy = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&suitability_test_plan(
            json!([{"id": "broad-legacy", "assigned_paths": ["src"]}]),
            2,
        ))
        .expect("serialize broad historical plan"),
    )
    .expect("broad historical plan remains readable");
    let broad_outcome = broad_legacy
        .assignment_metadata
        .suitability("broad-legacy")
        .outcome(
            "broad-legacy",
            broad_legacy.plan.assignments[0].assigned_paths.len(),
            broad_legacy
                .assignment_metadata
                .suitability_source("broad-legacy"),
        );
    assert_eq!(
        broad_outcome.assessment_source,
        AssignmentSuitabilityAssessmentSource::HistoricalCompatibilityDefault
    );
    assert_eq!(
        broad_outcome.disposition,
        AssignmentSuitabilityDisposition::Admitted
    );
    let configured_value = suitability_test_plan(
        json!([{
            "id": "root",
            "assigned_paths": ["README.md"],
            "suitability": {
                "classification": "viable",
                "bounded_scope": true,
                "max_scope_paths": 8,
                "verification_path": "supervisor_validation_floor",
                "autonomous_completion": true
            },
            "child_assignments": [{
                "id": "child",
                "assigned_paths": ["README.md"],
                "suitability": {
                    "classification": "needs_decision",
                    "bounded_scope": true,
                    "max_scope_paths": 4,
                    "verification_path": "supervisor_validation_floor",
                    "autonomous_completion": true,
                    "rationale": "operator must resolve the dependent decision"
                }
            }]
        }]),
        3,
    );
    let configured = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&configured_value).expect("serialize configured plan"),
    )
    .expect("parse recursively configured suitability plan");
    let normalized = supervisor_plan_value(
        &configured.plan,
        &configured.consultant,
        &configured.assignment_metadata,
        &configured.plan_metadata,
    )
    .expect("normalize configured suitability plan");
    let reloaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized suitability plan"),
    )
    .expect("reload normalized suitability plan");
    assert_eq!(
        reloaded.assignment_metadata.suitability,
        configured.assignment_metadata.suitability
    );
    assert_eq!(
        reloaded.assignment_metadata.suitability_sources,
        configured.assignment_metadata.suitability_sources
    );
    assert!(configured
        .assignment_metadata
        .suitability_sources
        .values()
        .all(
            |source| *source == AssignmentSuitabilityAssessmentSource::ExplicitAssignmentAuthority
        ));
    assert_eq!(
        reloaded
            .assignment_metadata
            .suitability("child")
            .classification,
        AssignmentSuitabilityClassification::NeedsDecision
    );
    let plan_only_temp = tempfile::tempdir().expect("create plan-only compatibility tempdir");
    let plan_only_path = plan_only_temp.path().join("configured-plan.json");
    fs::write(
        &plan_only_path,
        serde_json::to_vec(&configured_value).expect("serialize plan-only compatibility input"),
    )
    .expect("write plan-only compatibility input");
    let plan_only = load_supervisor_plan_file(&plan_only_path)
        .expect("historical plan-only API remains readable");
    let plan_only_json = serde_json::to_value(plan_only).expect("serialize plan-only model");
    assert!(plan_only_json["assignments"]
        .as_array()
        .expect("plan-only assignments")
        .iter()
        .all(|assignment| {
            assignment.get("suitability").is_none()
                && assignment.get("suitability_assessment_source").is_none()
        }),
        "the documented plan-only API is intentionally lossy; normalized document APIs preserve descriptive suitability provenance"
    );

    for invalid in [0, MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS + 1] {
        let value = suitability_test_plan(
            json!([{
                "id": "invalid-bound",
                "assigned_paths": ["README.md"],
                "suitability": {
                    "classification": "viable",
                    "bounded_scope": true,
                    "max_scope_paths": invalid,
                    "verification_path": "supervisor_validation_floor",
                    "autonomous_completion": true
                }
            }]),
            2,
        );
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&value).expect("serialize invalid bound")
        )
        .is_err());
    }
    let unknown = suitability_test_plan(
        json!([{
            "id": "unknown-field",
            "assigned_paths": ["README.md"],
            "suitability": {
                "classification": "viable",
                "bounded_scope": true,
                "max_scope_paths": 8,
                "verification_path": "supervisor_validation_floor",
                "autonomous_completion": true,
                "hidden_handoff_fragment": "must not be accepted"
            }
        }]),
        2,
    );
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&unknown).expect("serialize unknown field plan")
    )
    .is_err());

    let forged_source = suitability_test_plan(
        json!([{
            "id": "forged-source",
            "assigned_paths": ["README.md"],
            "suitability_assessment_source": "historical_compatibility_default"
        }]),
        2,
    );
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&forged_source).expect("serialize forged source plan")
    )
    .is_err());

    let mut excessive_capacity = suitability_test_plan(
        json!([{"id": "bounded-count", "assigned_paths": ["README.md"]}]),
        2,
    );
    excessive_capacity["max_child_assignments"] =
        json!(MAX_SUPERVISOR_ASSIGNMENT_OUTCOMES.saturating_add(1));
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&excessive_capacity).expect("serialize excessive capacity plan")
    )
    .is_err());

    let oversized_id = "a".repeat(MAX_SUPERVISOR_ASSIGNMENT_ID_BYTES.saturating_add(1));
    let oversized_id_plan = suitability_test_plan(
        json!([{"id": oversized_id, "assigned_paths": ["README.md"]}]),
        2,
    );
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&oversized_id_plan).expect("serialize oversized id plan")
    )
    .is_err());

    let excessive_input_paths = (0..=MAX_SUPERVISOR_ASSIGNMENT_INPUT_PATHS)
        .map(|index| format!("bounded-input/{index}.rs"))
        .collect::<Vec<_>>();
    let excessive_input_paths_plan = suitability_test_plan(
        json!([{"id": "excessive-input-paths", "assigned_paths": excessive_input_paths}]),
        2,
    );
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&excessive_input_paths_plan)
            .expect("serialize excessive input paths plan")
    )
    .is_err());

    let over_limit_paths = (0..=MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS)
        .map(|index| format!("scope/{index}.rs"))
        .collect::<Vec<_>>();
    let over_limit = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&suitability_test_plan(
            json!([{"id": "legacy-over-limit", "assigned_paths": over_limit_paths}]),
            2,
        ))
        .expect("serialize over-limit legacy plan"),
    )
    .expect("legacy over-limit scope is classified at runtime, not rejected by decoding");
    let outcome = over_limit
        .assignment_metadata
        .suitability("legacy-over-limit")
        .outcome(
            "legacy-over-limit",
            over_limit.plan.assignments[0].assigned_paths.len(),
            over_limit
                .assignment_metadata
                .suitability_source("legacy-over-limit"),
        );
    assert_eq!(
        outcome.disposition,
        AssignmentSuitabilityDisposition::Parked
    );
    assert_eq!(
        outcome.reasons,
        vec![AssignmentSuitabilityReason::ScopeNotBounded]
    );
    assert!(!outcome.axes.within_scope_path_limit);

    let refused = AssignmentSuitabilityConfig {
        classification: AssignmentSuitabilityClassification::Duplicate,
        rationale: Some("operator triage identified a duplicate assignment".to_string()),
        ..AssignmentSuitabilityConfig::default()
    }
    .outcome(
        "duplicate",
        1,
        AssignmentSuitabilityAssessmentSource::ExplicitAssignmentAuthority,
    );
    assert_eq!(
        refused.disposition,
        AssignmentSuitabilityDisposition::Refused
    );
    assert_eq!(
        refused.reasons,
        vec![AssignmentSuitabilityReason::ClassificationDuplicate]
    );

    let mut rationale_config = AssignmentSuitabilityConfig {
        rationale: Some("界".repeat(MAX_ASSIGNMENT_SUITABILITY_RATIONALE_CHARS)),
        ..AssignmentSuitabilityConfig::default()
    };
    rationale_config
        .validate("unicode-rationale-at-limit")
        .expect("runtime bound counts Unicode characters like JSON Schema maxLength");
    rationale_config.rationale =
        Some("界".repeat(MAX_ASSIGNMENT_SUITABILITY_RATIONALE_CHARS.saturating_add(1)));
    assert!(rationale_config
        .validate("unicode-rationale-over-limit")
        .is_err());
    for invalid_rationale in [" leading", "trailing ", "embedded\u{0007}control"] {
        rationale_config.rationale = Some(invalid_rationale.to_string());
        assert!(rationale_config.validate("invalid-rationale").is_err());
    }
}

#[test]
fn suitability_schema_is_strict_bounded_and_report_field_is_backward_readable() {
    let schema = supervisor_final_report_schema_value();
    assert!(!schema["required"]
        .as_array()
        .is_some_and(|required| required
            .iter()
            .any(|field| field == "assignment_suitability_outcomes")));
    assert!(schema["properties"]
        .get("assignment_suitability_outcomes")
        .is_some());
    let outcome = &schema["properties"]["assignment_suitability_outcomes"]["items"];
    assert_eq!(
        schema["properties"]["assignment_suitability_outcomes"]["maxItems"],
        MAX_SUPERVISOR_ASSIGNMENT_OUTCOMES
    );
    assert_eq!(outcome["additionalProperties"], false);
    assert!(outcome["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|field| field == "assessment_source")));
    assert_eq!(
        outcome["properties"]["reasons"]["maxItems"],
        MAX_ASSIGNMENT_SUITABILITY_REASONS
    );
    assert_eq!(
        outcome["properties"]["assignment_id"]["maxLength"],
        MAX_SUPERVISOR_ASSIGNMENT_ID_BYTES
    );
    assert_eq!(
        outcome["properties"]["axes"]["properties"]["scope_path_count"]["maximum"],
        MAX_SUPERVISOR_ASSIGNMENT_INPUT_PATHS
    );
    assert_eq!(
        outcome["properties"]["axes"]["properties"]["max_scope_paths"]["maximum"],
        MAX_SUPERVISOR_ASSIGNMENT_SCOPE_PATHS
    );
    assert_eq!(
        outcome["properties"]["rationale"]["maxLength"],
        MAX_ASSIGNMENT_SUITABILITY_RATIONALE_CHARS
    );
    assert_eq!(
        outcome["properties"]["rationale"]["pattern"],
        ASSIGNMENT_SUITABILITY_RATIONALE_PATTERN
    );
    let config_schema = assignment_suitability_config_schema_value();
    assert_eq!(
        config_schema["properties"]["rationale"]["maxLength"],
        MAX_ASSIGNMENT_SUITABILITY_RATIONALE_CHARS
    );
    assert_eq!(
        config_schema["allOf"][0]["then"]["required"],
        json!(["rationale"])
    );
    let generated_plan_schema = &schema["properties"]["generated_follow_up_tasks"]["items"]
        ["properties"]["supervisor_plan"];
    assert!(generated_plan_schema["required"]
        .as_array()
        .is_some_and(|required| required
            .iter()
            .all(|field| field != "assignment_suitability")));
    assert!(generated_plan_schema["properties"]
        .get("assignment_suitability")
        .is_none());

    let ordinary = injected_plan(injected_assignment(false), 0);
    let assignment_id = ordinary.assignments[0].id.clone();
    let source_budget = injected_run_budget(None, None, None, None, 100, 100);
    let generated_budget = derived_generated_follow_up_budget(&ordinary, &source_budget)
        .expect("derive closed generated follow-up budget");
    let generated = GeneratedFollowUpSupervisorPlan {
        version: ordinary.version,
        task: ordinary.task.clone(),
        task_file: ordinary.task_file.clone(),
        max_depth: ordinary.max_depth,
        max_child_assignments: ordinary.max_child_assignments,
        max_child_retries: ordinary.max_child_retries,
        max_gate_corrections: ordinary.max_gate_corrections,
        child_timeout_seconds: ordinary.child_timeout_seconds,
        semantic_coordination: ordinary.semantic_coordination,
        role_models: ordinary.role_models.clone(),
        model_pricing: ordinary.model_pricing.clone(),
        review_lenses: ordinary.review_lenses.clone(),
        review_aggregation_policy: ordinary.review_aggregation_policy,
        assignments: ordinary.assignments.clone(),
        spec_fragment_ids: Vec::new(),
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: assignment_id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        run_budget: generated_budget,
        consultant: SupervisorConsultantPlan::default(),
        generated_follow_up: GeneratedFollowUpPlanContext {
            breaking_assignment_id: "source-assignment".to_string(),
            breaking_change: CandidateValidationBinding {
                version: 1,
                agent_id: "source-assignment".to_string(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "1111111111111111111111111111111111111111".to_string(),
            },
            declaration_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            failure_signature: "historical generated plan fixture".to_string(),
            migration_rationale: "exercise compatibility decoding".to_string(),
            cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
            dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
            handoff: "deferred fixture handoff".to_string(),
            operator_defaults: generated_follow_up_operator_defaults(),
        },
    };
    let generated_bytes = serde_json::to_vec(&generated).expect("serialize generated plan");
    let generated_json: serde_json::Value =
        serde_json::from_slice(&generated_bytes).expect("decode generated plan JSON fixture");
    assert!(generated_json.get("assignment_suitability").is_none());
    let generated_roundtrip: GeneratedFollowUpSupervisorPlan =
        serde_json::from_slice(&generated_bytes).expect("decode historical generated plan");
    assert_eq!(
        serde_json::to_vec(&generated_roundtrip).expect("reserialize historical generated plan"),
        generated_bytes,
        "generated plan canonical bytes must not change for authenticated queue replay"
    );
    validate_generated_follow_up_plan_document(&generated)
        .expect("generated plan reloads through construction-derived suitability authority");
    assert_eq!(
        generated.effective_assignment_suitability(),
        BTreeMap::from([(
            assignment_id.clone(),
            AssignmentSuitabilityConfig::default()
        )])
    );
    let generated_loaded = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&generated_bytes).expect("generated plan JSON is UTF-8"),
    )
    .expect("ordinary loader consumes historical generated plan");
    assert_eq!(
        generated_loaded
            .assignment_metadata
            .suitability(&generated.assignments[0].id),
        AssignmentSuitabilityConfig::default()
    );
    assert_eq!(
        generated_loaded
            .assignment_metadata
            .suitability_source(&generated.assignments[0].id),
        AssignmentSuitabilityAssessmentSource::GeneratedFollowUpAuthority
    );

    let run_id = RunId::new("legacy-suitability-report").expect("valid legacy report id");
    let mut legacy_report = serde_json::to_value(artifact_test_final_report(&run_id))
        .expect("serialize final report fixture");
    legacy_report
        .as_object_mut()
        .expect("final report object")
        .remove("assignment_suitability_outcomes");
    let decoded: SupervisorFinalReport =
        serde_json::from_value(legacy_report).expect("read historical final report");
    assert!(decoded.assignment_suitability_outcomes.is_empty());

    let mut pre_source_report = serde_json::to_value(artifact_test_final_report(&run_id))
        .expect("serialize pre-assessment-source report fixture");
    let mut pre_source_outcome =
        serde_json::to_value(AssignmentSuitabilityConfig::default().outcome(
            "legacy-report-assignment",
            1,
            AssignmentSuitabilityAssessmentSource::ExplicitAssignmentAuthority,
        ))
        .expect("serialize pre-assessment-source outcome fixture");
    pre_source_outcome
        .as_object_mut()
        .expect("pre-assessment-source outcome object")
        .remove("assessment_source");
    pre_source_report["assignment_suitability_outcomes"] = json!([pre_source_outcome]);
    let decoded_pre_source: SupervisorFinalReport = serde_json::from_value(pre_source_report)
        .expect("read historical outcome without assessment source");
    assert_eq!(
        decoded_pre_source.assignment_suitability_outcomes[0].assessment_source,
        AssignmentSuitabilityAssessmentSource::HistoricalCompatibilityDefault
    );
}
