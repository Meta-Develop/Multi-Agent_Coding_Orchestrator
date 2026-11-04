fn qualification_selection(source: &str) -> Result<SupervisorSelectionResolution> {
    qualification_selection_with_prior(source, None)
}

fn qualification_selection_with_prior(
    source: &str,
    prior: Option<&str>,
) -> Result<SupervisorSelectionResolution> {
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _prior = if let Some(prior) = prior {
        std::fs::write(repo.join("prior.json"), prior)?;
        Some(super::super::prior_input::bind_operator_prior_data(
            &repo,
            "prior.json",
        )?)
    } else {
        None
    };
    let mut loaded =
        super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(source, Some(&repo))?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .clone()
        .context("qualification routing policy")?;
    let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
    // Membership is synthetic; effort and authority evidence come exclusively
    // from the active priors, as they do during live selection preflight.
    let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
        loaded
            .plan
            .role_models
            .values()
            .filter_map(|selection| selection.model.as_deref())
            .filter(|model| !model.starts_with("grok-"))
            .collect::<BTreeSet<_>>(),
    )?);
    let advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
        "grok-4.6",
        &["  * grok-4.6 (default)", "  - grok-4.7"],
    ))?);
    // Use the shipped assessment, not the selector unit-test wrapper that
    // synthesizes a different declaration. Parsing above validates its replay.
    super::initialize_supervisor_selection_with_assessment(
        &mut loaded.plan,
        SupervisorRuntime::Codex,
        &catalog,
        &test_admission(),
        &advertised,
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        loaded.plan_metadata.task_routing_assessment.as_ref(),
    )
}

#[test]
fn public_grok_evidence_checkpoint_cannot_admit_unqualified_lanes() -> Result<()> {
    let prior = include_str!("../../docs/qualification/priors/grok-public-2026-11-03.json");
    for source in [
        include_str!("../../examples/supervise/qualification-grok-lower-effort.json"),
        include_str!("../../examples/supervise/qualification-grok47-acp.json"),
    ] {
        let bundled = qualification_selection(source)?;
        let checkpoint = qualification_selection_with_prior(source, Some(prior))?;
        assert_eq!(
            qualification_refusals(&checkpoint)?,
            qualification_refusals(&bundled)?
        );
    }
    Ok(())
}

type QualificationRefusal = (
    AgentRole,
    selection_preflight::SelectionPreflightRejection,
    serde_json::Value,
);

fn qualification_refusals(
    resolution: &SupervisorSelectionResolution,
) -> Result<Vec<QualificationRefusal>> {
    let failure = resolution
        .selection_preflight_failure
        .as_ref()
        .context("expected qualification selection refusal")?;
    let diagnostics: Vec<serde_json::Value> = serde_json::from_str(
        failure
            .message
            .strip_prefix("selection preflight refused: ")
            .context("typed selection preflight diagnostics")?,
    )?;
    diagnostics
        .into_iter()
        .map(|entry| {
            Ok((
                serde_json::from_value(entry["role"].clone())?,
                serde_json::from_value(entry["rejection"].clone())?,
                entry["requested"].clone(),
            ))
        })
        .collect()
}

#[test]
fn qualification_fixtures_match_documented_bundled_prior_preflight_outcomes() -> Result<()> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/supervise");
    let mut fixtures = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    fixtures.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                (name.starts_with("qualification-") && name.ends_with(".json"))
                    || name == "nested-codex-budget-qualification.json"
            })
    });
    fixtures.sort();
    assert!(
        fixtures.len() >= 4,
        "qualification fixtures must be present"
    );
    for path in fixtures {
        let resolution = qualification_selection(&std::fs::read_to_string(&path)?)?;
        let expected_refusal = match path.file_name().and_then(|name| name.to_str()) {
            Some("qualification-grok-lower-effort.json") => Some((
                selection_preflight::SelectionPreflightRejection::EffortIncompatible,
                "grok-4.6",
                "low",
            )),
            Some("qualification-grok47-acp.json") => Some((
                selection_preflight::SelectionPreflightRejection::ModelUnavailable,
                "grok-4.7",
                "xhigh",
            )),
            _ => None,
        };
        if let Some((rejection, model, effort)) = expected_refusal {
            assert_eq!(
                qualification_refusals(&resolution)?,
                vec![(
                    AgentRole::Worker,
                    rejection,
                    json!({"runtime": "grok", "model": model, "effort": effort}),
                )],
                "{}",
                path.display()
            );
        } else {
            assert!(
                resolution.selection_preflight_failure.is_none(),
                "{}: {:?}",
                path.display(),
                resolution.selection_preflight_failure
            );
            assert!(!resolution.decisions.is_empty());
            assert!(resolution
                .decisions
                .iter()
                .all(|event| event.provenance.status == DecisionStatus::Selected));
        }
    }
    Ok(())
}

#[test]
fn qualification_original_medium_efforts_are_refused_before_release() -> Result<()> {
    for (name, roles) in [
        (
            "nested-codex-budget-qualification.json",
            vec![AgentRole::ChildOrchestrator, AgentRole::Worker],
        ),
        (
            "qualification-researcher-source-input.json",
            vec![AgentRole::Researcher],
        ),
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/supervise")
            .join(name);
        let mut source: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        for role in &roles {
            source["role_models"][role.as_str()]["reasoning_effort"] = json!("medium");
        }
        let resolution = qualification_selection(&serde_json::to_string(&source)?)?;
        assert_eq!(
            qualification_refusals(&resolution)?,
            roles
                .into_iter()
                .map(|role| {
                    (
                        role,
                        selection_preflight::SelectionPreflightRejection::EffortIncompatible,
                        json!({"runtime": "codex", "model": "gpt-6.1-sol", "effort": "medium"}),
                    )
                })
                .collect::<Vec<_>>(),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn synthetic_relative_public_prior_admits_only_requested_terminal_qualification_lane() -> Result<()> {
    // Synthetic scores exercise the reader/plan/bridge/selector path, not real qualification.
    for (source, model, effort) in [
        (include_str!("../../examples/supervise/qualification-grok-lower-effort.json"), "grok-4.6", selection::ReasoningEffort::Low),
        (include_str!("../../examples/supervise/qualification-grok47-acp.json"), "grok-4.7", selection::ReasoningEffort::Xhigh),
    ] {
        let mut public = selection::public_benchmark_test_snapshot();
        let today = crate::orchestration_event::format_rfc3339_utc(std::time::SystemTime::now())?;
        let today = &today[..10];
        for row in &mut public.rows {
            row.published_on = today.into();
            row.read_on = today.into();
        }
        public.rows[1].runtime = "grok".into();
        public.rows[1].model = model.into();
        public.rows[1].requested_effort = Some(effort);
        let prior = serde_json::json!({
            "schema_version": 1, "dataset_id": "synthetic-public-qualification", "revision": "synthetic-only",
            "published_on": today, "models": [], "public_benchmarks": [public],
            "capability_policy": { "id": "synthetic-public-qualification", "version": 1,
                "source": "synthetic test evidence; no actual qualification", "models": [] }
        });
        let selected = qualification_selection_with_prior(source, Some(&serde_json::to_string(&prior)?))?;
        assert!(selected.selection_preflight_failure.is_none(), "{model}: {selected:?}");
        for decision in &selected.decisions {
            let choice = decision.provenance.choice.as_ref().context("qualified fixture choice")?;
            if decision.role == AgentRole::Worker {
                assert_eq!(choice.candidate.model, model);
                assert_eq!(choice.candidate.effort, effort);
            } else {
                assert!(!choice.candidate.model.starts_with("grok-"));
            }
        }
    }
    Ok(())
}

const PUBLIC_LOCALIZED_PRIOR: &str =
    include_str!("../../docs/qualification/priors/public-localized-2026-11-04.json");
const PUBLIC_LOCALIZED_RELATIVE: &str = "docs/qualification/priors/public-localized-2026-11-04.json";
const PUBLIC_LOCALIZED_EVALUATED_ON: &str = "2026-11-04";

fn write_localized_prior(repo: &Path, bytes: &[u8]) -> Result<()> {
    let path = repo.join(PUBLIC_LOCALIZED_RELATIVE);
    fs::create_dir_all(path.parent().context("public prior parent")?)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn qualification_selection_with_localized(
    source: &str,
    prior_bytes: &[u8],
    primary: SupervisorRuntime,
) -> Result<SupervisorSelectionResolution> {
    let (_temporary, repo) = super::super::tests::injected_repository();
    write_localized_prior(&repo, prior_bytes)?;
    let _prior = super::super::prior_input::bind_operator_prior_data_evaluated_on(
        &repo,
        PUBLIC_LOCALIZED_RELATIVE,
        PUBLIC_LOCALIZED_EVALUATED_ON,
    )?;
    let mut loaded =
        super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(source, Some(&repo))?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .clone()
        .context("qualification routing policy")?;
    let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
    let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
        loaded
            .plan
            .role_models
            .values()
            .filter_map(|selection| selection.model.as_deref())
            .filter(|model| !model.starts_with("grok-"))
            .collect::<BTreeSet<_>>(),
    )?);
    let advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
        "grok-4.6",
        &["  * grok-4.6 (default)", "  - grok-4.7"],
    ))?);
    super::initialize_supervisor_selection_with_assessment(
        &mut loaded.plan,
        primary,
        &catalog,
        &test_admission(),
        &advertised,
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        loaded.plan_metadata.task_routing_assessment.as_ref(),
    )
}

fn grok_candidate(effort: SelectorEffort) -> CandidateKey {
    CandidateKey {
        runtime: "grok".to_string(),
        model: "grok-4.7".to_string(),
        effort,
    }
}

fn worker_lane(
    resolution: &SupervisorSelectionResolution,
    effort: SelectorEffort,
) -> Result<&selection::CandidateEvaluation> {
    let decision = resolution
        .decisions
        .iter()
        .find(|decision| decision.role == AgentRole::Worker)
        .context("worker decision")?;
    decision
        .provenance
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == grok_candidate(effort))
        .context("grok worker candidate")
}

fn set_role_model(source: &mut serde_json::Value, role: &str, model: &str, effort: &str) {
    source["role_models"][role]["model"] = json!(model);
    source["role_models"][role]["reasoning_effort"] = json!(effort);
}

fn set_assignment_runtime(source: &mut serde_json::Value, role: &str, runtime: &str) {
    for assignment in source["assignments"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        if assignment["role"] == role {
            assignment["runtime"] = json!(runtime);
        }
    }
}

#[test]
fn public_localized_prior_data_digest_uses_the_tracked_file() -> Result<()> {
    let (_temporary, repo) = super::super::tests::injected_repository();
    write_localized_prior(&repo, PUBLIC_LOCALIZED_PRIOR.as_bytes())?;
    let production =
        super::super::prior_input::bind_operator_prior_data(&repo, PUBLIC_LOCALIZED_RELATIVE)?;
    let production_provenance =
        super::super::prior_input::current_provenance().context("production provenance")?;
    assert_eq!(
        production_provenance.relative_path,
        PUBLIC_LOCALIZED_RELATIVE
    );
    assert_eq!(
        production_provenance.raw_sha256,
        crate::artifacts::state_auth::sha256_hex(PUBLIC_LOCALIZED_PRIOR.as_bytes())
    );
    drop(production);
    let _frozen = super::super::prior_input::bind_operator_prior_data_evaluated_on(
        &repo,
        PUBLIC_LOCALIZED_RELATIVE,
        PUBLIC_LOCALIZED_EVALUATED_ON,
    )?;
    let provenance = super::super::prior_input::current_provenance().context("frozen provenance")?;
    assert_eq!(provenance.raw_sha256, production_provenance.raw_sha256);
    assert_eq!(provenance.relative_path, PUBLIC_LOCALIZED_RELATIVE);
    let priors = super::super::prior_input::current_priors().context("frozen priors")?;
    assert_eq!(
        priors.public_benchmarks_evaluated_on.as_deref(),
        Some(PUBLIC_LOCALIZED_EVALUATED_ON)
    );
    assert_eq!(priors.public_benchmarks.len(), 1);
    let snapshot = &priors.public_benchmarks[0];
    assert_eq!(
        snapshot.task_classes,
        ["localized_code_change".to_string()].into_iter().collect()
    );
    assert_eq!(
        snapshot.reference_lane.as_ref(),
        Some(&CandidateKey {
            runtime: "codex".to_string(),
            model: "gpt-6.1-sol".to_string(),
            effort: SelectorEffort::High,
        })
    );
    assert_eq!(snapshot.rows.len(), 3);
    let grok = priors
        .models
        .iter()
        .find(|prior| prior.runtime == "grok" && prior.model == "grok-4.7")
        .context("public grok identity")?;
    assert!(grok.class_fit.is_empty());
    assert!(grok.authority_evidence.is_empty());
    assert_eq!(grok.strength_rank, 0);
    assert_eq!(grok.source_id, "dated-public-benchmark");
    assert!(!grok.prohibited);
    assert!(priors.models.iter().any(|prior| {
        prior.model == "gpt-6.1-sol"
            && prior.source_id == "owner-policy-gpt-6-1-sol-all-codex-roles-2026-10-22"
    }));
    let worker = super::task_profile_for_role(AgentRole::Worker);
    let reference = CandidateKey {
        runtime: "codex".to_string(),
        model: "gpt-6.1-sol".to_string(),
        effort: SelectorEffort::High,
    };
    assert_eq!(
        priors
            .relative_public_prior(&reference, &worker)
            .map(|prior| prior.quality_basis_points),
        Some(10_000)
    );
    assert_eq!(
        priors
            .relative_public_prior(&grok_candidate(SelectorEffort::High), &worker)
            .map(|prior| prior.quality_basis_points),
        Some(9956)
    );
    assert_eq!(
        priors
            .relative_public_prior(&grok_candidate(SelectorEffort::Xhigh), &worker)
            .map(|prior| prior.quality_basis_points),
        Some(10_000)
    );
    assert!(priors
        .relative_public_prior(&grok_candidate(SelectorEffort::Low), &worker)
        .is_none());
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("213"));
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("2026-10-27"));
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("\"requested_effort\": \"low\""));
    let mut review = super::task_profile_for_role(AgentRole::Researcher);
    assert!(priors
        .relative_public_prior(&grok_candidate(SelectorEffort::Xhigh), &review)
        .is_none());
    review.task_class = "unmapped_public_class".to_string();
    assert!(priors
        .relative_public_prior(&grok_candidate(SelectorEffort::Xhigh), &review)
        .is_none());
    for role in [
        AgentRole::ChildOrchestrator,
        AgentRole::Supervisor,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ] {
        let task = super::task_profile_for_role(role);
        assert!(
            priors
                .relative_public_prior(&grok_candidate(SelectorEffort::Xhigh), &task)
                .is_none(),
            "{role:?}"
        );
    }
    let mut bounded = worker;
    for authority in [
        selection::AuthorityRole::Delegating,
        selection::AuthorityRole::AcceptanceGate,
        selection::AuthorityRole::ReviewAuditor,
        selection::AuthorityRole::Audit,
        selection::AuthorityRole::ConflictResolution,
        selection::AuthorityRole::FailureClassification,
        selection::AuthorityRole::GitPublication,
        selection::AuthorityRole::UnknownJudgment,
    ] {
        bounded.authority_role = authority;
        assert!(
            priors
                .relative_public_prior(&grok_candidate(SelectorEffort::Xhigh), &bounded)
                .is_none(),
            "{authority:?}"
        );
    }
    let capability =
        super::super::prior_input::current_capability_policy().context("capability policy")?;
    assert!(capability
        .models
        .iter()
        .all(|row| row.model != "grok-4.7"));
    assert!(crate::supervise::model_policy::authorize_known_executor_role_model(
        AgentRole::Worker,
        Some("grok-4.7"),
        None
    )
    .is_err());
    for role in [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Auditor,
        AgentRole::GateClassifier,
    ] {
        assert!(
            crate::supervise::model_policy::validate_known_judgment_role_model(
                role,
                Some("grok-4.7")
            )
            .is_err(),
            "{role:?}"
        );
    }
    Ok(())
}

#[test]
fn public_localized_prior_admits_high_and_xhigh_only() -> Result<()> {
    let fixture = include_str!("../../examples/supervise/qualification-grok47-acp.json");
    for (effort, basis_points) in [
        (SelectorEffort::High, 9956u16),
        (SelectorEffort::Xhigh, 10_000u16),
    ] {
        let mut source: serde_json::Value = serde_json::from_str(fixture)?;
        set_role_model(&mut source, "worker", "grok-4.7", effort.as_str());
        let selected = qualification_selection_with_localized(
            &serde_json::to_string(&source)?,
            PUBLIC_LOCALIZED_PRIOR.as_bytes(),
            SupervisorRuntime::Codex,
        )?;
        assert!(
            selected.selection_preflight_failure.is_none(),
            "{effort:?}: {:?}",
            selected.selection_preflight_failure
        );
        let lane = worker_lane(&selected, effort)?;
        assert!(lane.eligible, "{effort:?}");
        let evidence = lane
            .loaded_policy_evidence
            .as_ref()
            .context("public evidence")?;
        assert_eq!(evidence.quality_basis_points, Some(basis_points), "{effort:?}");
        assert_eq!(evidence.samples, 0, "{effort:?}");
        let decision = selected
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert_eq!(decision.provenance.status, DecisionStatus::Selected);
        let choice = decision.provenance.choice.as_ref().context("worker choice")?;
        assert_eq!(choice.candidate, grok_candidate(effort));
        assert_eq!(
            decision
                .provenance
                .operator_prior_data
                .as_ref()
                .context("prior provenance")?
                .raw_sha256,
            crate::artifacts::state_auth::sha256_hex(PUBLIC_LOCALIZED_PRIOR.as_bytes())
        );
        for other in &selected.decisions {
            if other.role == AgentRole::Worker {
                continue;
            }
            assert_eq!(
                other.provenance.status,
                DecisionStatus::Selected,
                "{:?}",
                other.role
            );
            let other_choice = other
                .provenance
                .choice
                .as_ref()
                .context("control-role choice")?;
            assert!(
                !other_choice.candidate.model.starts_with("grok-"),
                "{:?}",
                other.role
            );
        }
    }

    let mut low: serde_json::Value = serde_json::from_str(fixture)?;
    set_role_model(&mut low, "worker", "grok-4.7", "low");
    let refused = qualification_selection_with_localized(
        &serde_json::to_string(&low)?,
        PUBLIC_LOCALIZED_PRIOR.as_bytes(),
        SupervisorRuntime::Codex,
    )?;
    assert_eq!(
        qualification_refusals(&refused)?,
        vec![(
            AgentRole::Worker,
            selection_preflight::SelectionPreflightRejection::EffortIncompatible,
            json!({"runtime": "grok", "model": "grok-4.7", "effort": "low"}),
        )]
    );
    Ok(())
}

#[test]
fn public_localized_prior_refuses_unmapped_classes_and_low() -> Result<()> {
    let mut researcher: serde_json::Value = serde_json::from_str(include_str!(
        "../../examples/supervise/qualification-researcher-source-input.json"
    ))?;
    set_role_model(&mut researcher, "researcher", "grok-4.7", "xhigh");
    set_assignment_runtime(&mut researcher, "researcher", "grok");
    let rejected_researcher = qualification_selection_with_localized(
        &serde_json::to_string(&researcher)?,
        PUBLIC_LOCALIZED_PRIOR.as_bytes(),
        SupervisorRuntime::Codex,
    );
    assert!(
        rejected_researcher
            .expect_err("grok researcher runtime must be refused")
            .to_string()
            .contains("researcher requires a supported strict Linux read-only runtime")
    );
    let mut researcher_codex: serde_json::Value = serde_json::from_str(include_str!(
        "../../examples/supervise/qualification-researcher-source-input.json"
    ))?;
    set_role_model(&mut researcher_codex, "researcher", "grok-4.7", "xhigh");
    let researcher_model = qualification_selection_with_localized(
        &serde_json::to_string(&researcher_codex)?,
        PUBLIC_LOCALIZED_PRIOR.as_bytes(),
        SupervisorRuntime::Codex,
    )?;
    assert!(qualification_refusals(&researcher_model)?
        .iter()
        .any(|refusal| {
            refusal.0 == AgentRole::Researcher
                && refusal.1 == selection_preflight::SelectionPreflightRejection::ModelUnavailable
                && refusal.2["model"] == "grok-4.7"
        }));

    let mut nested: serde_json::Value = serde_json::from_str(include_str!(
        "../../examples/supervise/nested-codex-budget-qualification.json"
    ))?;
    set_role_model(&mut nested, "child_orchestrator", "grok-4.7", "xhigh");
    set_assignment_runtime(&mut nested, "child_orchestrator", "grok");
    let nested = qualification_selection_with_localized(
        &serde_json::to_string(&nested)?,
        PUBLIC_LOCALIZED_PRIOR.as_bytes(),
        SupervisorRuntime::Codex,
    )?;
    assert!(qualification_refusals(&nested)?.iter().any(|refusal| {
        refusal.0 == AgentRole::ChildOrchestrator
            && refusal.1 == selection_preflight::SelectionPreflightRejection::ModelUnavailable
            && refusal.2["model"] == "grok-4.7"
    }));

    let mut judgment: serde_json::Value =
        serde_json::from_str(include_str!("../../examples/supervise/qualification-grok47-acp.json"))?;
    for role in ["supervisor", "gate_classifier", "auditor"] {
        set_role_model(&mut judgment, role, "grok-4.7", "xhigh");
    }
    let judgment = qualification_selection_with_localized(
        &serde_json::to_string(&judgment)?,
        PUBLIC_LOCALIZED_PRIOR.as_bytes(),
        SupervisorRuntime::Grok,
    )?;
    let refusals = qualification_refusals(&judgment)?;
    for role in [
        AgentRole::Supervisor,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ] {
        assert!(
            refusals.iter().any(|refusal| {
                refusal.0 == role
                    && refusal.1
                        == selection_preflight::SelectionPreflightRejection::ModelUnavailable
                    && refusal.2["model"] == "grok-4.7"
            }),
            "{role:?}: {refusals:?}"
        );
    }
    assert!(
        !refusals
            .iter()
            .any(|refusal| refusal.0 == AgentRole::Worker),
        "worker xhigh is a tracked row: {refusals:?}"
    );
    let worker = judgment
        .decisions
        .iter()
        .find(|decision| decision.role == AgentRole::Worker)
        .context("worker decision")?;
    assert_eq!(worker.provenance.status, DecisionStatus::Selected);
    let choice = worker.provenance.choice.as_ref().context("worker choice")?;
    assert_eq!(choice.candidate, grok_candidate(SelectorEffort::Xhigh));
    let evidence = worker_lane(&judgment, SelectorEffort::Xhigh)?
        .loaded_policy_evidence
        .as_ref()
        .context("worker evidence")?;
    assert_eq!(evidence.quality_basis_points, Some(10_000));
    assert_eq!(evidence.samples, 0);

    let tracked: serde_json::Value = serde_json::from_str(PUBLIC_LOCALIZED_PRIOR)?;
    let benchmarks = tracked["public_benchmarks"]
        .as_array()
        .context("public benchmarks")?;
    assert_eq!(benchmarks.len(), 1);
    assert_eq!(benchmarks[0]["rows"].as_array().context("rows")?.len(), 3);
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("213"));
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("2026-10-27"));
    assert!(!PUBLIC_LOCALIZED_PRIOR.contains("\"requested_effort\": \"low\""));
    Ok(())
}
