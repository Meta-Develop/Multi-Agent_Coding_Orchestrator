fn qualification_selection(source: &str) -> Result<SupervisorSelectionResolution> {
    let (_temporary, repo) = super::super::tests::injected_repository();
    let mut loaded =
        super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(source, Some(&repo))?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .clone()
        .context("qualification routing policy")?;
    let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
    // Membership is synthetic; effort and authority evidence come exclusively
    // from the bundled priors, as they do during live selection preflight.
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
        &["  * grok-4.6 (default)"],
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

fn qualification_refusals(
    resolution: &SupervisorSelectionResolution,
) -> Result<Vec<(AgentRole, selection_preflight::SelectionPreflightRejection)>> {
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
            ))
        })
        .collect()
}

#[test]
fn qualification_fixtures_pass_live_selection_preflight_except_documented_grok_low() -> Result<()> {
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
        fixtures.len() >= 3,
        "qualification fixtures must be present"
    );
    for path in fixtures {
        let resolution = qualification_selection(&std::fs::read_to_string(&path)?)?;
        if path.file_name().and_then(|name| name.to_str())
            == Some("qualification-grok-lower-effort.json")
        {
            assert_eq!(
                qualification_refusals(&resolution)?,
                vec![(
                    AgentRole::Worker,
                    selection_preflight::SelectionPreflightRejection::EffortIncompatible,
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
                    )
                })
                .collect::<Vec<_>>(),
            "{name}"
        );
    }
    Ok(())
}
