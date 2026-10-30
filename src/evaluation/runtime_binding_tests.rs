use super::*;
use crate::supervise::SupervisorRuntime;

fn pilot_manifest() -> ExperimentManifest {
    parse_observation_experiment_manifest(include_bytes!(
        "../../examples/supervise/model-mix-pilot-manifest.json"
    ))
    .unwrap()
}

fn direct_plan(dir: &std::path::Path) -> std::path::PathBuf {
    let mut plan: serde_json::Value =
        serde_json::from_slice(&caller_plan_document("direct-worker", false, false)).unwrap();
    plan["assignments"][0]["role"] = json!("worker");
    plan["assignments"][0]["role_category"] = json!("non_delegating_terminal_worker");
    plan["assignments"][0]["runtime"] = json!("grok");
    plan["assignments"][0]["worker_assignments"] = json!([]);
    let path = dir.join("provider-plan.json");
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    path
}

#[test]
fn pilot_manifest_validates_offline_with_three_fixed_budget_arms() {
    let manifest = pilot_manifest();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/supervise/model-mix-pilot-plan.json");
    let inputs = validate_held_out_comparison_inputs(&manifest, &path).unwrap();
    assert!(!inputs.production_eligible);
    assert_eq!(inputs.effective_plan_sha256.len(), 3);
    assert_eq!(
        inputs
            .effective_plan_sha256
            .values()
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    assert_eq!(manifest.repetitions, 1);
    assert_eq!(manifest.limits.wall_time_seconds, 3600);
    let plan: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(plan["run_budget"]["hard_tokens"], 160000);
    assert_eq!(plan["max_child_retries"], 0);
    assert_eq!(plan["max_gate_corrections"], 0);
    assert_eq!(plan["concurrency"]["max_concurrent_children"], 1);
    assert_eq!(plan["child_timeout_seconds"], 1200);
    assert!(plan.get("model_pricing").is_none());
    assert!(plan.get("pricing_contract").is_none());
    for profile in &manifest.profiles {
        assert!(profile
            .role_models
            .values()
            .all(|selection| selection.reasoning_effort.as_deref() == Some("xhigh")));
        for (role, selection) in &profile.role_models {
            if *role != AgentRole::Worker {
                assert_eq!(selection.model.as_deref(), Some("gpt-6.1-sol"));
            }
        }
    }
}

#[test]
fn runtime_overlay_preserves_common_plan_and_source_and_binds_all_interventions() {
    let manifest = pilot_manifest();
    let (_source, source_repo, base_commit) = init_committed_source_repo("baseline");
    let dir = tempfile::TempDir::new().unwrap();
    let path = direct_plan(dir.path());
    let original = fs::read(&path).unwrap();
    let frozen = crate::supervise::freeze_held_out_production_caller_plan(&path).unwrap();
    let source = HeldOutExplicitSourceBaseline {
        source_repo,
        base_commit,
    };
    let oid = resolve_held_out_explicit_source_baseline(&source).unwrap();
    let inputs = super::super::runtime_binding::comparison_inputs(
        &manifest,
        &frozen,
        Some(&source.source_repo),
    )
    .unwrap();
    let mut common = None;
    for profile in &manifest.profiles {
        let (isolated, bytes) = super::super::experiment::IsolatedSuperviseState::create_with_explicit_source_and_frozen_plan(&manifest, profile, 0, &source, oid, &frozen).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["assignments"][0]["runtime"],
            serde_json::to_value(profile.worker_runtime).unwrap()
        );
        assert_eq!(
            value["role_models"],
            serde_json::to_value(&profile.role_models).unwrap()
        );
        assert_eq!(
            git2::Repository::open(&isolated.repo)
                .unwrap()
                .head()
                .unwrap()
                .target(),
            Some(oid)
        );
        value.as_object_mut().unwrap().remove("role_models");
        value["assignments"][0]
            .as_object_mut()
            .unwrap()
            .remove("runtime");
        if let Some(expected) = &common {
            assert_eq!(expected, &value);
        }
        common.get_or_insert(value);
    }
    assert_eq!(original, fs::read(path).unwrap());
    let digest = super::super::runtime_binding::comparison_digest;
    let baseline = digest(
        &inputs,
        "commit-a",
        "tree-a",
        &json!({"codex":"/bound/codex"}),
    )
    .unwrap();
    assert_ne!(
        baseline,
        digest(
            &inputs,
            "commit-b",
            "tree-a",
            &json!({"codex":"/bound/codex"})
        )
        .unwrap()
    );
    assert_ne!(
        baseline,
        digest(
            &inputs,
            "commit-a",
            "tree-b",
            &json!({"codex":"/bound/codex"})
        )
        .unwrap()
    );
    assert_ne!(
        baseline,
        digest(
            &inputs,
            "commit-a",
            "tree-a",
            &json!({"codex":"/other/codex"})
        )
        .unwrap()
    );
    let mut changed = manifest.clone();
    changed.held_out_validation[0]
        .command
        .push("different-check".into());
    let changed =
        super::super::runtime_binding::comparison_inputs(&changed, &frozen, None).unwrap();
    assert_ne!(inputs.manifest_sha256, changed.manifest_sha256);
    assert_ne!(
        baseline,
        digest(
            &changed,
            "commit-a",
            "tree-a",
            &json!({"codex":"/bound/codex"})
        )
        .unwrap()
    );
}

#[test]
fn runtime_binding_refuses_partial_role_mismatch_fake_and_nonterminal_arms() {
    let manifest = pilot_manifest();
    let mut bad = manifest.clone();
    bad.profiles[1].worker_runtime = None;
    assert!(bad.validate_for_observation().is_err());
    let mut bad = manifest.clone();
    bad.profiles[1].role_models.remove(&AgentRole::Auditor);
    assert!(bad.validate_for_observation().is_err());
    let mut bad = manifest.clone();
    for profile in &mut bad.profiles {
        profile.role_models.remove(&AgentRole::Auditor);
    }
    assert!(bad.validate_for_observation().is_err());
    let mut bad = manifest.clone();
    bad.profiles[0].worker_runtime = Some(SupervisorRuntime::Fake);
    assert!(bad.validate_for_observation().is_err());
    assert!(manifest.validate().is_err());
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_caller_plan(dir.path(), "nested", false, false);
    assert!(validate_held_out_comparison_inputs(&manifest, &path)
        .unwrap_err()
        .to_string()
        .contains("direct non-delegating"));
}

#[test]
#[cfg(target_os = "linux")]
fn cross_runtime_unknown_identity_withholds_later_paid_cells_and_rejects_tampering() {
    let manifest = pilot_manifest();
    let (_source, source_repo, base_commit) = init_committed_source_repo("baseline");
    let dir = tempfile::TempDir::new().unwrap();
    let path = direct_plan(dir.path());
    let (_artifact, artifact_repo) = artifact_owner();
    let mut request = real_provider_request(
        HeldOutExplicitSourceBaseline {
            source_repo,
            base_commit,
        },
        path,
    );
    request.runtime = SupervisorRuntime::Codex;
    let mut calls = 0;
    let refused =
        super::super::executed_experiment::run_held_out_real_provider_experiment_with_dispatch(
            &manifest,
            request.clone(),
            &artifact_repo,
            |_, _, _| {
                panic!("missing allowlist must refuse before dispatch");
            },
        )
        .unwrap_err();
    assert!(refused.to_string().contains("allowlist"));
    no_reserved_runs(&artifact_repo);
    request
        .additional_runtime_executables
        .push(HeldOutAdditionalRuntimeBinding {
            runtime: SupervisorRuntime::Grok,
            executable: "/usr/bin/true".into(),
        });
    let _runtime_bindings = crate::supervise::bind_explicit_runtime_executables(
        &request.source.source_repo,
        &crate::orchestrator::RunId::new("held-out-runtime-binding-preflight").unwrap(),
        SupervisorRuntime::Codex,
        std::path::Path::new("/usr/bin/true"),
        &[(SupervisorRuntime::Grok, "/usr/bin/true".into())],
    )
    .unwrap();
    let results =
        super::super::executed_experiment::run_held_out_real_provider_experiment_with_dispatch(
            &manifest,
            request,
            &artifact_repo,
            |options, _, _| {
                calls += 1;
                let plan: serde_json::Value =
                    serde_json::from_slice(&fs::read(options.plan_file).unwrap()).unwrap();
                assert_eq!(plan["assignments"][0]["runtime"], "codex");
                anyhow::bail!("no provider invocation in offline test")
            },
        )
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(results.runs.len(), 3);
    assert!(
        !results.production_eligible
            && !results.eligible_for_production_economics
            && !results.eligible_to_justify_named_default
    );
    for run in &results.runs {
        let binding = run.profile_binding.as_ref().unwrap();
        assert_eq!(binding.roles.len(), manifest.profiles[0].role_models.len());
        assert!(binding
            .roles
            .values()
            .all(|role| role.observed_model.is_none()
                && role.observed_effort.is_none()
                && role.unavailable_reason.is_some()));
    }
    assert!(results.runs[1]
        .failure
        .as_ref()
        .unwrap()
        .contains("paid cell withheld"));
    let mut runs = results.runs.clone();
    runs[1].profile_binding.as_mut().unwrap().comparison_sha256 = "0".repeat(64);
    assert!(
        summarize_executed_observation_runs(&manifest, &results.manifest_sha256, &runs)
            .unwrap_err()
            .to_string()
            .contains("comparison hashes differ")
    );
    let mut runs = results.runs.clone();
    runs[1].profile_binding = None;
    assert!(
        summarize_executed_observation_runs(&manifest, &results.manifest_sha256, &runs).is_err()
    );
}
