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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentityReceiptCase {
    AppServer,
    Exec,
    ServedMismatch,
    EffortMismatch,
    RequestedMismatch,
    Missing,
    MissingSummary,
    SummaryMismatch,
    Tampered,
    UnknownRetry,
    WrongRole,
    WrongRuntime,
    WrongRun,
    WrongReportRun,
    Grok,
    LabelsOnly,
}

/// Synthetic parent receipts exercise capture and withholding without starting a provider.
#[cfg(target_os = "linux")]
fn identity_receipt_experiment(case: IdentityReceiptCase) -> (ExecutedExperimentResults, usize) {
    use crate::artifacts::{
        state_auth::sha256_hex, ArtifactFileDisposition, ArtifactRunWriter, RunArtifactFamily,
    };
    use crate::supervise::{
        HeldOutProductionExperimentOutcome, HeldOutProductionLaunchObservation,
        SupervisorFinalReport, SupervisorPlan,
    };
    let mut manifest = pilot_manifest();
    let template = manifest.profiles[0].clone();
    for profile in &mut manifest.profiles {
        profile.role_models = template.role_models.clone();
        profile.worker_runtime = template.worker_runtime;
        if case == IdentityReceiptCase::Grok {
            profile.worker_runtime = Some(SupervisorRuntime::Grok);
            profile
                .role_models
                .get_mut(&AgentRole::Worker)
                .unwrap()
                .model = Some("grok-4.6".into());
        }
    }
    let (_source, source_repo, base_commit) = init_committed_source_repo("baseline");
    let plans = tempfile::TempDir::new().unwrap();
    let (_artifact, artifact_repo) = artifact_owner();
    let mut request = real_provider_request(
        HeldOutExplicitSourceBaseline {
            source_repo,
            base_commit,
        },
        direct_plan(plans.path()),
    );
    request.runtime = SupervisorRuntime::Codex;
    if case == IdentityReceiptCase::Grok {
        request
            .additional_runtime_executables
            .push(HeldOutAdditionalRuntimeBinding {
                runtime: SupervisorRuntime::Grok,
                executable: "/usr/bin/true".into(),
            });
    }
    let _runtime_bindings = (case == IdentityReceiptCase::Grok).then(|| {
        crate::supervise::bind_explicit_runtime_executables(
            &request.source.source_repo,
            &crate::orchestrator::RunId::new("held-out-runtime-binding-preflight").unwrap(),
            SupervisorRuntime::Codex,
            std::path::Path::new("/usr/bin/true"),
            &[(SupervisorRuntime::Grok, "/usr/bin/true".into())],
        )
        .unwrap()
    });
    let mut calls = 0;
    let results = super::super::executed_experiment::run_held_out_real_provider_experiment_with_dispatch(
        &manifest, request, &artifact_repo, |options, _, _| {
            calls += 1;
            let plan: SupervisorPlan = serde_json::from_slice(&fs::read(&options.plan_file)?).unwrap();
            let mut writer = ArtifactRunWriter::reserve(&options.repo, RunArtifactFamily::Supervise, options.run_id.clone(), "synthetic-identity-test")?;
            let mut tamper_path = None;
            for (role, selection) in &plan.role_models {
                let worker = *role == AgentRole::Worker;
                let runtime = if worker { plan.assignments[0].runtime.unwrap() } else { options.runtime };
                let attempts = if worker && case == IdentityReceiptCase::UnknownRetry { 2 } else { 1 };
                for attempt in 1..=attempts {
                    let path = format!("logs/{}.attempt-{attempt}.summary.json", role.as_str());
                    let observed_model = if worker && case == IdentityReceiptCase::ServedMismatch { "other-model" } else { selection.model.as_deref().unwrap() };
                    let mut summary = json!({
                        "codex_parent_evidence": {
                            "codex_version":"0.162.0", "thread_id":format!("thread-{}-{attempt}", role.as_str()),
                            "requested_model":selection.model, "requested_effort":selection.reasoning_effort,
                            "rollout_model":"unknown", "rollout_effort":"unknown",
                            "observed_model":{"known":observed_model}, "observed_effort":{"known":"xhigh"},
                            "server_rerouted_model":null, "model_mismatch":false,
                            "turn_usage":{"status":"known","input_tokens":10,"output_tokens":4,"cached_input_tokens":0,"reasoning_output_tokens":1},
                            "resolution_status":"complete"
                        }
                    });
                    if case == IdentityReceiptCase::Exec {
                        summary["codex_parent_evidence"]["rollout_model"] = json!({"known":observed_model});
                        summary["codex_parent_evidence"]["rollout_effort"] = json!({"known":"xhigh"});
                    }
                    if worker && case == IdentityReceiptCase::RequestedMismatch {
                        summary["codex_parent_evidence"]["requested_effort"] = json!("low");
                    }
                    if worker && case == IdentityReceiptCase::EffortMismatch {
                        summary["codex_parent_evidence"]["observed_effort"] = json!({"known":"low"});
                    }
                    if worker && case == IdentityReceiptCase::Grok {
                        summary = json!({"runtime_identity":{
                            "requested_model":selection.model,"requested_effort":selection.reasoning_effort,
                            "model":"grok-4.6-build","effort":null
                        }});
                    }
                    if (worker && case == IdentityReceiptCase::LabelsOnly) || attempt == 2 {
                        summary = json!({"models":[selection.model],"model":selection.model,"reasoning_effort":"xhigh"});
                    }
                    let bytes = serde_json::to_vec(&summary)?;
                    if !(worker && case == IdentityReceiptCase::MissingSummary) {
                        writer.write_bytes(&path, &bytes, ArtifactFileDisposition::PrivateEvidence)?;
                    }
                    if !(worker && case == IdentityReceiptCase::Missing) {
                        let receipt = json!({
                            "version":1,
                            "binding":{
                                "run_id":if worker && case == IdentityReceiptCase::WrongRun { "another-run" } else { options.run_id.as_str() },
                                "task_id":role.as_str(), "parent":null, "attempt":attempt,
                                "role":if worker && case == IdentityReceiptCase::WrongRole { "auditor" } else { role.as_str() },
                                "runtime":if worker && case == IdentityReceiptCase::WrongRuntime { SupervisorRuntime::Grok } else { runtime },
                                "command_summary":path
                            },
                            "command_summary_sha256":if worker && case == IdentityReceiptCase::SummaryMismatch { "0".repeat(64) } else { sha256_hex(&bytes) }, "target_launch_attempted":true,
                            "target_process_tree":{"status":"unknown"}, "target_side_effects":{"status":"unknown"}
                        });
                        writer.write_json(std::path::Path::new(&path).with_extension("target-containment.json"), &receipt, ArtifactFileDisposition::PrivateEvidence)?;
                    }
                    if worker && case == IdentityReceiptCase::Tampered {
                        tamper_path = Some(writer.run_dir().join(path));
                    }
                }
            }
            let mut report: SupervisorFinalReport = serde_json::from_slice(&super::super::executed_measurements::supervisor_final_report_execution_fixture_bytes())?;
            report.run_id = options.run_id;
            if case == IdentityReceiptCase::WrongReportRun {
                report.run_id = crate::orchestrator::RunId::new("another-run").unwrap();
            }
            report.runtime = options.runtime;
            // Deliberately misleading role labels never override native observations.
            report.role_usage.insert(AgentRole::Worker, crate::supervise::RoleUsageReport {
                models: vec!["label-only-model".into()], usage: None, cost_usd: None,
                observation: crate::supervise::RoleUsageObservation::ProcessObserved, unavailable_reason: None,
            });
            let report_path = RunArtifactFamily::Supervise.final_report_relative_path();
            writer.write_json(&report_path, &report, ArtifactFileDisposition::PrivateEvidence)?;
            writer.finalize(&report_path, false)?;
            if let Some(path) = tamper_path { fs::write(path, b"tampered")?; }
            Ok(HeldOutProductionExperimentOutcome {
                report: Ok(report),
                launch: HeldOutProductionLaunchObservation { target_launch_attempted:false, native_runtime_result_captured:false },
            })
        },
    ).unwrap();
    assert!(
        !results.real_provider_executed
            && !results.production_eligible
            && !results.eligible_for_production_economics
            && !results.eligible_to_justify_named_default
    );
    (results, calls)
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_codex_role_receipts_project_app_server_and_exec_identity() {
    for case in [IdentityReceiptCase::AppServer, IdentityReceiptCase::Exec] {
        let (results, calls) = identity_receipt_experiment(case);
        assert_eq!(
            calls, 3,
            "complete matching identity should not withhold the next cell"
        );
        for run in &results.runs {
            for role in run.profile_binding.as_ref().unwrap().roles.values() {
                assert_eq!(role.observed_model.as_deref(), Some("gpt-6.1-sol"));
                assert_eq!(role.observed_effort.as_deref(), Some("xhigh"));
                assert!(role.unavailable_reason.is_none());
            }
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_role_receipts_refuse_mismatch_and_withhold_later_cells() {
    for case in [
        IdentityReceiptCase::ServedMismatch,
        IdentityReceiptCase::EffortMismatch,
        IdentityReceiptCase::RequestedMismatch,
        IdentityReceiptCase::WrongRole,
        IdentityReceiptCase::WrongRuntime,
        IdentityReceiptCase::WrongRun,
        IdentityReceiptCase::WrongReportRun,
    ] {
        let (results, calls) = identity_receipt_experiment(case);
        assert_eq!(calls, 1);
        let role = &results.runs[0].profile_binding.as_ref().unwrap().roles[&AgentRole::Worker];
        assert!(role.observed_model.is_none() && role.observed_effort.is_none());
        assert!(role.unavailable_reason.is_some());
        assert!(results.runs[1]
            .failure
            .as_deref()
            .unwrap()
            .contains("paid cell withheld"));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_role_receipts_missing_tampered_or_unknown_retry_stay_unknown() {
    for case in [
        IdentityReceiptCase::Missing,
        IdentityReceiptCase::Tampered,
        IdentityReceiptCase::MissingSummary,
        IdentityReceiptCase::SummaryMismatch,
        IdentityReceiptCase::UnknownRetry,
        IdentityReceiptCase::LabelsOnly,
    ] {
        let (results, calls) = identity_receipt_experiment(case);
        assert_eq!(calls, 1);
        let role = &results.runs[0].profile_binding.as_ref().unwrap().roles[&AgentRole::Worker];
        assert!(role.observed_model.is_none() && role.observed_effort.is_none());
        assert!(role.unavailable_reason.is_some());
        assert!(results.runs[1]
            .failure
            .as_deref()
            .unwrap()
            .contains("paid cell withheld"));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_grok_role_receipt_projects_model_only_and_withholds_later_cells() {
    let (results, calls) = identity_receipt_experiment(IdentityReceiptCase::Grok);
    assert_eq!(calls, 1);
    let role = &results.runs[0].profile_binding.as_ref().unwrap().roles[&AgentRole::Worker];
    assert_eq!(role.observed_model.as_deref(), Some("grok-4.6-build"));
    assert!(role.observed_effort.is_none() && role.unavailable_reason.is_some());
    assert!(results.runs[1]
        .failure
        .as_deref()
        .unwrap()
        .contains("paid cell withheld"));
}
