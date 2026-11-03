//! Ordinary scheduler integration with deterministic, contained transport fixtures.
//! Synthetic account/catalog and report captures confer no live provider qualification.
use super::*;
use crate::supervise::selection_bridge::bind_test_selector_triple_catalog;
use std::os::unix::fs::PermissionsExt;

#[test]
fn codex_parent_grok_worker_uses_frozen_executables_and_independent_auditor() -> Result<()> {
    use crate::process_runner::{
        run_process, EnvironmentMode, ProcessSpec, SideEffectConfinementProfile, StdinMode,
        StreamCapture, StrictOfflineWorkspaceProfile,
    };
    if crate::test_containment::skip_current()? {
        return Ok(());
    }
    let (temp, repo) = injected_repository();
    let codex = temp.path().join("codex-fixture");
    let grok = temp.path().join("grok-fixture");
    // The provider shims consume a deterministic parent-authored report on stdin.
    // Only the Worker edits; the independently launched Auditor verifies the bytes.
    fs::write(&grok, "#!/bin/sh\nset -eu\nprintf 'baseline\\nHello from MACO\\n' > README.md\nIFS= read -r report\nprintf '%s\\n' \"$report\"\n")?;
    fs::write(&codex, "#!/bin/sh\nset -eu\n{ IFS= read -r first; IFS= read -r second; } < \"$1\"\n[ \"$first\" = baseline ]\n[ \"$second\" = 'Hello from MACO' ]\nIFS= read -r report\nprintf '%s\\n' \"$report\"\n")?;
    for path in [&codex, &grok] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let mut options = injected_options(&repo, temp.path(), "mixed-runtime-managed-process");
    options.codex_bin = codex.clone();
    let run_id = options.run_id.clone();
    let _binding = runtime_executables::bind_new(
        &repo,
        &run_id,
        SupervisorRuntime::Codex,
        &codex,
        &[(SupervisorRuntime::Grok, grok.clone())],
    )?;
    let mut loaded = plan_api::parse_supervisor_plan_with_consultant_in_repo(
        include_str!("../../../examples/supervise/mixed-codex-grok-plan.json"),
        Some(&repo),
    )?;
    // Keep a single independently selected parent lens, as the shared scheduler
    // fixtures do; all production lens eligibility and acceptance checks still run.
    loaded.plan.review_lenses = single_parent_acceptance_review_lenses();
    let assignment = loaded.plan.assignments[0].clone();
    let authored = loaded.plan.clone();
    let (_selector, catalog) = bind_test_selector_triple_catalog()?;
    let _cam =
        super::super::scheduler::install_positive_injected_mixed_runtime_fixture(&temp, &catalog)?;
    let calls = Mutex::new(Vec::new());
    let worker_report = Mutex::new(None);
    let candidate_path = Mutex::new(None::<PathBuf>);
    let runner = |command: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        let is_worker = command.agent_lifecycle.as_ref().unwrap().role == "worker";
        assert_eq!(
            command.program,
            if is_worker {
                grok.clone()
            } else {
                codex.clone()
            }
        );
        assert_ne!(command.cwd, repo);
        runtime_executables::validate_launch(command).unwrap();
        calls.lock().unwrap().push(if is_worker {
            "grok-worker"
        } else {
            "codex-auditor"
        });
        let payload = if is_worker {
            *candidate_path.lock().unwrap() = Some(command.cwd.join("README.md"));
            assert_eq!(
                command.invocation.adapter_id(),
                Some(crate::runtime_adapter::AdapterId::Grok)
            );
            let mut template = injected_assignment(true);
            template.worker_assignments[0].id = assignment.id.clone();
            let mut worker = injected_child_report(&template).worker_reports.remove(0);
            worker.assigned_paths = assignment.assigned_paths.clone();
            worker.files_changed = assignment.assigned_paths.clone();
            worker.claim_token = SyncStore::open(&repo)
                .unwrap()
                .snapshot()
                .unwrap()
                .iter()
                .find(|claim| claim.agent_id == assignment.id)
                .map(|claim| claim.token.get());
            let envelope = direct_worker_report_envelope(worker.clone());
            *worker_report.lock().unwrap() = Some(envelope);
            serde_json::to_vec(&worker).unwrap()
        } else {
            assert_eq!(
                command.invocation.adapter_id(),
                Some(crate::runtime_adapter::AdapterId::Codex)
            );
            serde_json::to_vec(&injected_auditor_report(
                &assignment,
                worker_report.lock().unwrap().as_ref().unwrap(),
            ))
            .unwrap()
        };
        let mut stdin = payload;
        stdin.push(b'\n');
        let mut profile = if is_worker {
            StrictOfflineWorkspaceProfile::read_write(&command.cwd)
        } else {
            StrictOfflineWorkspaceProfile::read_only(&command.cwd)
        }
        .with_visible_read_only_file(&command.program);
        let args = if is_worker {
            Vec::new()
        } else {
            let path = candidate_path.lock().unwrap().clone().unwrap();
            profile = profile.with_visible_read_only_file(&path);
            vec![path]
        };
        let output = run_process(
            ProcessSpec::direct(
                "mixed runtime fixture transport",
                &command.program,
                args,
                &command.cwd,
                65536,
            )
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_stdin(StdinMode::Bytes(stdin))
            .with_timeout(Some(Duration::from_secs(30)))
            .with_stdout(StreamCapture::bounded(65536))
            .with_side_effect_confinement(
                SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
            ),
        )
        .unwrap();
        assert!(
            output
                .status
                .as_ref()
                .is_some_and(|status| status.success()),
            "fixture failed: {output:?}"
        );
        assert!(output.process_tree.is_verified_empty());
        assert!(output.side_effects.is_verified());
        fs::write(&command.output_last_message, output.stdout.as_bytes()).unwrap();
        let mut run = injected_verified_run(command);
        run.process_tree = Some(output.process_tree);
        run.side_effects = Some(output.side_effects);
        run.stdout.target_launch_attempted = true;
        run.command = vec![command.program.to_string_lossy().into_owned()];
        run
    };
    let report = super::super::scheduler::run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
        &runner,
    )?;
    assert!(report.success, "mixed run failed: {report:#?}");
    assert_eq!(*calls.lock().unwrap(), ["grok-worker", "codex-auditor"]);
    assert_eq!(report.runtime, SupervisorRuntime::Codex);
    assert_eq!(fs::read(repo.join("README.md"))?, b"baseline\n");
    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)?;
    let frozen: Value = serde_json::from_slice(&reader.read("runtime_executables/binding.json")?)?;
    assert_eq!(frozen["bindings"][0]["runtime"], "codex");
    assert_eq!(frozen["bindings"][1]["runtime"], "grok");
    let saved: Value = serde_json::from_slice(&reader.read("assignments/supervisor-plan.json")?)?;
    assert_eq!(saved["assignments"][0]["runtime"], "grok");
    assert_eq!(saved["task"], authored.task);
    let (_restored, primary) =
        runtime_executables::bind_resume(&repo, &run_id, SupervisorRuntime::Codex, None, &[])?
            .context("restored allowlist")?;
    assert_eq!(primary, codex);
    Ok(())
}

#[test]
fn authored_missing_binding_is_refused_before_reservation() -> Result<()> {
    let (temp, repo) = injected_repository();
    let executable = temp.path().join("codex-fixture");
    fs::write(&executable, "#!/bin/sh\nexit 99\n")?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    let mut options = injected_options(&repo, temp.path(), "missing-grok-binding");
    options.codex_bin = executable.clone();
    let run_id = options.run_id.clone();
    let _binding =
        runtime_executables::bind_new(&repo, &run_id, SupervisorRuntime::Codex, &executable, &[])?;
    let loaded = plan_api::parse_supervisor_plan_with_consultant_in_repo(
        include_str!("../../../examples/supervise/mixed-codex-grok-plan.json"),
        Some(&repo),
    )?;
    let (_, catalog) = bind_test_selector_triple_catalog()?;
    let error = super::super::scheduler::run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
        &|_, _, _| panic!("missing binding must never dispatch"),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("has no frozen executable binding"));
    assert!(!repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str())
        .exists());
    Ok(())
}
