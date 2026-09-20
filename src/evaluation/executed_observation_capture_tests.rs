//! Integration tests for `run_experiment_with_held_out` → capture → summary wiring.

use super::super::{
    executed_measurements::{
        observed_run_measurements_from_retained_supervisor_final_report,
        parent_review_capture_proven, ParentReviewCaptureObservation,
    },
    executed_summary::{
        summarize_executed_observation_runs, ExecutedAcceptedQualityStatus,
        ExecutedObservationParetoStatus,
    },
    experiment::ExperimentRunRequest,
    run_experiment_with_held_out, CommandObservationStatus, ExecutedExperimentResults,
    ExperimentManifest,
};
use super::experiment_manifest;
use crate::{
    artifacts::{ArtifactRunReader, RunArtifactFamily},
    orchestrator::RunId,
};
use std::collections::BTreeSet;

fn artifact_owner() -> (tempfile::TempDir, std::path::PathBuf) {
    let workspace = tempfile::TempDir::new().expect("artifact workspace");
    let repo = workspace.path().join("artifact-owner");
    git2::Repository::init(&repo).expect("artifact repo");
    (workspace, repo)
}

fn two_profile_held_out_manifest(repetitions: u32) -> ExperimentManifest {
    let mut manifest = experiment_manifest();
    manifest.repetitions = repetitions;
    // Child + held-out command + stacked parent-acceptance/output-only/diff-only auditors.
    manifest.limits.max_dispatches = 8;
    manifest
}

fn run_fake_held_out_observation(
    manifest: &ExperimentManifest,
) -> (tempfile::TempDir, ExecutedExperimentResults) {
    let (workspace, artifact_repo) = artifact_owner();
    let results =
        run_experiment_with_held_out(manifest, ExperimentRunRequest::default(), &artifact_repo)
            .expect("held-out Fake observation experiment");
    (workspace, results)
}

fn retained_supervisor_report_bytes(
    artifact_repo: &std::path::Path,
    results: &ExecutedExperimentResults,
    run_index: usize,
) -> Vec<u8> {
    let run = &results.runs[run_index];
    let evidence = run
        .supervisor_evidence
        .as_ref()
        .expect("retained supervisor evidence path");
    let run_id = RunId::new(&results.artifact_run_id).expect("artifact run id");
    let reader = ArtifactRunReader::open(artifact_repo, RunArtifactFamily::Supervise, &run_id)
        .expect("artifact reader");
    reader
        .read(evidence)
        .expect("retained supervisor-final bytes")
}

#[test]
fn held_out_fake_entrypoint_crosses_run_finalize_and_emits_observation_v3_summary() {
    let manifest = two_profile_held_out_manifest(1);
    let (workspace, results) = run_fake_held_out_observation(&manifest);
    let artifact_repo = workspace.path().join("artifact-owner");

    assert_eq!(results.schema, "evaluation_experiment_observations_v3");
    assert_eq!(results.runs.len(), manifest.profiles.len());
    assert!(!results.profile_summaries.is_empty());
    assert!(results.observation_pareto_conclusion.is_some());
    assert!(
        !results.production_eligible
            && !results.real_provider_executed
            && results.confidence.is_none()
    );

    let baseline = &results.runs[0].held_out.run;
    for run in &results.runs {
        assert!(run.held_out.passed(), "{run:?}");
        assert!(
            run.held_out
                .commands
                .iter()
                .all(|cmd| cmd.observation.status == CommandObservationStatus::Passed),
            "{run:?}"
        );
        assert_eq!(run.held_out.run.baseline_head, baseline.baseline_head);
        assert_eq!(run.held_out.run.baseline_tree, baseline.baseline_tree);
        assert!(run.supervisor_evidence.is_some(), "{run:?}");
        let measurements = run.measurements.as_ref().expect("parent measurements");
        assert_eq!(measurements.manifest_sha256, results.manifest_sha256);
        assert_ne!(
            measurements
                .parent_review_capture_unavailable_reason
                .as_deref(),
            Some("retained supervisor-final bytes do not match the live parent supervisor report")
        );
    }

    let reserialized =
        summarize_executed_observation_runs(&manifest, &results.manifest_sha256, &results.runs)
            .expect("re-summarize entrypoint runs");
    assert_eq!(
        reserialized.profile_summaries.len(),
        results.profile_summaries.len()
    );

    let run_id = RunId::new(&results.artifact_run_id).expect("artifact run id");
    let reader = ArtifactRunReader::open(&artifact_repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized artifact run");
    let on_disk: ExecutedExperimentResults = serde_json::from_slice(
        &reader
            .read(RunArtifactFamily::Supervise.final_report_relative_path())
            .expect("final observation report bytes"),
    )
    .expect("parse finalized observation report");
    assert_eq!(on_disk.schema, results.schema);
    assert_eq!(
        on_disk.profile_summaries.len(),
        results.profile_summaries.len()
    );

    let wire = serde_json::to_vec(&results).expect("serialize observation results");
    let decoded: ExecutedExperimentResults =
        serde_json::from_slice(&wire).expect("deserialize observation results");
    for run in &decoded.runs {
        let measurements = run
            .measurements
            .as_ref()
            .expect("measurements survive wire");
        assert!(measurements.parent_review_capture_proof.is_none());
        assert!(
            !parent_review_capture_proven(measurements, &run.held_out),
            "serde cannot restore in-process proof"
        );
    }

    let bytes = retained_supervisor_report_bytes(&artifact_repo, &results, 0);
    let held_out = results.runs[0].held_out.clone();
    let replay = observed_run_measurements_from_retained_supervisor_final_report(
        &held_out,
        &bytes,
        &artifact_repo,
        &BTreeSet::new(),
    )
    .expect("byte-only replay lift");
    assert_eq!(
        replay.parent_review_capture,
        ParentReviewCaptureObservation::UnprovenAfterDeserialize
    );
    assert!(!parent_review_capture_proven(&replay, &held_out));
}

#[test]
fn held_out_fake_entrypoint_proven_capture_seals_parent_review_when_supervisor_succeeds() {
    let manifest = two_profile_held_out_manifest(1);
    let (_workspace, results) = run_fake_held_out_observation(&manifest);

    let proven_runs = results
        .runs
        .iter()
        .filter(|run| {
            run.supervisor_succeeded
                && run.measurements.as_ref().is_some_and(|measurements| {
                    measurements.parent_review_capture
                        == ParentReviewCaptureObservation::ProvenAtCapture
                })
        })
        .count();
    assert!(
        proven_runs > 0,
        "expected at least one in-process parent review capture; runs={:?}",
        results
            .runs
            .iter()
            .map(|run| (
                run.supervisor_succeeded,
                run.measurements.as_ref().map(|m| m.parent_review_capture),
                run.measurements
                    .as_ref()
                    .and_then(|m| m.parent_review_capture_unavailable_reason.clone()),
            ))
            .collect::<Vec<_>>()
    );

    for run in &results.runs {
        let measurements = run.measurements.as_ref().expect("measurements");
        if measurements.parent_review_capture == ParentReviewCaptureObservation::ProvenAtCapture {
            assert!(parent_review_capture_proven(measurements, &run.held_out));
            let mut tampered = measurements.clone();
            tampered.manifest_sha256 = "0".repeat(64);
            assert!(!parent_review_capture_proven(&tampered, &run.held_out));
        }
    }
}

#[test]
fn held_out_fake_entrypoint_honest_unknown_reported_cost_refuses_observation_pareto() {
    let manifest = two_profile_held_out_manifest(1);
    let (_workspace, results) = run_fake_held_out_observation(&manifest);

    let pareto = results
        .observation_pareto_conclusion
        .as_ref()
        .expect("pareto conclusion");
    assert_ne!(
        pareto.status,
        ExecutedObservationParetoStatus::Available,
        "Fake held-out observation does not license provider-quality Pareto"
    );
    assert!(results.observation_pareto_frontier.is_empty());
    assert!(results.quality.is_none());
}

#[test]
fn held_out_fake_entrypoint_unknown_cost_stays_unknown_across_repetition_order() {
    let manifest = two_profile_held_out_manifest(2);
    let (_workspace, results) = run_fake_held_out_observation(&manifest);
    assert_eq!(results.runs.len(), 4);

    let forward = results.runs.clone();
    let mut reverse = results.runs.clone();
    reverse.reverse();
    for mut runs in [forward, reverse] {
        if let Some(run) = runs.iter_mut().find(|run| run.held_out.run.repetition == 0) {
            run.measurements.as_mut().unwrap().total_cost_usd = None;
        }
        let summary =
            summarize_executed_observation_runs(&manifest, &results.manifest_sha256, &runs)
                .expect("summarize with one unknown cost cell");
        for profile in &manifest.profiles {
            let profile_summary = summary
                .profile_summaries
                .iter()
                .find(|summary| summary.profile_id == profile.id)
                .expect("profile summary");
            assert!(
                profile_summary.aggregate_reported_cost_usd.is_none(),
                "profile {}",
                profile.id
            );
        }
    }
}

#[test]
fn held_out_fake_entrypoint_quality_proxy_requires_proven_review_not_byte_replay() {
    let manifest = two_profile_held_out_manifest(1);
    let (workspace, results) = run_fake_held_out_observation(&manifest);
    let artifact_repo = workspace.path().join("artifact-owner");

    let mut replay_runs = results.runs.clone();
    for (index, run) in replay_runs.iter_mut().enumerate() {
        let bytes = retained_supervisor_report_bytes(&artifact_repo, &results, index);
        let replay = observed_run_measurements_from_retained_supervisor_final_report(
            &run.held_out,
            &bytes,
            &artifact_repo,
            &BTreeSet::new(),
        )
        .expect("replay bytes");
        assert_eq!(
            replay.parent_review_capture,
            ParentReviewCaptureObservation::UnprovenAfterDeserialize
        );
        let measurements = run.measurements.as_mut().expect("measurements");
        *measurements = replay;
        measurements.parent_review_capture = ParentReviewCaptureObservation::ProvenAtCapture;
        measurements.parent_review_capture_proof = None;
    }
    let summary =
        summarize_executed_observation_runs(&manifest, &results.manifest_sha256, &replay_runs)
            .expect("summarize replay-forged runs");
    assert!(
        summary
            .profile_summaries
            .iter()
            .any(|profile| profile.accepted_quality.status != ExecutedAcceptedQualityStatus::Known),
        "byte replay cannot license qualified accepted-quality"
    );
    assert!(summary.pareto_frontier.is_empty());
}
