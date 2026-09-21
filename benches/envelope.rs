//! Finite 12-cell Git-native worktree + merge operating envelope.
//!
//! Cells (do not expand):
//!
//! 1. Lifecycle create → list_managed_verified → remove(force=true) concurrency 1 on S
//!
//! 2-3. Same lifecycle, disjoint agent_ids, concurrency 4 and 8 on S
//!
//! 4-5. Merge preview (claim + commit + preview_merge_apply_with_evidence, validation off)
//! concurrency 1 on S and M
//!
//! 6. Merge review+apply: CLI preview JSON watermark → CLI apply, concurrency 1 on S
//!
//! 7-8. Registry list with N∈{1,4} quiescent worktrees on S (list only)
//!
//! Optional probes (not extra factorial cells): 8-thread same-path claim overlap;
//! 5th create while 4 lanes are retained.

use crate::envelope_fixtures::{
    cli_merge_apply, create_managed, eprint_identity_once, force_remove, git_maco_state_bytes,
    prepare_merge_lane, preview_merge, reset_primary_hard, try_force_remove,
    write_cli_preview_watermark, EnvelopeRepo, MergeLane, OutcomeCounters, MEDIUM_CLAIM_PATH,
    SMALL_CLAIM_PATH,
};
use crate::{bound_group, RepositoryFixture};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use multi_agent_coding_orchestrator::{sync_store::SyncStore, worktree::WorktreeCreateOptions};
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
};

pub fn worktree_lifecycle_s(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("worktree_lifecycle_s");
    bound_group(&mut group);

    for worker_count in [1_usize, 4, 8] {
        let repo = EnvelopeRepo::small();
        eprint_identity_once(repo.repo_path());
        let agents = (0..worker_count)
            .map(|index| format!("life-{index}"))
            .collect::<Vec<_>>();
        let counters = OutcomeCounters::new();
        run_lifecycle_round(&repo, &agents, &counters);
        let (probe_ok, probe_err) = counters.snapshot();
        assert_eq!(probe_err, 0, "lifecycle probe must not fail");
        assert_eq!(probe_ok, worker_count as u64);
        if let Some(bytes) = git_maco_state_bytes(repo.repo_path()) {
            eprintln!(
                "coordination_envelope cell=lifecycle_s workers={worker_count} \
                 post_probe_git_maco_bytes={bytes} (optional authenticated-state growth)"
            );
        }

        group.throughput(Throughput::Elements(worker_count as u64));
        group.bench_with_input(
            BenchmarkId::new("create_list_force_remove", worker_count),
            &worker_count,
            |bencher, &_count| {
                bencher.iter(|| {
                    run_lifecycle_round(&repo, &agents, &counters);
                });
            },
        );
        let (success, failure) = counters.snapshot();
        eprintln!(
            "coordination_envelope cell=lifecycle_s workers={worker_count} \
             success={success} failure={failure} (includes Criterion warmup)"
        );
    }

    group.finish();
}

fn run_lifecycle_round(repo: &EnvelopeRepo, agents: &[String], counters: &OutcomeCounters) {
    let barrier = Arc::new(Barrier::new(agents.len()));
    std::thread::scope(|scope| {
        for agent in agents {
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let manager = repo.manager();
                barrier.wait();
                match manager.create(WorktreeCreateOptions {
                    agent_id: agent.clone(),
                    branch: None,
                    base: None,
                    worktree_root: Some(repo.worktree_root.clone()),
                }) {
                    Ok(created) => {
                        let listed = manager
                            .list_managed_verified()
                            .expect("list_managed_verified after create");
                        assert!(
                            listed.iter().any(|record| record.name == created.name),
                            "created worktree {} missing from verified list",
                            created.name
                        );
                        black_box(listed);
                        manager
                            .remove(agent, true, true)
                            .expect("force-remove managed worktree");
                        counters.record_ok();
                    }
                    Err(error) => {
                        counters.record_err();
                        panic!("managed worktree create failed for {agent}: {error:#}");
                    }
                }
            });
        }
    });
}

pub fn merge_preview(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("merge_preview");
    bound_group(&mut group);

    for (label, repo, claim) in [
        ("S", EnvelopeRepo::small(), SMALL_CLAIM_PATH),
        ("M", EnvelopeRepo::medium(), MEDIUM_CLAIM_PATH),
    ] {
        eprint_identity_once(repo.repo_path());
        let lane = prepare_merge_lane(repo, claim);
        assert!(
            lane.worktree.path.exists(),
            "managed merge worktree must exist for preview"
        );
        let probe = preview_merge(&lane);
        black_box(probe);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("preview_validation_off", label),
            &(),
            |bencher, _| {
                bencher.iter(|| black_box(preview_merge(&lane)));
            },
        );
        force_remove(&lane.repo, &lane.agent_id);
    }

    group.finish();
}

pub fn merge_review_apply_s(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("merge_review_apply_s");
    bound_group(&mut group);

    let lane = prepare_merge_lane(EnvelopeRepo::small(), SMALL_CLAIM_PATH);
    eprint_identity_once(lane.repo.repo_path());
    let watermark_path = lane.repo.scratch_path().join("reviewed-preview.json");
    let counters = OutcomeCounters::new();
    run_review_apply(&lane, &watermark_path, &counters);
    reset_primary_hard(lane.repo.repo_path());
    let (probe_ok, probe_err) = counters.snapshot();
    assert_eq!(probe_err, 0);
    assert_eq!(probe_ok, 1);

    group.throughput(Throughput::Elements(1));
    group.bench_function("preview_watermark_cli_apply", |bencher| {
        bencher.iter_batched(
            || {
                reset_primary_hard(lane.repo.repo_path());
            },
            |_| {
                run_review_apply(&lane, &watermark_path, &counters);
            },
            BatchSize::PerIteration,
        );
    });
    let (success, failure) = counters.snapshot();
    eprintln!(
        "coordination_envelope cell=6_review_apply_s success={success} failure={failure} \
         (includes Criterion warmup); apply uses CLI not public apply_merge_result"
    );
    reset_primary_hard(lane.repo.repo_path());
    force_remove(&lane.repo, &lane.agent_id);
    group.finish();
}

fn run_review_apply(
    lane: &MergeLane,
    watermark_path: &std::path::Path,
    counters: &OutcomeCounters,
) {
    write_cli_preview_watermark(lane, watermark_path);
    let report = cli_merge_apply(lane, watermark_path);
    counters.record_ok();
    black_box(report);
}

pub fn worktree_list_quiescent_s(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("worktree_list_quiescent_s");
    bound_group(&mut group);

    for count in [1_usize, 4] {
        let repo = EnvelopeRepo::small();
        eprint_identity_once(repo.repo_path());
        let agents = (0..count)
            .map(|index| format!("quiet-{index}"))
            .collect::<Vec<_>>();
        for agent in &agents {
            create_managed(&repo, agent);
        }
        let probe = repo
            .manager()
            .list_managed_verified()
            .expect("probe quiescent list");
        assert_eq!(probe.len(), count);
        black_box(probe);

        group.throughput(Throughput::Elements(1));
        let manager = repo.manager();
        group.bench_with_input(
            BenchmarkId::new("list_managed_verified", count),
            &count,
            |bencher, &count| {
                bencher.iter(|| {
                    let listed = manager
                        .list_managed_verified()
                        .expect("list quiescent managed worktrees");
                    assert_eq!(listed.len(), count);
                    black_box(listed)
                });
            },
        );

        for agent in &agents {
            force_remove(&repo, agent);
        }
    }

    group.finish();
}

pub fn envelope_probes(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("envelope_probes");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::claims();
        eprint_identity_once(&fixture.repo_path);
        let stores = (0..8)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open overlap SyncStore"))
            .collect::<Vec<_>>();
        let agents = (0..8)
            .map(|index| format!("overlap-{index}"))
            .collect::<Vec<_>>();
        let counters = OutcomeCounters::new();
        run_same_path_overlap(&stores, &agents, "src/lib.rs", &counters);
        let (probe_ok, probe_err) = counters.snapshot();
        assert_eq!(
            probe_ok, 1,
            "exactly one overlapping same-path claim must succeed while others are held"
        );
        assert_eq!(
            probe_err, 7,
            "the other seven overlapping same-path claims must be refused"
        );
        eprintln!(
            "coordination_envelope probe=same_path_claim_x8 probe_success={probe_ok} \
             probe_failure={probe_err}"
        );

        group.throughput(Throughput::Elements(8));
        group.bench_function("same_path_claim_threads_8", |bencher| {
            bencher.iter(|| {
                run_same_path_overlap(&stores, &agents, "src/lib.rs", &counters);
            });
        });
        let (success, failure) = counters.snapshot();
        eprintln!(
            "coordination_envelope probe=same_path_claim_x8 success={success} failure={failure} \
             (includes Criterion warmup)"
        );
    }

    {
        let repo = EnvelopeRepo::small();
        let retained = ["keep-0", "keep-1", "keep-2", "keep-3"];
        for agent in retained {
            create_managed(&repo, agent);
        }
        let fifth = "keep-4";
        create_managed(&repo, fifth);
        force_remove(&repo, fifth);
        let listed = repo
            .manager()
            .list_managed_verified()
            .expect("four retained lanes");
        assert_eq!(listed.len(), 4);

        group.throughput(Throughput::Elements(1));
        group.bench_function("fifth_create_with_four_retained", |bencher| {
            bencher.iter_batched(
                || {
                    if repo
                        .manager()
                        .list_managed_verified()
                        .expect("inspect fifth lane")
                        .iter()
                        .any(|record| record.name == fifth)
                    {
                        force_remove(&repo, fifth);
                    }
                },
                |_| {
                    black_box(create_managed(&repo, fifth));
                },
                BatchSize::PerIteration,
            );
        });
        let _ = try_force_remove(&repo, fifth);
        for agent in retained {
            force_remove(&repo, agent);
        }
    }

    group.finish();
}

fn run_same_path_overlap(
    stores: &[SyncStore],
    agents: &[String],
    path: &str,
    counters: &OutcomeCounters,
) {
    let start = Arc::new(Barrier::new(stores.len()));
    let attempted = Arc::new(Barrier::new(stores.len()));
    std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(stores.len());
        for (store, agent) in stores.iter().zip(agents) {
            let start = Arc::clone(&start);
            let attempted = Arc::clone(&attempted);
            workers.push(scope.spawn(move || {
                start.wait();
                match store.claim_paths(agent, [path]) {
                    Ok(claim) => {
                        counters.record_ok();
                        attempted.wait();
                        store
                            .release(claim.token)
                            .expect("release successful overlap claim");
                    }
                    Err(error) => {
                        counters.record_err();
                        assert!(
                            error.to_string().contains("already claimed"),
                            "unexpected overlap refusal: {error:#}"
                        );
                        attempted.wait();
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().expect("join same-path overlap worker");
        }
    });
}
