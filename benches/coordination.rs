//! Reproducible Criterion baselines for MACO's public coordination substrate.
//!
//! Every timed case completes a successful public-API operation. Managed
//! worktree and merge throughput are intentionally absent because their public
//! entrypoints cannot construct the required capability-bound worktree today.

#[path = "../tests/support/containment.rs"]
mod containment;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use git2::{IndexAddOption, Oid, Repository, RepositoryInitOptions, Signature};
use multi_agent_coding_orchestrator::{
    repo_map,
    repo_semantic::{self, SemanticRepoMap},
    sync_store::SyncStore,
};
use std::{
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Barrier},
    time::Duration,
};
use tempfile::{tempdir, TempDir};

const SAMPLE_SIZE: usize = 10;
const WARM_UP_TIME: Duration = Duration::from_millis(300);
const MEASUREMENT_TIME: Duration = Duration::from_millis(700);
#[cfg(target_os = "linux")]
const FORCE_CONTAINMENT_UNAVAILABLE_ENV: &str = "MACO_BENCH_FORCE_CONTAINMENT_UNAVAILABLE";

struct RepositoryFixture {
    _temp: TempDir,
    repo_path: PathBuf,
}

impl RepositoryFixture {
    fn claims() -> Self {
        Self::with_files(&[
            ("Cargo.toml", "[package]\nname = \"bench-fixture\"\n"),
            ("README.md", "# Benchmark fixture\n"),
            ("src/lib.rs", "pub fn fixture() {}\n"),
            ("src/main.rs", "fn main() {}\n"),
        ])
    }

    fn repository_map() -> Self {
        Self::with_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"bench-fixture\"\nversion = \"0.1.0\"\n",
            ),
            ("README.md", "# Benchmark fixture\n"),
            (
                "src/lib.rs",
                "pub mod api;\npub use crate::api::endpoint;\n",
            ),
            (
                "src/api.rs",
                "pub struct Api;\npub fn endpoint() -> Api { Api }\n",
            ),
        ])
    }

    fn with_files(files: &[(&str, &str)]) -> Self {
        let temp = tempdir().expect("create benchmark tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir_all(&repo_path).expect("create benchmark repository directory");

        let mut options = RepositoryInitOptions::new();
        options.initial_head("main");
        let repo = Repository::init_opts(&repo_path, &options)
            .expect("initialize benchmark git repository");
        for (relative, contents) in files {
            write_file(&repo_path, relative, contents);
        }
        commit_all(&repo, "initialize benchmark fixture");
        drop(repo);

        Self {
            _temp: temp,
            repo_path,
        }
    }
}

fn write_file(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create benchmark fixture parent");
    }
    fs::write(path, contents).expect("write benchmark fixture file");
}

fn commit_all(repo: &Repository, message: &str) -> Oid {
    let mut index = repo.index().expect("open benchmark repository index");
    index
        .add_all(["*"], IndexAddOption::DEFAULT, None)
        .expect("stage benchmark fixture");
    index.write().expect("write benchmark repository index");
    let tree_id = index.write_tree().expect("write benchmark fixture tree");
    let tree = repo
        .find_tree(tree_id)
        .expect("find benchmark fixture tree");
    let signature = Signature::now("maco benchmark", "maco-benchmark@example.invalid")
        .expect("create benchmark signature");
    repo.commit(Some("HEAD"), &signature, &signature, message, &tree, &[])
        .expect("commit benchmark fixture")
}

fn bound_group(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group
        .sample_size(SAMPLE_SIZE)
        .warm_up_time(WARM_UP_TIME)
        .measurement_time(MEASUREMENT_TIME);
}

fn assert_single_claim_round_trip(store: &SyncStore, agent: &str, path: &str) {
    let claim = store
        .claim_paths(agent, [path])
        .expect("public SyncStore claim must succeed");
    let released = store
        .release(claim.token)
        .expect("public SyncStore release must succeed");
    assert_eq!(released, claim);
}

fn claim_acquire_release(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_acquire_release");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::claims();
        let store = SyncStore::open(&fixture.repo_path).expect("open single-claim SyncStore");
        assert_single_claim_round_trip(&store, "probe-single", "src/lib.rs");

        group.bench_function("single_path_release_by_token", |bencher| {
            bencher.iter(|| {
                let claim = store
                    .claim_paths("bench-single", ["src/lib.rs"])
                    .expect("acquire single-path claim");
                let released = store
                    .release(claim.token)
                    .expect("release single-path claim by token");
                black_box(released)
            });
        });
    }

    {
        let fixture = RepositoryFixture::claims();
        let store = SyncStore::open(&fixture.repo_path).expect("open batch-claim SyncStore");
        let paths = [
            "src/lib.rs",
            "src/main.rs",
            "tests/coordination.rs",
            "README.md",
        ];
        let probe = store
            .claim_paths("probe-batch", paths)
            .expect("public four-path claim must succeed");
        let probe_released = store
            .release_by_agent("probe-batch")
            .expect("public release_by_agent must succeed");
        assert_eq!(probe_released, vec![probe]);

        group.bench_function("four_paths_release_by_agent", |bencher| {
            bencher.iter(|| {
                let claim = store
                    .claim_paths("bench-batch", paths)
                    .expect("acquire four-path claim");
                let released = store
                    .release_by_agent("bench-batch")
                    .expect("release four-path claim by agent");
                assert_eq!(released, vec![claim]);
                black_box(released)
            });
        });
    }

    group.finish();
}

fn run_disjoint_round(stores: &[SyncStore], agents: &[String], paths: &[String]) {
    let barrier = Arc::new(Barrier::new(stores.len()));
    std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(stores.len());
        for ((store, agent), path) in stores.iter().zip(agents).zip(paths) {
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                barrier.wait();
                let claim = store
                    .claim_paths(agent, [path])
                    .expect("acquire concurrent disjoint claim");
                let released = store
                    .release(claim.token)
                    .expect("release concurrent disjoint claim");
                assert_eq!(released, claim);
                released
            }));
        }
        for worker in workers {
            black_box(worker.join().expect("join concurrent claim worker"));
        }
    });
}

fn run_overlapping_handoff(owner: &SyncStore, contender: &SyncStore) {
    let (owner_ready_tx, owner_ready_rx) = mpsc::sync_channel(0);
    let (conflict_seen_tx, conflict_seen_rx) = mpsc::sync_channel(0);
    let (owner_released_tx, owner_released_rx) = mpsc::sync_channel(0);

    std::thread::scope(|scope| {
        let owner_worker = scope.spawn(move || {
            let claim = owner
                .claim_paths("bench-overlap-owner", ["src/lib.rs"])
                .expect("overlap owner claim must succeed");
            owner_ready_tx
                .send(())
                .expect("notify overlap contender that owner is ready");
            conflict_seen_rx
                .recv()
                .expect("wait for observed overlap conflict");
            let released = owner
                .release(claim.token)
                .expect("overlap owner release must succeed");
            owner_released_tx
                .send(())
                .expect("notify overlap contender that owner released");
            assert_eq!(released, claim);
            released
        });

        let contender_worker = scope.spawn(move || {
            owner_ready_rx.recv().expect("wait for overlap owner claim");
            let conflict = contender
                .claim_paths("bench-overlap-contender", ["src/lib.rs"])
                .expect_err("overlapping claim must be refused while owner is active");
            assert!(
                conflict.to_string().contains("already claimed"),
                "unexpected overlap refusal: {conflict:#}"
            );
            black_box(conflict);
            conflict_seen_tx
                .send(())
                .expect("notify owner that overlap was observed");
            owner_released_rx
                .recv()
                .expect("wait for overlap owner release");

            let claim = contender
                .claim_paths("bench-overlap-contender", ["src/lib.rs"])
                .expect("contender claim after handoff must succeed");
            let released = contender
                .release(claim.token)
                .expect("contender release after handoff must succeed");
            assert_eq!(released, claim);
            released
        });

        black_box(
            owner_worker
                .join()
                .expect("join overlap owner claim worker"),
        );
        black_box(
            contender_worker
                .join()
                .expect("join overlap contender claim worker"),
        );
    });
}

fn claim_contention(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_contention");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::claims();
        let stores = (0..2)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open disjoint SyncStore"))
            .collect::<Vec<_>>();
        let agents = vec![
            "probe-disjoint-a".to_string(),
            "probe-disjoint-b".to_string(),
        ];
        let paths = vec!["src/lib.rs".to_string(), "README.md".to_string()];
        run_disjoint_round(&stores, &agents, &paths);

        let agents = vec![
            "bench-disjoint-a".to_string(),
            "bench-disjoint-b".to_string(),
        ];
        group.bench_function("disjoint_two_successes", |bencher| {
            bencher.iter(|| run_disjoint_round(&stores, &agents, &paths));
        });
    }

    {
        let fixture = RepositoryFixture::claims();
        let owner = SyncStore::open(&fixture.repo_path).expect("open overlap owner SyncStore");
        let contender =
            SyncStore::open(&fixture.repo_path).expect("open overlap contender SyncStore");
        run_overlapping_handoff(&owner, &contender);

        group.bench_function("overlapping_handoff_two_successes", |bencher| {
            bencher.iter(|| run_overlapping_handoff(&owner, &contender));
        });
    }

    group.finish();
}

fn claim_concurrency(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_concurrency_disjoint");
    bound_group(&mut group);

    for worker_count in [1_usize, 4, 8] {
        let fixture = RepositoryFixture::claims();
        let stores = (0..worker_count)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open concurrent SyncStore"))
            .collect::<Vec<_>>();
        let agents = (0..worker_count)
            .map(|index| format!("bench-thread-{index}"))
            .collect::<Vec<_>>();
        let paths = (0..worker_count)
            .map(|index| format!("generated/thread-{index}.rs"))
            .collect::<Vec<_>>();
        run_disjoint_round(&stores, &agents, &paths);

        group.bench_with_input(
            BenchmarkId::new("threads", worker_count),
            &worker_count,
            |bencher, &_count| {
                bencher.iter(|| run_disjoint_round(&stores, &agents, &paths));
            },
        );
    }

    group.finish();
}

fn assert_semantic_fixture(map: &SemanticRepoMap) {
    assert!(
        map.files
            .iter()
            .any(|file| file.path == Path::new("src/api.rs")),
        "semantic fixture must include src/api.rs"
    );
    assert!(
        map.symbols.iter().any(|symbol| symbol.name == "endpoint"),
        "semantic fixture must include endpoint"
    );
}

fn skip_repository_queries_if_containment_unavailable() -> bool {
    const GROUP_NAME: &str = "benchmark group repository_queries";

    #[cfg(target_os = "linux")]
    if std::env::var_os(FORCE_CONTAINMENT_UNAVAILABLE_ENV).is_some() {
        return containment::skip_if_unavailable_for_cgroups(
            GROUP_NAME,
            "0::/system.slice/maco-bench-forced-unavailable.service\n",
        );
    }

    containment::skip_if_unavailable(GROUP_NAME)
        .expect("probe containment capability for repository_queries benchmark group")
}

fn repository_queries(criterion: &mut Criterion) {
    if skip_repository_queries_if_containment_unavailable() {
        return;
    }

    let mut group = criterion.benchmark_group("repository_queries");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::repository_map();
        let probe =
            repo_map::scan_repository(&fixture.repo_path).expect("public repository map probe");
        assert!(
            probe
                .entries
                .iter()
                .any(|entry| entry.path == Path::new("src/api.rs")),
            "repository map fixture must include src/api.rs"
        );

        group.bench_function("inventory_scan_small_repo", |bencher| {
            bencher.iter(|| {
                let map = repo_map::scan_repository(&fixture.repo_path)
                    .expect("public repository map scan must succeed");
                black_box(map)
            });
        });
    }

    {
        let fixture = RepositoryFixture::repository_map();
        let probe =
            repo_semantic::scan_repository(&fixture.repo_path).expect("public semantic map probe");
        assert_semantic_fixture(&probe);

        group.bench_function("semantic_scan_small_repo", |bencher| {
            bencher.iter(|| {
                let map = repo_semantic::scan_repository(&fixture.repo_path)
                    .expect("public semantic repository scan must succeed");
                assert_semantic_fixture(&map);
                black_box(map)
            });
        });
    }

    {
        let fixture = RepositoryFixture::repository_map();
        let map = repo_semantic::scan_repository(&fixture.repo_path)
            .expect("prepare public semantic risk fixture");
        assert_semantic_fixture(&map);
        let probe = repo_semantic::risk_report_for_paths(&map, ["src/api.rs"]);
        assert!(
            probe
                .touched_symbols
                .iter()
                .any(|symbol| symbol.name == "endpoint"),
            "risk query must return the endpoint symbol"
        );
        assert!(
            probe.impacted_files.contains(&PathBuf::from("src/lib.rs")),
            "risk query must return the importing lib.rs"
        );

        group.bench_function("semantic_risk_small_repo", |bencher| {
            bencher.iter(|| {
                let report = repo_semantic::risk_report_for_paths(&map, ["src/api.rs"]);
                assert!(
                    report
                        .touched_symbols
                        .iter()
                        .any(|symbol| symbol.name == "endpoint"),
                    "timed risk query must return the endpoint symbol"
                );
                black_box(report)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    claim_acquire_release,
    claim_contention,
    claim_concurrency,
    repository_queries
);
criterion_main!(benches);
