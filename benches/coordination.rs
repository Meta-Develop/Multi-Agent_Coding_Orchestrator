//! Reproducible Criterion baselines for MACO's git-native coordination substrate.
//!
//! Claim benchmarks exercise the persisted `SyncStore` path. The current public
//! API cannot construct a capability-bound managed worktree, so the worktree and
//! merge groups explicitly measure their public fail-closed boundaries instead
//! of presenting test-only setup as production lifecycle throughput.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use git2::{IndexAddOption, Oid, Repository, Signature, WorktreeAddOptions};
use multi_agent_coding_orchestrator::{
    merge::{
        preview_merge_apply, MergeCollectOptions, MergeForceOptions, MergePreviewOptions,
        DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
    },
    sync_store::SyncStore,
    worktree::{WorktreeCreateOptions, WorktreeManager},
};
use std::{
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    time::Duration,
};
use tempfile::{tempdir, TempDir};

const SAMPLE_SIZE: usize = 10;
const WARM_UP_TIME: Duration = Duration::from_millis(500);
const MEASUREMENT_TIME: Duration = Duration::from_secs(1);

struct RepositoryFixture {
    _temp: TempDir,
    repo_path: PathBuf,
}

impl RepositoryFixture {
    fn new() -> Self {
        Self::with_files(&[("README.md", "# Benchmark fixture\n")])
    }

    fn with_files(files: &[(&str, &str)]) -> Self {
        let temp = tempdir().expect("create benchmark tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main")
            .expect("initialize benchmark repository");
        for (relative, contents) in files {
            write_file(&repo_path, relative, contents);
        }
        let repo = Repository::open(&repo_path).expect("open benchmark repository");
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
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .expect("commit benchmark fixture")
}

fn bound_group(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group
        .sample_size(SAMPLE_SIZE)
        .warm_up_time(WARM_UP_TIME)
        .measurement_time(MEASUREMENT_TIME);
}

fn claim_acquire_release(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_acquire_release");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::new();
        let store = SyncStore::open(&fixture.repo_path).expect("open single-path sync store");
        group.bench_function("single_path", |bencher| {
            bencher.iter(|| {
                let claim = store
                    .claim_paths("bench-single", ["src/lib.rs"])
                    .expect("acquire single-path claim");
                let released = store
                    .release(claim.token)
                    .expect("release single-path claim");
                black_box(released)
            });
        });
    }

    {
        let fixture = RepositoryFixture::new();
        let store = SyncStore::open(&fixture.repo_path).expect("open batch-path sync store");
        let paths = [
            "src/lib.rs",
            "src/main.rs",
            "tests/coordination.rs",
            "README.md",
        ];
        group.bench_function("small_batch_4_paths", |bencher| {
            bencher.iter(|| {
                let claim = store
                    .claim_paths("bench-batch", paths)
                    .expect("acquire batch claim");
                let released = store.release(claim.token).expect("release batch claim");
                black_box(released)
            });
        });
    }

    group.finish();
}

fn claim_contention(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_contention");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::new();
        let stores = (0..2)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open overlap sync store"))
            .collect::<Vec<_>>();
        group.bench_function("overlapping_race_one_winner", |bencher| {
            bencher.iter(|| {
                run_claim_race(
                    &stores,
                    &["bench-overlap-a", "bench-overlap-b"],
                    &["src", "src/lib.rs"],
                    1,
                )
            });
        });
    }

    {
        let fixture = RepositoryFixture::new();
        let stores = (0..2)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open disjoint sync store"))
            .collect::<Vec<_>>();
        group.bench_function("disjoint_race_two_winners", |bencher| {
            bencher.iter(|| {
                run_claim_race(
                    &stores,
                    &["bench-disjoint-a", "bench-disjoint-b"],
                    &["src", "README.md"],
                    2,
                )
            });
        });
    }

    group.finish();
}

fn run_claim_race(
    stores: &[SyncStore],
    agents: &[&str],
    paths: &[&str],
    expected_successes: usize,
) {
    let barrier = Arc::new(Barrier::new(stores.len()));
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(stores.len());
        for (index, ((store, agent), path)) in stores.iter().zip(agents).zip(paths).enumerate() {
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                barrier.wait();
                (index, store.claim_paths(*agent, [*path]))
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().expect("join claim race worker"))
            .collect::<Vec<_>>()
    });

    let mut success_count = 0;
    for (index, result) in results {
        match result {
            Ok(claim) => {
                success_count += 1;
                black_box(
                    stores[index]
                        .release(claim.token)
                        .expect("release claim race winner"),
                );
            }
            Err(error) => {
                black_box(error);
            }
        }
    }
    assert_eq!(success_count, expected_successes);
}

fn claim_concurrency(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("claim_concurrency_disjoint");
    bound_group(&mut group);

    for worker_count in [1_usize, 4, 8] {
        let fixture = RepositoryFixture::new();
        let stores = (0..worker_count)
            .map(|_| SyncStore::open(&fixture.repo_path).expect("open concurrent sync store"))
            .collect::<Vec<_>>();
        let agents = (0..worker_count)
            .map(|index| format!("bench-thread-{index}"))
            .collect::<Vec<_>>();
        let paths = (0..worker_count)
            .map(|index| format!("generated/thread-{index}.rs"))
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("threads", worker_count),
            &worker_count,
            |bencher, &count| {
                bencher.iter(|| {
                    let barrier = Arc::new(Barrier::new(count));
                    std::thread::scope(|scope| {
                        let mut workers = Vec::with_capacity(count);
                        for index in 0..count {
                            let barrier = Arc::clone(&barrier);
                            let store = &stores[index];
                            let agent = &agents[index];
                            let path = &paths[index];
                            workers.push(scope.spawn(move || {
                                barrier.wait();
                                let claim = store
                                    .claim_paths(agent, [path])
                                    .expect("acquire concurrent disjoint claim");
                                store
                                    .release(claim.token)
                                    .expect("release concurrent disjoint claim")
                            }));
                        }
                        for worker in workers {
                            black_box(worker.join().expect("join concurrent claim worker"));
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn worktree_registry_public_boundary(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("worktree_registry_lifecycle");
    bound_group(&mut group);

    {
        let fixture = RepositoryFixture::new();
        let manager = WorktreeManager::new(&fixture.repo_path);
        let create_options = WorktreeCreateOptions {
            agent_id: "bench-agent".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(fixture._temp.path().join("guarded-managed-worktrees")),
        };
        let error = manager
            .create(create_options.clone())
            .expect_err("public create must require a capability-bound cleanliness input");
        assert!(error
            .to_string()
            .contains("capability-bound repository cleanliness input"));
        group.bench_function("public_api_guard_create_refused", |bencher| {
            bencher.iter(|| {
                let error = manager
                    .create(create_options.clone())
                    .expect_err("public create must remain fail closed");
                black_box(error)
            });
        });
    }

    {
        let fixture = RepositoryFixture::new();
        let manager = WorktreeManager::new(&fixture.repo_path);
        assert!(
            manager
                .list()
                .expect("initialize empty managed registry")
                .is_empty(),
            "public-boundary fixture must begin with an empty registry"
        );
        group.bench_function("public_api_list_empty", |bencher| {
            bencher.iter(|| {
                let listed = manager.list().expect("list guarded managed registry");
                assert!(listed.is_empty());
                black_box(listed)
            });
        });
    }

    {
        let fixture = RepositoryFixture::new();
        let manager = WorktreeManager::new(&fixture.repo_path);
        assert!(
            manager
                .list()
                .expect("initialize empty managed registry")
                .is_empty(),
            "public-boundary fixture must begin with an empty registry"
        );
        let error = manager
            .remove("bench-agent", true, true)
            .expect_err("unbound worktree removal must be refused");
        assert!(error
            .to_string()
            .contains("has no create-time managed binding"));
        group.bench_function("public_api_guard_remove_unbound_refused", |bencher| {
            bencher.iter(|| {
                let error = manager
                    .remove("bench-agent", true, true)
                    .expect_err("unbound worktree removal must remain fail closed");
                black_box(error)
            });
        });
    }

    group.finish();
}

#[derive(Clone, Copy)]
enum MergeEditShape {
    Disjoint,
    SameFile,
}

struct MergeBoundaryFixture {
    _repository: RepositoryFixture,
    options: MergePreviewOptions,
}

impl MergeBoundaryFixture {
    fn new(shape: MergeEditShape) -> Self {
        let repository = RepositoryFixture::with_files(&[
            ("candidate.txt", "base\n"),
            ("primary.txt", "base\n"),
            ("shared.txt", "base\n"),
        ]);
        let agent_path = repository._temp.path().join("agent-a");
        let repo = Repository::open(&repository.repo_path).expect("open merge fixture repository");
        let base = repo
            .head()
            .expect("find merge fixture HEAD")
            .peel_to_commit()
            .expect("peel merge fixture HEAD");
        {
            let branch = repo
                .branch("bench/agent-a", &base, false)
                .expect("create merge fixture agent branch");
            let reference = branch.into_reference();
            let mut add_options = WorktreeAddOptions::new();
            add_options.reference(Some(&reference));
            repo.worktree("agent-a", &agent_path, Some(&add_options))
                .expect("create merge fixture linked worktree");
        }
        drop(base);

        let claimed_path = match shape {
            MergeEditShape::Disjoint => {
                write_file(&agent_path, "candidate.txt", "candidate edit\n");
                write_file(&repository.repo_path, "primary.txt", "primary edit\n");
                "candidate.txt"
            }
            MergeEditShape::SameFile => {
                write_file(&agent_path, "shared.txt", "candidate edit\n");
                write_file(&repository.repo_path, "shared.txt", "primary edit\n");
                "shared.txt"
            }
        };
        commit_all(&repo, "prepare primary merge edit");
        drop(repo);

        let manager = WorktreeManager::new(&repository.repo_path);
        assert!(
            manager
                .list()
                .expect("initialize empty merge fixture registry")
                .is_empty(),
            "git2-only linked worktree must not be adopted as managed"
        );
        let options = MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: repository.repo_path.clone(),
                agent_id: "agent-a".to_string(),
                claimed_paths: vec![PathBuf::from(claimed_path)],
                include_full_diff: false,
                diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            forces: MergeForceOptions::default(),
            require_validation: false,
        };
        let error = preview_merge_apply(options.clone())
            .expect_err("unmanaged merge fixture must fail closed at the public boundary");
        assert!(
            error.to_string().contains("not registered or readable"),
            "unexpected public merge boundary: {error:#}"
        );

        Self {
            _repository: repository,
            options,
        }
    }
}

fn merge_preview_public_boundary(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("merge_preview");
    bound_group(&mut group);

    {
        let fixture = MergeBoundaryFixture::new(MergeEditShape::Disjoint);
        group.bench_function("public_api_guard_disjoint_edits", |bencher| {
            bencher.iter(|| {
                let error = preview_merge_apply(fixture.options.clone())
                    .expect_err("unmanaged disjoint preview must remain fail closed");
                black_box(error)
            });
        });
    }

    {
        let fixture = MergeBoundaryFixture::new(MergeEditShape::SameFile);
        group.bench_function("public_api_guard_same_file_edits", |bencher| {
            bencher.iter(|| {
                let error = preview_merge_apply(fixture.options.clone())
                    .expect_err("unmanaged same-file preview must remain fail closed");
                black_box(error)
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
    worktree_registry_public_boundary,
    merge_preview_public_boundary
);
criterion_main!(benches);
