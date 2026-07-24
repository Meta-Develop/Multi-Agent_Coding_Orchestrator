//! Reproducible Criterion baselines for MACO's git-native coordination substrate.

use criterion::{criterion_group, criterion_main, Criterion};

fn coordination_placeholder(criterion: &mut Criterion) {
    criterion.bench_function("coordination/harness", |bencher| bencher.iter(|| ()));
}

criterion_group!(benches, coordination_placeholder);
criterion_main!(benches);
