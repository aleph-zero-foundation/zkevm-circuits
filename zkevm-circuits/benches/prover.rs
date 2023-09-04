use criterion::{Criterion, criterion_group, criterion_main};
use zkevm_circuits::run_keccak_prover;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak");
    group.sample_size(10);
    group.bench_function("keccak", |b| b.iter(run_keccak_prover));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
