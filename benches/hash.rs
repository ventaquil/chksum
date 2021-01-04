use chksum::hash::{Context as _, md5, sha1};

use criterion::{criterion_group, Criterion};

fn benchmark_md5_empty(c: &mut Criterion) {
    let context = md5::new();
    c.bench_function("md5.empty", move |b| b.iter(|| {
        context.digest();
    }));
}

fn benchmark_md5_block_update(c: &mut Criterion) {
    let mut context = md5::new();
    let data = &[0u8; 64][..];
    c.bench_function("md5.block_update", move |b| b.iter(|| {
        context.update(data);
    }));
}

fn benchmark_md5_block_update_digest(c: &mut Criterion) {
    let mut context = md5::new();
    let data = &[0u8; 64][..];
    c.bench_function("md5.block_update_digest", move |b| b.iter(|| {
        context.update(data);
        context.digest();
    }));
}

criterion_group!(
    md5,
    benchmark_md5_empty,
    benchmark_md5_block_update,
    benchmark_md5_block_update_digest,
);

fn benchmark_sha1_empty(c: &mut Criterion) {
    let context = sha1::new();
    c.bench_function("sha1.empty", move |b| b.iter(|| {
        context.digest();
    }));
}

fn benchmark_sha1_block_update(c: &mut Criterion) {
    let mut context = sha1::new();
    let data = &[0u8; 64][..];
    c.bench_function("sha1.block_update", move |b| b.iter(|| {
        context.update(data);
    }));
}

fn benchmark_sha1_block_update_digest(c: &mut Criterion) {
    let mut context = sha1::new();
    let data = &[0u8; 64][..];
    c.bench_function("sha1.block_update_digest", move |b| b.iter(|| {
        context.update(data);
    }));
}

criterion_group!(
    sha1,
    benchmark_sha1_empty,
    benchmark_sha1_block_update,
    benchmark_sha1_block_update_digest,
);
