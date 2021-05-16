use criterion::{Criterion, criterion_group};

fn benchmark_md5_state_u32x1_update(c: &mut Criterion) {
    use chksum::hash::md5::State;

    let data = [0u32; 16];
    let mut state: State<u32> = State::new();
    c.bench_function("md5::State::<u32x1>::update", move |b| b.iter(|| {
        state.update(data);
    }));
}

fn benchmark_md5_state_u32x4_update(c: &mut Criterion) {
    use chksum::arch::x86_64::u32x4;
    use chksum::hash::md5::State;
    
    let data = [u32x4::from(0u32); 16];
    let mut state: State<u32x4> = State::new();
    c.bench_function("md5::State::<u32x4>::update", move |b| b.iter(|| {
        state.update(data);
    }));
}

fn benchmark_md5_hash_x1_update(c: &mut Criterion) {
    use chksum::arch::x1;
    use chksum::hash::{Update as _, md5::Hash};

    let data = [0u8; 64];
    let mut hash: Hash<x1::Arch> = Hash::new();
    c.bench_function("md5::Hash::<x1::Arch>::update", move |b| b.iter(|| {
        hash.update(&data[..]);
    }));
}

fn benchmark_md5_hash_x4_update(c: &mut Criterion) {
    use chksum::arch::{x4, x86_64::u8x4};
    use chksum::hash::{Update as _, md5::Hash};

    let data = [u8x4::from(0u8); 64];
    let mut hash: Hash<x4::Arch> = Hash::new();
    c.bench_function("md5::Hash::<x4::Arch>::update", move |b| b.iter(|| {
        hash.update(&data[..]);
    }));
}

criterion_group!{
    md5,
    benchmark_md5_state_u32x1_update,
    benchmark_md5_state_u32x4_update,
    benchmark_md5_hash_x1_update,
    benchmark_md5_hash_x4_update,
}
