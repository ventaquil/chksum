use criterion::{criterion_group, Criterion, Throughput};

fn benchmark_md5_state_update(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("md5::State::<T>::update");

    group.throughput(Throughput::Bytes(64));

    {
        use chksum_hash::md5::State;

        let data = [0u32; 16];
        let mut state: State<u32> = State::new();
        group.bench_function("T: u32x1", move |bencher| {
            bencher.iter(|| {
                state.update(data);
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        #[cfg(target_arch = "x86")]
        use chksum_arch::x86::u32x4;
        #[cfg(target_arch = "x86_64")]
        use chksum_arch::x86_64::u32x4;
        use chksum_hash::md5::State;

        let data = [u32x4::from(0u32); 16];
        let mut state: State<u32x4> = State::new();
        group.bench_function("T: u32x4", move |bencher| {
            bencher.iter(|| {
                state.update(data);
            })
        });
    }

    group.finish();
}

fn benchmark_md5_hash_update(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("md5::Hash::<T>::update");

    group.throughput(Throughput::Bytes(64));

    {
        use chksum_arch::x1::Arch;
        use chksum_hash::md5::Hash;

        let data = [0u8; 64];
        let mut hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x1::Arch", move |bencher| {
            bencher.iter(|| {
                hash.update(&data);
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        use chksum_arch::x4::Arch;
        #[cfg(target_arch = "x86")]
        use chksum_arch::x86::u8x4;
        #[cfg(target_arch = "x86_64")]
        use chksum_arch::x86_64::u8x4;
        use chksum_hash::md5::Hash;

        let data = [u8x4::from(0u8); 64];
        let mut hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x4::Arch", move |bencher| {
            bencher.iter(|| {
                hash.update(&data);
            })
        });
    }

    group.finish();
}

fn benchmark_md5_hash_digest(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("md5::Hash::<T>::digest");

    {
        use chksum_arch::x1::Arch;
        use chksum_hash::md5::Hash;

        let hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x1::Arch", move |bencher| {
            bencher.iter(|| {
                hash.digest();
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        use chksum_arch::x4::Arch;
        use chksum_hash::md5::Hash;

        let hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x4::Arch", move |bencher| {
            bencher.iter(|| {
                hash.digest();
            })
        });
    }

    group.finish();
}

criterion_group!(
    md5,
    benchmark_md5_state_update,
    benchmark_md5_hash_update,
    benchmark_md5_hash_digest
);

fn benchmark_sha1_state_update(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sha1::State::<T>::update");

    group.throughput(Throughput::Bytes(64));

    {
        use chksum_hash::sha1::State;

        let data = [0u32; 16];
        let mut state: State<u32> = State::new();
        group.bench_function("T: u32x1", move |bencher| {
            bencher.iter(|| {
                state.update(data);
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        #[cfg(target_arch = "x86")]
        use chksum_arch::x86::u32x4;
        #[cfg(target_arch = "x86_64")]
        use chksum_arch::x86_64::u32x4;
        use chksum_hash::md5::State;

        let data = [u32x4::from(0u32); 16];
        let mut state: State<u32x4> = State::new();
        group.bench_function("T: u32x4", move |bencher| {
            bencher.iter(|| {
                state.update(data);
            })
        });
    }

    group.finish();
}

fn benchmark_sha1_hash_update(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sha1::Hash::<T>::update");

    group.throughput(Throughput::Bytes(64));

    {
        use chksum_arch::x1::Arch;
        use chksum_hash::sha1::Hash;

        let data = [0u8; 64];
        let mut hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x1::Arch", move |bencher| {
            bencher.iter(|| {
                hash.update(&data);
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        use chksum_arch::x4::Arch;
        #[cfg(target_arch = "x86")]
        use chksum_arch::x86::u8x4;
        #[cfg(target_arch = "x86_64")]
        use chksum_arch::x86_64::u8x4;
        use chksum_hash::sha1::Hash;

        let data = [u8x4::from(0u8); 64];
        let mut hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x4::Arch", move |bencher| {
            bencher.iter(|| {
                hash.update(&data);
            })
        });
    }

    group.finish();
}

fn benchmark_sha1_hash_digest(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sha1::Hash::<T>::digest");

    {
        use chksum_arch::x1::Arch;
        use chksum_hash::sha1::Hash;

        let hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x1::Arch", move |bencher| {
            bencher.iter(|| {
                hash.digest();
            })
        });
    }

    #[cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    ))]
    {
        use chksum_arch::x4::Arch;
        use chksum_hash::sha1::Hash;

        let hash: Hash<Arch> = Hash::new();
        group.bench_function("T: x4::Arch", move |bencher| {
            bencher.iter(|| {
                hash.digest();
            })
        });
    }

    group.finish();
}

criterion_group!(
    sha1,
    benchmark_sha1_state_update,
    benchmark_sha1_hash_update,
    benchmark_sha1_hash_digest
);
