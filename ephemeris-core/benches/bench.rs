//! Benchmarks for ephemeris-core cryptographic operations.
//!
//! Run with: `cargo bench -p ephemeris-core`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ephemeris_core::*;

fn bench_encrypt(c: &mut Criterion) {
    let params = Argon2Params::low_memory();

    let mut group = c.benchmark_group("encrypt");

    group.bench_function("1KB", |b| {
        let msg = vec![0x42u8; 1024];
        b.iter(|| encrypt(black_box(&msg), black_box(b"password"), black_box(&params)))
    });

    group.bench_function("100KB", |b| {
        let msg = vec![0x42u8; 102_400];
        b.iter(|| encrypt(black_box(&msg), black_box(b"password"), black_box(&params)))
    });

    group.bench_function("1MB", |b| {
        let msg = vec![0x42u8; 1_048_576];
        b.iter(|| encrypt(black_box(&msg), black_box(b"password"), black_box(&params)))
    });

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let params = Argon2Params::low_memory();

    let mut group = c.benchmark_group("decrypt");

    for size in [1024, 102_400, 1_048_576usize] {
        let msg = vec![0x42u8; size];
        let result = encrypt(&msg, b"password", &params);
        group.bench_function(format!("{}B", size), |b| {
            b.iter(|| {
                decrypt(
                    black_box(&result.eph_file),
                    black_box(b"password"),
                    black_box(&params),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

fn bench_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");

    let fast = Argon2Params::low_memory();
    let default = Argon2Params::default();

    group.bench_function("low_memory", |b| {
        let salt = generate_salt();
        b.iter(|| {
            let _ = unwrap_key(
                black_box(&vec![0u8; 64]),
                black_box(b"password"),
                black_box(&salt),
                black_box(&fast),
            );
        })
    });

    group.bench_function("default_37mb", |b| {
        let salt = generate_salt();
        b.iter(|| {
            let _ = unwrap_key(
                black_box(&vec![0u8; 64]),
                black_box(b"password"),
                black_box(&salt),
                black_box(&default),
            );
        })
    });

    group.finish();
}

fn bench_repudiate(c: &mut Criterion) {
    let params = Argon2Params::low_memory();

    let mut group = c.benchmark_group("repudiate");

    for size in [1024, 102_400usize] {
        let msg = vec![0x42u8; size];
        let fake = vec![0x12u8; size];
        let result = encrypt(&msg, b"real", &params);

        group.bench_function(format!("{}B", size), |b| {
            b.iter(|| {
                repudiate_eph(
                    black_box(&result.eph_file),
                    black_box(&fake),
                    black_box(b"fake"),
                    black_box(&params),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_argon2,
    bench_repudiate
);
criterion_main!(benches);
