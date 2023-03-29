use criterion::{criterion_group, criterion_main, Criterion};

use rust_otp::{Algo, totp};

pub fn criterion_benchmark(c: &mut Criterion) {
    let sha1_secret = b"12345678901234567890";
    let sha256_secret = b"12345678901234567890";
    let sha512_secret = b"12345678901234567890";

    c.bench_function("gen totp SHA1 1_000", |b| b.iter(|| {
        for _ in 0..1_000 {
            totp(&Algo::SHA1, sha1_secret, 6, 30, 1234567890);
        }
    }));

    c.bench_function("gen totp sha256 1_000", |b| b.iter(|| {
        for _ in 0..1_000 {
            totp(&Algo::SHA256, sha256_secret, 6, 30, 1234567890);
        }
    }));

    c.bench_function("gen totp sha512 1_000", |b| b.iter(|| {
        for _ in 0..1_000 {
            totp(&Algo::SHA512, sha512_secret, 6, 30, 1234567890);
        }
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
