use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigUint;
use rrsa_common::math::mod_pow;
use serde::Deserialize;
use std::{time::Duration, vec::Vec};

fn modpow_internal(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    mod_pow(base, exponent, modulus)
}

fn modpow_trait(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

#[derive(Debug, Deserialize)]
struct MyNumber {
    base: u128,
    exponent: u128,
    modulus: u128,
}

fn modpow_bench(c: &mut Criterion) {
    let mut numbers = Vec::with_capacity(3333);
    for result in csv::Reader::from_path("./benches/big_numberscsv")
        .unwrap()
        .deserialize()
    {
        let record: MyNumber = result.unwrap();
        numbers.push(record);
    }

    let mut group = c.benchmark_group("Mod Pow");
    group.measurement_time(Duration::from_millis(500));
    group.warm_up_time(Duration::from_millis(100));

    for number in numbers[..20].iter() {
        // Internal Implementation"
        group.bench_with_input(
            BenchmarkId::new("Internal Implementation", number.base),
            &number,
            |b, i| {
                b.iter(|| {
                    modpow_internal(
                        black_box(&BigUint::from(i.base)),
                        black_box(&BigUint::from(i.exponent)),
                        black_box(&BigUint::from(i.modulus)),
                    )
                })
            },
        );
        // Trait Implementation
        group.bench_with_input(
            BenchmarkId::new("Trait Implementation", number.base),
            &number,
            |b, i| {
                b.iter(|| {
                    modpow_trait(
                        black_box(&BigUint::from(i.base)),
                        black_box(&BigUint::from(i.exponent)),
                        black_box(&BigUint::from(i.modulus)),
                    )
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, modpow_bench);
criterion_main!(benches);
