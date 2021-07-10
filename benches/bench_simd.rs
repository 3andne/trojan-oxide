// #![feature(aarch64_target_feature)]
// #![feature(stdsimd)]

// use criterion::{black_box, criterion_group, criterion_main, Criterion};

// #[path = "../src/simd/simd_parse.rs"]
// mod simd_parse;
// use simd_parse::*;

// const TESTSET1: [u8; 16] = [
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'\r', b'\n', 
//     b'_', b'_', b'_', b'_',
// ];

// const TESTSET2: [u8; 32] = [
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'\r', b'\n', 
//     b'_', b'_', b'_', b'_',
// ];

// const TESTSET3: [u8; 64] = [
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'\r', b'\n', 
//     b'_', b'_', b'_', b'_',
// ];

// const TESTSET4: [u8; 128] = [
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_',
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'_', b'_', 
//     b'_', b'_', b'\r', b'\n', 
//     b'_', b'_', b'_', b'_',
// ];


// fn criterion_benchmark(c: &mut Criterion) {
//     c.bench_function("simd-neon-16-16", |b| b.iter(|| simd16_wrap(black_box(&TESTSET1))));
//     c.bench_function("simd-neon-8-16", |b| b.iter(|| simd8_wrap(black_box(&TESTSET1))));
//     c.bench_function("scalar-16", |b| b.iter(|| parse_scalar(black_box(&TESTSET1))));
//     c.bench_function("simd-neon-16-32", |b| b.iter(|| simd16_wrap(black_box(&TESTSET2))));
//     c.bench_function("simd-neon-8-32", |b| b.iter(|| simd8_wrap(black_box(&TESTSET2))));
//     c.bench_function("scalar-32", |b| b.iter(|| parse_scalar(black_box(&TESTSET2))));
//     c.bench_function("simd-neon-16-64", |b| b.iter(|| simd16_wrap(black_box(&TESTSET3))));
//     c.bench_function("simd-neon-8-64", |b| b.iter(|| simd8_wrap(black_box(&TESTSET3))));
//     c.bench_function("scalar-64", |b| b.iter(|| parse_scalar(black_box(&TESTSET3))));
//     c.bench_function("simd-neon-16-128", |b| b.iter(|| simd16_wrap(black_box(&TESTSET4))));
//     c.bench_function("simd-neon-8-128", |b| b.iter(|| simd8_wrap(black_box(&TESTSET4))));
//     c.bench_function("scalar-128", |b| b.iter(|| parse_scalar(black_box(&TESTSET4))));
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);