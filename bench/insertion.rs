use criterion::{criterion_group, criterion_main, Criterion};
use mssmt::{CompactMSSMT, Leaf, MemoryDb, MSSMT};
use sha2::Sha256;

pub fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for byte in key.iter_mut() {
        *byte = rand::random();
    }
    key
}

pub fn generate_random_leaf() -> Leaf<32, Sha256> {
    let mut value = Vec::with_capacity(32);
    for _ in 0..32 {
        value.push(rand::random());
    }
    Leaf::new(value, rand::random::<u32>() as u64)
}

fn bench_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("MSSMT Insertion");

    // Benchmark regular tree insertion
    group.bench_function("Regular Tree", |b| {
        b.iter(|| {
            let db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut tree = MSSMT::<32, Sha256, ()>::new(db);
            for _ in 0..100 {
                let key = generate_random_key();
                let leaf = generate_random_leaf();
                tree.insert(&key, leaf).unwrap();
            }
        })
    });

    // Benchmark compact tree insertion
    group.bench_function("Compact Tree", |b| {
        b.iter(|| {
            let db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut tree = CompactMSSMT::<32, Sha256, ()>::new(db);
            for _ in 0..100 {
                let key = generate_random_key();
                let leaf = generate_random_leaf();
                tree.insert(&key, leaf).unwrap();
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_insertion);
criterion_main!(benches);
