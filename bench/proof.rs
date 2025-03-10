use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mssmt::{verify_merkle_proof, CompactMSSMT, Leaf, MemoryDb, TreeError, MSSMT};
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

#[allow(clippy::type_complexity)]
fn setup_trees(
    num_leaves: usize,
) -> (
    MSSMT<32, Sha256, ()>,
    CompactMSSMT<32, Sha256, ()>,
    Vec<[u8; 32]>,
) {
    let regular_db = Box::new(MemoryDb::<32, Sha256>::new());
    let compact_db = Box::new(MemoryDb::<32, Sha256>::new());

    let mut regular_tree = MSSMT::<32, Sha256, ()>::new(regular_db);
    let mut compact_tree = CompactMSSMT::<32, Sha256, ()>::new(compact_db);

    let mut keys = Vec::with_capacity(num_leaves);

    for _ in 0..num_leaves {
        let key = generate_random_key();
        let leaf = generate_random_leaf();
        regular_tree.insert(key, leaf.clone()).unwrap();
        compact_tree.insert(key, leaf).unwrap();
        keys.push(key);
    }

    (regular_tree, compact_tree, keys)
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("MSSMT Proof Generation");

    // Setup trees with 100 leaves
    let (regular_tree, compact_tree, keys) = setup_trees(100);

    // Benchmark regular tree proof generation
    group.bench_function("Regular Tree", |b| {
        b.iter(|| {
            for key in &keys {
                black_box(regular_tree.merkle_proof(*key)).unwrap();
            }
        })
    });

    // Benchmark compact tree proof generation
    group.bench_function("Compact Tree", |b| {
        b.iter(|| {
            for key in &keys {
                black_box(compact_tree.merkle_proof(*key)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("MSSMT Proof Verification");

    // Setup trees with 100 leaves
    let (regular_tree, compact_tree, keys) = setup_trees(100);

    // Generate proofs for all keys
    let regular_proofs: Vec<_> = keys
        .iter()
        .map(|key| regular_tree.merkle_proof(*key).unwrap())
        .collect();

    let compact_proofs: Vec<_> = keys
        .iter()
        .map(|key| compact_tree.merkle_proof(*key).unwrap())
        .collect();
    let regular_leaves: Vec<_> = keys
        .iter()
        .map(|key| regular_tree.walk_down(*key, |_, _, _, _| {}).unwrap())
        .collect();

    let compact_leaves: Vec<_> = keys
        .iter()
        .map(|key| compact_tree.walk_down(key, |_, _, _, _| {}).unwrap())
        .collect();
    // Benchmark regular tree proof verification
    group.bench_function("Regular Tree", |b| {
        b.iter(|| {
            for ((key, proof), regular_leaf) in keys
                .iter()
                .zip(regular_proofs.iter())
                .zip(regular_leaves.clone().into_iter())
            {
                black_box::<Result<(), TreeError<()>>>(verify_merkle_proof(
                    *key,
                    regular_leaf,
                    proof.clone(),
                    regular_tree.root().unwrap().hash(),
                ))
                .unwrap();
            }
        })
    });

    // Benchmark compact tree proof verification
    group.bench_function("Compact Tree", |b| {
        b.iter(|| {
            for ((key, proof), compact_leaf) in keys
                .iter()
                .zip(compact_proofs.iter())
                .zip(compact_leaves.clone().into_iter())
            {
                black_box::<Result<(), TreeError<()>>>(verify_merkle_proof(
                    *key,
                    compact_leaf,
                    proof.clone(),
                    compact_tree.root().unwrap().hash(),
                ))
                .unwrap();
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_proof_generation, bench_proof_verification);
criterion_main!(benches);
