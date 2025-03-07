//! Example of using the Compact Merkle Sum Sparse Merkle Tree
//!
//! This example demonstrates:
//! - Creating a compact tree
//! - Inserting leaves
//! - Memory efficiency compared to regular tree
//! - Verifying merkle proofs

use merkle_sum_sparse_tree::{verify_merkle_proof, TreeError};
use merkle_sum_sparse_tree::{CompactMSSMT, Leaf, MemoryDb, MSSMT};
use sha2::Sha256;

fn main() {
    // Create a new compact tree with 32-byte hashes using SHA256
    let db = Box::new(MemoryDb::<32, Sha256>::new());
    let mut compact_tree = CompactMSSMT::<32, Sha256, ()>::new(db.clone()).unwrap();
    let mut regular_tree = MSSMT::<32, Sha256, ()>::new(db).unwrap();
    // Insert some leaves with different values and sums
    let leaf1 = Leaf::new(vec![1, 2, 3], 100);
    let leaf2 = Leaf::new(vec![4, 5, 6], 200);
    let leaf3 = Leaf::new(vec![7, 8, 9], 300);

    // Insert leaves with different keys
    compact_tree.insert([1; 32], leaf1.clone()).unwrap();
    compact_tree.insert([2; 32], leaf2.clone()).unwrap();
    compact_tree.insert([3; 32], leaf3.clone()).unwrap();

    regular_tree.insert([1; 32], leaf1.clone()).unwrap();
    regular_tree.insert([2; 32], leaf2.clone()).unwrap();
    regular_tree.insert([3; 32], leaf3.clone()).unwrap();

    // Get the root hash
    let root = compact_tree.root().unwrap();
    println!("Root hash: {}", hex::encode(root.hash()));
    println!("Total sum: {}", root.sum());

    // Get and verify a merkle proof for leaf1
    let proof = compact_tree.merkle_proof([1; 32]).unwrap();
    println!("Merkle proof length: {}", proof.len());

    // Verify the proof
    let result: Result<(), TreeError<()>> = verify_merkle_proof([1; 32], leaf1, proof, root);
    println!("Proof verification: {}", result.is_ok());

    // Demonstrate memory efficiency
    println!("\nMemory efficiency demonstration:");

    // Get the underlying MemoryDb directly from the Box
    let compact_db = compact_tree.db();
    let regular_db = regular_tree.db();
    let compact_memory_db = compact_db
        .as_any()
        .downcast_ref::<MemoryDb<32, Sha256>>()
        .unwrap();
    let regular_memory_db = regular_db
        .as_any()
        .downcast_ref::<MemoryDb<32, Sha256>>()
        .unwrap();
    println!(
        "Number of branches stored in regular tree: {}",
        regular_memory_db.get_branches().len()
    );
    println!(
        "Number of branches stored in compact tree: {}",
        compact_memory_db.get_branches().len()
    );

    println!(
        "Number of leaves stored in compact tree: {}",
        compact_memory_db.get_leaves().len()
    );
    println!(
        "Number of leaves stored: {}",
        regular_memory_db.get_leaves().len()
    );
}
