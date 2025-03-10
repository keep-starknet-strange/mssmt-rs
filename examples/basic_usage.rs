//! Basic example of using the Merkle Sum Sparse Merkle Tree
//!
//! This example demonstrates:
//! - Creating a new tree
//! - Inserting leaves
//! - Getting the root hash
//! - Verifying merkle proofs

use mssmt::{verify_merkle_proof, ComputedNode, Leaf, MemoryDb, Node, TreeError, MSSMT};
use sha2::Sha256;

fn main() {
    // Create a new tree with 32-byte hashes using SHA256
    let db = Box::new(MemoryDb::<32, Sha256>::new());
    let mut tree = MSSMT::<32, Sha256, ()>::new(db);

    // Insert some leaves with different values and sums
    let leaf1 = Leaf::new(vec![1, 2, 3], 100);
    let leaf2 = Leaf::new(vec![4, 5, 6], 200);
    let leaf3 = Leaf::new(vec![7, 8, 9], 300);

    // Insert leaves with different keys
    tree.insert([1; 32], leaf1.clone()).unwrap();
    tree.insert([2; 32], leaf2.clone()).unwrap();
    tree.insert([3; 32], leaf3.clone()).unwrap();

    // Get the root hash
    let root = tree.root().unwrap();
    println!("Root hash: {}", hex::encode(root.hash()));
    println!("Total sum: {}", root.sum());

    // Get and verify a merkle proof for leaf1
    let proof = tree.merkle_proof([1; 32]).unwrap();
    println!("Merkle proof length: {}", proof.len());

    // Verify the proof
    // Not necessary but for the sake of the example we'll use computed nodes for the proof verification
    // because it's most likely what you'll do in production
    let result: Result<(), TreeError<()>> = verify_merkle_proof(
        [1; 32],
        leaf1,
        proof
            .iter()
            .map(|node| Node::Computed(ComputedNode::new(node.hash(), node.sum())))
            .collect(),
        root.hash(),
    );
    println!("Proof verification: {}", result.is_ok());
}
