//! Example of implementing a custom hasher for the Merkle Sum Sparse Merkle Tree
//!
//! This example demonstrates:
//! - Creating a custom hasher implementation
//! - Using it with the tree
//! - Basic tree operations with the custom hasher

use merkle_sum_sparse_tree::{Hasher, Leaf, MemoryDb, MSSMT};
use sha2::{Digest, Sha256};

// Custom hasher that uses SHA256 but adds a prefix to the input
#[derive(Clone)]
struct PrefixedSha256;

impl Hasher<32> for PrefixedSha256 {
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Add a custom prefix to the input
        hasher.update(b"custom_prefix:");
        hasher.update(data);
        hasher.finalize().into()
    }
}

fn main() {
    // Create a new tree with our custom hasher
    let db = Box::new(MemoryDb::<32, PrefixedSha256>::new());
    let mut tree = MSSMT::<32, PrefixedSha256, ()>::new(db).unwrap();

    // Insert a leaf
    let prefixed_leaf = Leaf::new(vec![1, 2, 3], 100);
    tree.insert([1; 32], prefixed_leaf.clone()).unwrap();

    // Get the root hash
    let root = tree.root().unwrap();
    println!("Root hash with custom hasher: {}", hex::encode(root.hash()));

    // Compare with standard SHA256
    let standard_db = Box::new(MemoryDb::<32, Sha256>::new());
    let mut standard_tree = MSSMT::<32, Sha256, ()>::new(standard_db).unwrap();
    let standard_leaf = Leaf::new(vec![1, 2, 3], 100);
    standard_tree.insert([1; 32], standard_leaf).unwrap();
    let standard_root = standard_tree.root().unwrap();
    println!(
        "Root hash with standard SHA256: {}",
        hex::encode(standard_root.hash())
    );

    // Note that the hashes are different due to our custom prefix
    println!("\nThe hashes are different because our custom hasher adds a prefix to the input.");
}
