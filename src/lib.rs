//! Merkle Sum Sparse Merkle Tree implementation
//!
//! This crate provides an implementation of a Merkle Sum Sparse Merkle Tree (MSSMT) based on this implementation https://github.com/lightninglabs/taproot-assets/tree/main/mssmt,
//! which combines the properties of both Merkle Sum Trees and Sparse Merkle Trees.
//!
//! The tree supports:
//! - Efficient sparse storage
//! - Sum aggregation at each level
//! - Cryptographic verification
//! - Flexible storage backend through the `Db` trait

mod db;
mod error;
mod node;
mod proof;
mod tree;

pub use db::{Db, MemoryDb, ThreadSafe};
pub use error::TreeError;
pub use node::{Branch, CompactLeaf, ComputedNode, EmptyLeaf, Hasher, Leaf, Node};
pub use proof::{CompressedProof, Proof};
pub use tree::{walk_up, CompactMSSMT, EmptyTree, MSSMT};
#[cfg(test)]
mod tests;
