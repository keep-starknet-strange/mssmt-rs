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
mod empty_tree;
mod error;
mod memory_db;
mod node;
mod tree;

pub use db::{Db, ThreadSafe};
pub use empty_tree::{EmptyTree, TreeSize};
pub use error::TreeError;
pub use memory_db::MemoryDb;
pub use node::{Branch, CompactLeaf, EmptyLeaf, Hasher, Leaf, Node};
pub use tree::CompactMSSMT;
pub use tree::MSSMT;

#[cfg(test)]
mod tests;
