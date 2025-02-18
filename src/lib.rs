#![recursion_limit = "256"]

//! A Merkle Sum Sparse Merkle Tree implementation
//!
//! This crate provides an implementation of a Merkle Sum Sparse Merkle Tree (MSSMT) based on this implementation https://github.com/lightninglabs/taproot-assets/tree/main/mssmt,
//! which combines the properties of both Merkle Sum Trees and Sparse Merkle Trees.
//!
//! The tree supports:
//! - Efficient sparse storage
//! - Sum aggregation at each level
//! - Cryptographic verification
//! - Flexible storage backend through the `Db` trait

pub mod node;
#[cfg(test)]
mod tests;
pub mod tree;
