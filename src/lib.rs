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

use std::collections::HashMap;

use node::{Branch, Hasher, Leaf};
use tree::Db;

pub mod node;
#[cfg(test)]
mod tests;
pub mod tree;
/// A simple in-memory database implementation for testing
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryDb<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    branches: HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>>,
    leaves: HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>>,
    root_node: Option<Branch<HASH_SIZE, H>>,
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Db<HASH_SIZE, H>
    for MemoryDb<HASH_SIZE, H>
{
    fn get_root_node(&self) -> crate::node::Branch<HASH_SIZE, H> {
        self.root_node.clone().unwrap()
    }

    fn get_branch(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Branch<HASH_SIZE, H>> {
        self.branches.get(key).cloned()
    }
    fn get_leaf(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Leaf<HASH_SIZE, H>> {
        self.leaves.get(key).cloned()
    }

    fn insert_leaf(&mut self, leaf: crate::node::Leaf<HASH_SIZE, H>) {
        self.leaves.insert(leaf.hash(), leaf);
    }

    fn update_root(&mut self, root: crate::node::Branch<HASH_SIZE, H>) {
        self.root_node = Some(root)
    }

    fn delete_branch(&mut self, key: &[u8; HASH_SIZE]) {
        self.branches.remove(key);
    }

    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]) {
        self.leaves.remove(key);
    }

    fn insert_branch(&mut self, branch: crate::node::Branch<HASH_SIZE, H>) {
        self.branches.insert(branch.hash(), branch);
    }
}
