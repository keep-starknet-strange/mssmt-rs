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

use node::{Branch, CompactLeaf, Hasher, Leaf, Node};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use tree::{Db, TreeBuilder};

pub mod compact_tree;
pub mod node;
#[cfg(test)]
mod tests;
pub mod tree;
/// A simple in-memory database implementation for testing
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryDb<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    #[serde_as(as = "HashMap<Bytes, _>")]
    branches: HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>>,
    #[serde_as(as = "HashMap<Bytes, _>")]
    leaves: HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>>,
    #[serde_as(as = "HashMap<Bytes, _>")]
    compact_leaves: HashMap<[u8; HASH_SIZE], CompactLeaf<HASH_SIZE, H>>,
    root_node: Option<Branch<HASH_SIZE, H>>,
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Db<HASH_SIZE, H>
    for MemoryDb<HASH_SIZE, H>
{
    fn get_root_node(&self) -> Option<Branch<HASH_SIZE, H>> {
        self.root_node.clone()
    }

    fn get_branch(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Branch<HASH_SIZE, H>> {
        self.branches.get(key).cloned()
    }
    fn get_leaf(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Leaf<HASH_SIZE, H>> {
        self.leaves.get(key).cloned()
    }
    fn get_compact_leaf(&self, key: &[u8; HASH_SIZE]) -> Option<CompactLeaf<HASH_SIZE, H>> {
        self.compact_leaves.get(key).cloned()
    }
    fn get_children(
        &self,
        height: usize,
        key: [u8; HASH_SIZE],
    ) -> (Node<HASH_SIZE, H>, Node<HASH_SIZE, H>) {
        let get_node = |height: usize, key: [u8; HASH_SIZE]| {
            if key == TreeBuilder::<HASH_SIZE, H>::empty_tree()[height].hash() {
                TreeBuilder::empty_tree()[height].clone()
            } else if let Some(node) = self.get_branch(&key) {
                Node::Branch(node)
            } else if let Some(leaf) = self.get_leaf(&key) {
                Node::Leaf(leaf)
            } else if let Some(compact) = self.get_compact_leaf(&key) {
                Node::Compact(compact)
            } else {
                TreeBuilder::empty_tree()[height].clone()
            }
        };
        let node = get_node(height, key);
            if key != TreeBuilder::<HASH_SIZE, H>::empty_tree()[height].hash() && node.hash() == TreeBuilder::<HASH_SIZE, H>::empty_tree()[height].hash() {
            panic!("node not found")
        }
        if let Node::Branch(branch) = node {
            (
                get_node(height + 1, branch.left().hash()),
                get_node(height + 1, branch.right().hash()),
            )
        } else {
            panic!("Should be a branch node")
        }
    }
    fn insert_branch(&mut self, branch: crate::node::Branch<HASH_SIZE, H>) {
        self.branches.insert(branch.hash(), branch);
    }
    fn insert_leaf(&mut self, leaf: crate::node::Leaf<HASH_SIZE, H>) {
        self.leaves.insert(leaf.hash(), leaf);
    }
    fn insert_compact_leaf(&mut self, compact_leaf: CompactLeaf<HASH_SIZE, H>) {
        self.compact_leaves.insert(compact_leaf.hash(), compact_leaf);
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

    fn delete_compact_leaf(&mut self, key: &[u8; HASH_SIZE]) {
        self.compact_leaves.remove(key);
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> MemoryDb<HASH_SIZE, H> {
    pub fn get_branches(&self) -> &HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>> {
        &self.branches
    }
    pub fn get_leaves(&self) -> &HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>> {
        &self.leaves
    }
}
