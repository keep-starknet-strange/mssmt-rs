use std::{collections::HashMap, sync::Arc};
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};
use typenum::Unsigned;

use crate::{
    db::Db, empty_tree::{EmptyTree, TreeSize}, node::{Branch, CompactLeaf, Hasher, Leaf, Node}, ThreadSafe, TreeError
};

/// A simple in-memory database implementation for testing
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDb<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    #[serde_as(as = "HashMap<Bytes, _>")]
    branches: HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>>,
    #[serde_as(as = "HashMap<Bytes, _>")]
    leaves: HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>>,
    #[serde_as(as = "HashMap<Bytes, _>")]
    compact_leaves: HashMap<[u8; HASH_SIZE], CompactLeaf<HASH_SIZE, H>>,
    #[serde(skip, default = "EmptyTree::empty_tree")]
    empty_tree: Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]>,
    root: Option<Branch<HASH_SIZE, H>>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> MemoryDb<HASH_SIZE, H> {
    pub fn new() -> Self {
        Self {
            branches: HashMap::new(),
            leaves: HashMap::new(),
            compact_leaves: HashMap::new(),
            empty_tree: EmptyTree::<HASH_SIZE, H>::empty_tree(),
            root: None,
        }
    }
    pub fn get_branches(&self) -> &HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>> {
        &self.branches
    }
    pub fn get_leaves(&self) -> &HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>> {
        &self.leaves
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Default for MemoryDb<HASH_SIZE, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone + ThreadSafe> Db<HASH_SIZE, H> for MemoryDb<HASH_SIZE, H> {
    type DbError = ();

    fn get_root_node(&self) -> Option<Branch<HASH_SIZE, H>> {
        self.root.clone()
    }

    fn get_children(
        &self,
        height: usize,
        key: [u8; HASH_SIZE],
    ) -> Result<(Node<HASH_SIZE, H>, Node<HASH_SIZE, H>), TreeError<Self::DbError>> {
        let get_node = |height: usize, key: [u8; HASH_SIZE]| {
            if key == self.empty_tree()[height].hash() {
                self.empty_tree()[height].clone()
            } else if let Some(node) = self.branches.get(&key) {
                Node::Branch(node.clone())
            } else if let Some(leaf) = self.leaves.get(&key) {
                Node::Leaf(leaf.clone())
            } else if let Some(compact) = self.compact_leaves.get(&key) {
                Node::Compact(compact.clone())
            } else {
                self.empty_tree()[height].clone()
            }
        };
        let node = get_node(height, key);
        if key != self.empty_tree()[height].hash()
            && node.hash() == self.empty_tree()[height].hash()
        {
            return Err(TreeError::NodeNotFound);
        }
        if let Node::Branch(branch) = node {
            Ok((
                get_node(height + 1, branch.left().hash()),
                get_node(height + 1, branch.right().hash()),
            ))
        } else {
            Err(TreeError::NodeNotBranch)
        }
    }

    fn insert_leaf(&mut self, leaf: Leaf<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>> {
        self.leaves.insert(leaf.hash(), leaf);
        Ok(())
    }

    fn insert_branch(&mut self, branch: Branch<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>> {
        self.branches.insert(branch.hash(), branch);
        Ok(())
    }

    fn insert_compact_leaf(&mut self, compact_leaf: CompactLeaf<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>> {
        self.compact_leaves.insert(compact_leaf.hash(), compact_leaf);
        Ok(())
    }

    fn empty_tree(&self) -> Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]> {
        self.empty_tree.clone()
    }

    fn update_root(&mut self, root: Branch<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>> {
        self.root = Some(root);
        Ok(())
    }

    fn delete_branch(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>> {
        self.branches.remove(key).ok_or(TreeError::NodeNotFound)?;
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>> {
        self.leaves.remove(key).ok_or(TreeError::NodeNotFound)?;
        Ok(())
    }

    fn delete_compact_leaf(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>> {
        self.compact_leaves.remove(key).ok_or(TreeError::NodeNotFound)?;
        Ok(())
    }
} 