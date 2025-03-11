use std::{any::Any, collections::HashMap, sync::Arc};

use typenum::Unsigned;

use crate::{
    db::Db,
    node::{Branch, CompactLeaf, Hasher, Leaf, Node},
    tree::{EmptyTree, TreeSize},
    ThreadSafe, TreeError,
};

/// A simple in-memory database implementation for testing
#[derive(Debug, Clone)]
pub struct MemoryDb<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    branches: HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>>,
    leaves: HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>>,
    compact_leaves: HashMap<[u8; HASH_SIZE], CompactLeaf<HASH_SIZE, H>>,
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
    pub fn get_compact_leaves(&self) -> &HashMap<[u8; HASH_SIZE], CompactLeaf<HASH_SIZE, H>> {
        &self.compact_leaves
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Default for MemoryDb<HASH_SIZE, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone + ThreadSafe> Db<HASH_SIZE, H>
    for MemoryDb<HASH_SIZE, H>
{
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
            Err(TreeError::ExpectedBranch)
        }
    }

    fn insert_leaf(&mut self, leaf: Leaf<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>> {
        self.leaves.insert(leaf.hash(), leaf);
        Ok(())
    }

    fn insert_branch(
        &mut self,
        branch: Branch<HASH_SIZE, H>,
    ) -> Result<(), TreeError<Self::DbError>> {
        self.branches.insert(branch.hash(), branch);
        Ok(())
    }

    fn insert_compact_leaf(
        &mut self,
        compact_leaf: CompactLeaf<HASH_SIZE, H>,
    ) -> Result<(), TreeError<Self::DbError>> {
        self.compact_leaves
            .insert(compact_leaf.hash(), compact_leaf);
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
        self.branches.remove(key);
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>> {
        self.leaves.remove(key);
        Ok(())
    }

    fn delete_compact_leaf(
        &mut self,
        key: &[u8; HASH_SIZE],
    ) -> Result<(), TreeError<Self::DbError>> {
        self.compact_leaves.remove(key);
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use super::Db;
    use crate::{Branch, Leaf, MemoryDb, Node, TreeError};
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_memory_db_new() {
        let db = MemoryDb::<32, Sha256>::new();
        assert_eq!(db.empty_tree().len(), 257);
    }

    #[test]
    fn test_memory_db_get_root_node() {
        let db = MemoryDb::<32, Sha256>::new();
        assert!(db.get_root_node().is_none());
    }

    #[test]
    fn test_memory_db_get_children() {
        let mut db = MemoryDb::<32, Sha256>::new();
        assert_eq!(
            db.get_children(
                0,
                hex!("0000000000000000000000000000000000000000000000000000000000000000")
            )
            .unwrap_err(),
            TreeError::NodeNotFound
        );
        let Node::Branch(empty_root) = db.empty_tree()[0].clone() else {
            panic!("Empty root is not a branch");
        };
        db.insert_branch(empty_root.clone()).unwrap();
        let (children_left, children_right) = db.get_children(0, empty_root.hash()).unwrap();
        assert_eq!(children_left.hash(), db.empty_tree()[1].hash());
        assert_eq!(children_right.hash(), db.empty_tree()[1].hash());
    }

    #[test]
    fn test_memory_db_insert_leaf() {
        let mut db = MemoryDb::<32, Sha256>::new();
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        db.insert_leaf(leaf).unwrap();
        assert_eq!(db.get_leaves().len(), 1);
    }

    #[test]
    fn test_memory_db_delete_leaf() {
        let mut db = MemoryDb::<32, Sha256>::new();
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        db.insert_leaf(leaf.clone()).unwrap();
        db.delete_leaf(&leaf.hash()).unwrap();
        assert_eq!(db.get_leaves().len(), 0);
    }

    #[test]
    fn test_memory_db_insert_branch() {
        let mut db = MemoryDb::<32, Sha256>::new();
        let branch = Branch::new(Node::new_empty_leaf(), Node::new_empty_leaf());
        db.insert_branch(branch).unwrap();
        assert_eq!(db.get_branches().len(), 1);
    }

    #[test]
    fn test_memory_db_get_children_leaf() {
        let mut db = MemoryDb::<32, Sha256>::new();
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        db.insert_leaf(leaf.clone()).unwrap();
        assert_eq!(
            db.get_children(0, leaf.hash()).unwrap_err(),
            TreeError::ExpectedBranch
        );
    }
}
