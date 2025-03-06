//! Database trait and implementations for the Merkle Sum Sparse Merkle Tree

use std::sync::Arc;
use typenum::Unsigned;

use crate::{
    node::{Branch, CompactLeaf, Hasher, Leaf, Node},
    tree::TreeSize,
    TreeError,
};

/// Thread safety marker trait
#[cfg(feature = "multi-thread")]
pub trait ThreadSafe: Send + Sync {}
#[cfg(feature = "multi-thread")]
impl<T: Send + Sync> ThreadSafe for T {}

#[cfg(not(feature = "multi-thread"))]
pub trait ThreadSafe {}
#[cfg(not(feature = "multi-thread"))]
impl<T> ThreadSafe for T {}

/// Store for the tree nodes
///
/// This trait must be implemented by any storage backend used with the tree.
/// It provides the basic operations needed to store and retrieve nodes.
pub trait Db<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>: ThreadSafe {
    /// The error type for database operations
    type DbError;

    /// Get the root node of the tree
    fn get_root_node(&self) -> Option<Branch<HASH_SIZE, H>>;

    #[allow(clippy::type_complexity)]
    /// Get the children of a node at the given height and key
    fn get_children(
        &self,
        height: usize,
        key: [u8; HASH_SIZE],
    ) -> Result<(Node<HASH_SIZE, H>, Node<HASH_SIZE, H>), TreeError<Self::DbError>>;

    /// Insert a leaf node
    fn insert_leaf(&mut self, leaf: Leaf<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>>;

    /// Insert a branch node
    fn insert_branch(
        &mut self,
        branch: Branch<HASH_SIZE, H>,
    ) -> Result<(), TreeError<Self::DbError>>;

    /// Insert a compact leaf node
    fn insert_compact_leaf(
        &mut self,
        compact_leaf: CompactLeaf<HASH_SIZE, H>,
    ) -> Result<(), TreeError<Self::DbError>>;

    /// Get the empty tree for this database
    fn empty_tree(&self) -> Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]>;

    /// Update the root node of the tree
    fn update_root(&mut self, root: Branch<HASH_SIZE, H>) -> Result<(), TreeError<Self::DbError>>;

    /// Delete a branch node
    fn delete_branch(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>>;

    /// Delete a leaf node
    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]) -> Result<(), TreeError<Self::DbError>>;

    /// Delete a compact leaf node
    fn delete_compact_leaf(
        &mut self,
        key: &[u8; HASH_SIZE],
    ) -> Result<(), TreeError<Self::DbError>>;
}
