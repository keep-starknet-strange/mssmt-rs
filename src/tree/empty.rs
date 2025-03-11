//! Empty tree implementation for the Merkle Sum Sparse Merkle Tree
use std::{cell::LazyCell, marker::PhantomData, sync::Arc};

use crate::node::{Hasher, Node};

/// Helper struct to create an empty mssmt.
pub struct EmptyTree<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>(PhantomData<H>);

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> EmptyTree<HASH_SIZE, H> {
    /// Define the empty tree array size as (HASH_SIZE * 8) + 1
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY_TREE: LazyCell<Arc<Vec<Node<HASH_SIZE, H>>>> =
        LazyCell::new(|| Arc::new(Self::build_tree()));

    /// Gets an empty mssmt.
    pub fn empty_tree() -> Arc<Vec<Node<HASH_SIZE, H>>> {
        #[allow(clippy::borrow_interior_mutable_const)]
        Self::EMPTY_TREE.clone()
    }

    /// builds the empty tree
    fn build_tree() -> Vec<Node<HASH_SIZE, H>> {
        let max_height = HASH_SIZE * 8;
        let mut empty_tree = Vec::with_capacity(max_height + 1);
        let empty_leaf = Node::<HASH_SIZE, H>::new_empty_leaf();
        empty_tree.push(empty_leaf);

        for i in 1..=max_height {
            empty_tree.push(Node::new_branch(
                empty_tree[i - 1].clone(),
                empty_tree[i - 1].clone(),
            ));
        }
        empty_tree.reverse();

        let Node::Branch(_branch) = &empty_tree[0] else {
            unreachable!("Root should be a branch")
        };

        empty_tree
    }
}
