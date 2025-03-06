use std::sync::Arc;
use std::{fmt::Display, marker::PhantomData};

use super::{Hasher, Sum};
use super::Node;

/// A branch is a node that has exactly 2 children. Those children can either be
/// empty leaves or regular leaves.
/// Those nodes hold the sum of all their descendants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    left: Arc<Node<HASH_SIZE, H>>,
    right: Arc<Node<HASH_SIZE, H>>,
    sum: Sum,
    node_hash: [u8; HASH_SIZE],
    _phantom: PhantomData<H>,
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Branch<HASH_SIZE, H> {
    /// Creates a new [`Branch`]. This function performs a hash and an addition.
    pub fn new(left: Node<HASH_SIZE, H>, right: Node<HASH_SIZE, H>) -> Self {
        let sum = left.sum() + right.sum();
        let node_hash = H::hash(
            [
                left.hash().as_slice(),
                right.hash().as_slice(),
                sum.to_be_bytes().as_slice(),
            ]
            .concat()
            .as_slice(),
        );

        Self {
            sum,
            left: Arc::new(left),
            right: Arc::new(right),
            node_hash,
            _phantom: PhantomData,
        }
    }

    pub fn new_with_arc_children(
        left: Arc<Node<HASH_SIZE, H>>,
        right: Arc<Node<HASH_SIZE, H>>,
    ) -> Self {
        let sum = left.sum() + right.sum();
        let node_hash = H::hash(
            [
                left.hash().as_slice(),
                right.hash().as_slice(),
                sum.to_be_bytes().as_slice(),
            ]
            .concat()
            .as_slice(),
        );

        Self {
            sum,
            left,
            right,
            node_hash,
            _phantom: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The node hash won't be recomputed so if the provided hash is incorrect the whole tree will be incorrect
    pub unsafe fn new_with_hash(
        left: Node<HASH_SIZE, H>,
        right: Node<HASH_SIZE, H>,
        node_hash: [u8; HASH_SIZE],
        sum: Sum,
    ) -> Self {
        Self {
            sum,
            left: Arc::new(left),
            right: Arc::new(right),
            node_hash,
            _phantom: PhantomData,
        }
    }

    /// Creates a new branch with 2 empty leaves.
    pub fn empty_branch() -> Self {
        let leaf = Node::new_empty_leaf();
        Self::new(leaf.clone(), leaf)
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }

    pub fn sum(&self) -> Sum {
        self.sum
    }

    /// Returns the left and right children of this branch.
    pub fn children(&self) -> (&Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>) {
        (&self.left, &self.right)
    }

    /// Returns the left children of this branch.
    pub fn left(&self) -> &Node<HASH_SIZE, H> {
        &self.left
    }

    /// Returns the right children of this branch.
    pub fn right(&self) -> &Node<HASH_SIZE, H> {
        &self.right
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Branch<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Branch {{ sum: {}, hash: {} }}",
            self.sum(),
            hex::encode(self.hash().as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::Branch;
    use crate::{node::Node, Leaf};
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_branch_hash() {
        let branch = Branch::new(
            Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1)),
            Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2)),
        );
        assert_eq!(
            branch.hash(),
            hex!("c3171e69d789087eea2e9a1f0a7cb0068421e5af3727455ea5ec24ef764184a6")
        );
    }

    #[test]
    fn test_branch_with_empty_leaves() {
        assert_eq!(
            Branch::<32, Sha256>::empty_branch().hash(),
            hex!("5a61e238f07e3a8114e39670c1e5ff430913d5793028258cf8a49282efee4411")
        )
    }

    #[test]
    fn test_branch_sum() {
        let branch = Branch::new(
            Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1)),
            Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2)),
        );
        assert_eq!(branch.sum(), 3);
    }

    #[test]
    fn test_branch_left_and_right() {
        let left = Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1));
        let right = Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2));
        let branch = Branch::new(left.clone(), right.clone());
        assert_eq!(branch.left().hash(), left.hash());
        assert_eq!(branch.right().hash(), right.hash());
    }

    #[test]
    fn test_branch_children() {
        let left = Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1));
        let right = Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2));
        let branch = Branch::new(left.clone(), right.clone());
        let (children_left, children_right) = branch.children();
        assert_eq!(children_left.hash(), left.hash());
        assert_eq!(children_right.hash(), right.hash());
    }

    #[test]
    fn test_branch_display() {
        let branch = Branch::new(
            Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1)),
            Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2)),
        );
        assert_eq!(format!("{}", branch), "Branch { sum: 3, hash: c3171e69d789087eea2e9a1f0a7cb0068421e5af3727455ea5ec24ef764184a6 }");
    }

    #[test]
    fn test_branch_new_with_arc_children() {
        let left = Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1));
        let right = Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2));
        let branch = Branch::new_with_arc_children(Arc::new(left), Arc::new(right));
        assert_eq!(
            branch.hash(),
            hex!("c3171e69d789087eea2e9a1f0a7cb0068421e5af3727455ea5ec24ef764184a6")
        );
    }

    #[test]
    fn test_branch_new_with_hash() {
        let left = Node::Leaf(Leaf::<32, Sha256>::new(vec![1, 2, 3], 1));
        let right = Node::Leaf(Leaf::<32, Sha256>::new(vec![4, 5, 6], 2));
        let branch = unsafe {
            Branch::new_with_hash(
                left,
                right,
                hex!("c3171e69d789087eea2e9a1f0a7cb0068421e5af3727455ea5ec24ef764184a6"),
                3,
            )
        };
        assert_eq!(
            branch.hash(),
            hex!("c3171e69d789087eea2e9a1f0a7cb0068421e5af3727455ea5ec24ef764184a6")
        );
    }
}
