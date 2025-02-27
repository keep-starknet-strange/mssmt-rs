use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
#[cfg(test)]
use std::fmt::Display;
use std::{marker::PhantomData, sync::Arc};

use crate::tree::{bit_index, TreeBuilder};

impl Hasher<32> for Sha256 {
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

pub type Sum = u64;

/// Simple hash trait required to hash the nodes in the tree
///
/// # Type Parameters
/// * `HASH_SIZE` - The size of the hash digest in bytes
pub trait Hasher<const HASH_SIZE: usize> {
    fn hash(data: &[u8]) -> [u8; HASH_SIZE];
}

/// All possible nodes in the tree.
///
/// # Type Parameters
/// * `HASH_SIZE` - The size of the hash digest in bytes
/// * `H` - The hasher implementation used for this node
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Node<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    /// A leaf node containing a value and sum
    Leaf(Leaf<HASH_SIZE, H>),
    /// A branch node with two children
    Branch(Branch<HASH_SIZE, H>),
    /// A compact leaf node containing a value and sum
    Compact(CompactLeaf<HASH_SIZE, H>),
    /// An empty leaf representing unset branches
    Empty(EmptyLeaf<HASH_SIZE, H>),
}

/// Utils for debugging purpose.
#[cfg(test)]
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Node<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.hash()).as_str())
    }
}
#[cfg(test)]
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Branch<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.hash()).as_str())
    }
}
#[cfg(test)]
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for CompactLeaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.hash()).as_str())
    }
}
#[cfg(test)]
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Leaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.hash()).as_str())
    }
}

/// Represents an empty leaf in the tree. Those leaves have no `value` and hold `0` as sum value.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmptyLeaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    #[serde_as(as = "Bytes")]
    node_hash: [u8; HASH_SIZE],
    #[serde(skip)]
    _phantom: PhantomData<H>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Default for EmptyLeaf<HASH_SIZE, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> EmptyLeaf<HASH_SIZE, H> {
    /// Creates a new [`EmptyLeaf`]. This function performs a hash.
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update([]);
        hasher.update([0; 8]);

        Self {
            node_hash: H::hash([0; 8].as_slice()),
            _phantom: PhantomData,
        }
    }

    /// Returns the hash of the node. No hash happening in this function.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }
    pub fn sum(&self) -> Sum {
        0
    }
}

/// A Leaf is a node that has no children and simply hold information.
/// They are the last row of the tree.
/// Each leaf contains a `value`
/// represented as bytes and a `sum` which is an integer.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    value: Vec<u8>,
    sum: Sum,
    #[serde_as(as = "Bytes")]
    node_hash: [u8; HASH_SIZE],
    #[serde(skip)]
    _phantom: PhantomData<H>,
}

/// A branch is a node that has exactly 2 children. Those children can either be
/// empty leaves or regular leaves.
/// Those nodes hold the sum of all their descendants.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Branch<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    left: Arc<Node<HASH_SIZE, H>>,
    right: Arc<Node<HASH_SIZE, H>>,
    sum: Sum,
    #[serde_as(as = "Bytes")]
    node_hash: [u8; HASH_SIZE],
    #[serde(skip)]
    _phantom: PhantomData<H>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    From<(Branch<HASH_SIZE, H>, Branch<HASH_SIZE, H>)> for Node<HASH_SIZE, H>
{
    fn from((left, right): (Branch<HASH_SIZE, H>, Branch<HASH_SIZE, H>)) -> Self {
        Self::new_branch(Self::Branch(left), Self::Branch(right))
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    From<(Arc<Node<HASH_SIZE, H>>, Arc<Node<HASH_SIZE, H>>)> for Node<HASH_SIZE, H>
{
    fn from((left, right): (Arc<Node<HASH_SIZE, H>>, Arc<Node<HASH_SIZE, H>>)) -> Self {
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

        Self::Branch(Branch {
            sum,
            left,
            right,
            node_hash,
            _phantom: PhantomData,
        })
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    From<(Node<HASH_SIZE, H>, Node<HASH_SIZE, H>)> for Node<HASH_SIZE, H>
{
    fn from((left, right): (Node<HASH_SIZE, H>, Node<HASH_SIZE, H>)) -> Self {
        Self::new_branch(left, right)
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    From<(Node<HASH_SIZE, H>, Branch<HASH_SIZE, H>)> for Node<HASH_SIZE, H>
{
    fn from((left, right): (Self, Branch<HASH_SIZE, H>)) -> Self {
        Self::new_branch(left, Self::Branch(right))
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    From<(Branch<HASH_SIZE, H>, Node<HASH_SIZE, H>)> for Node<HASH_SIZE, H>
{
    fn from((left, right): (Branch<HASH_SIZE, H>, Self)) -> Self {
        Self::new_branch(Self::Branch(left), right)
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Node<HASH_SIZE, H> {
    /// Creates a [`Node::Branch`] from 2 [`Node`]
    pub fn new_branch(left: Node<HASH_SIZE, H>, right: Node<HASH_SIZE, H>) -> Self {
        Self::Branch(Branch::<HASH_SIZE, H>::new(left, right))
    }
    /// Creates a [`Node::Leaf`] from a `value` and a `sum`
    pub fn new_leaf(value: Vec<u8>, sum: Sum) -> Self {
        Self::Leaf(Leaf::<HASH_SIZE, H>::new(value, sum))
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Branch(branch) => branch.hash(),
            Self::Empty(empty) => empty.hash(),
            Self::Compact(compact) => compact.hash(),
        }
    }

    /// Returns the sum of a [`Node`]. NO OPERATION IS DONE HERE.
    pub fn sum(&self) -> Sum {
        match self {
            Self::Leaf(leaf) => leaf.sum,
            Self::Branch(branch) => branch.sum,
            Self::Empty(empty) => empty.sum(),
            Self::Compact(compact) => compact.sum(),
        }
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Leaf<HASH_SIZE, H> {
    /// Creates a new [`Leaf`]. This function performs a hash.
    pub fn new(value: Vec<u8>, sum: Sum) -> Self {
        let node_hash = H::hash(
            [value.as_slice(), sum.to_be_bytes().as_slice()]
                .concat()
                .as_slice(),
        );
        Self {
            value,
            sum,
            node_hash,
            _phantom: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The node hash won't be recomputed so if the provided hash is incorrect the whole tree will be incorrect
    pub unsafe fn new_with_hash(value: Vec<u8>, sum: Sum, node_hash: [u8; HASH_SIZE]) -> Self {
        Self {
            value,
            sum,
            node_hash,
            _phantom: PhantomData,
        }
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }
    pub fn sum(&self) -> Sum {
        self.sum
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
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
        let leaf = Node::<HASH_SIZE, H>::Empty(EmptyLeaf::<HASH_SIZE, H>::new());
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

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactLeaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    #[serde_as(as = "Bytes")]
    node_hash: [u8; HASH_SIZE],
    leaf: Leaf<HASH_SIZE, H>,
    #[serde_as(as = "Bytes")]
    key: [u8; HASH_SIZE],
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> CompactLeaf<HASH_SIZE, H> {
    pub fn new_compact_leaf(height: usize, key: [u8; HASH_SIZE], leaf: Leaf<HASH_SIZE, H>) -> Self {
        let mut current = Node::Leaf(leaf.clone());
        let empty_tree = TreeBuilder::<HASH_SIZE, H>::empty_tree();

        for i in (height..HASH_SIZE * 8).rev() {
            if bit_index(i, &key) == 0 {
                current = Node::new_branch(current, empty_tree[i + 1].clone());
            } else {
                current = Node::new_branch(empty_tree[i + 1].clone(), current);
            }
        }

        Self {
            node_hash: current.hash(),
            leaf,
            key,
        }
    }
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }
    pub fn leaf(&self) -> &Leaf<HASH_SIZE, H> {
        &self.leaf
    }
    pub fn key(&self) -> &[u8; HASH_SIZE] {
        &self.key
    }
    pub fn sum(&self) -> u64 {
        self.leaf.sum()
    }
    pub fn extract(&self, height: usize) -> Node<HASH_SIZE, H> {
        let mut current = Node::Leaf(self.leaf.clone());
        let empty_tree = TreeBuilder::<HASH_SIZE, H>::empty_tree();

        // Walk up and recreate the missing branches
        for j in (height + 1..HASH_SIZE * 8).rev() {
            let (left, right) = if bit_index(j - 1, &self.key) == 0 {
                (current, empty_tree[j].clone())
            } else {
                (empty_tree[j].clone(), current)
            };

            current = Node::new_branch(left, right);
        }

        current
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use sha2::Sha256;

    use crate::node::Branch;
    #[test]
    fn test_empty_leaf_node_hash() {
        assert_eq!(
            super::EmptyLeaf::<32, Sha256>::new().hash(),
            hex!("af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc")
        )
    }
    #[test]
    fn test_non_empty_leaf_node_hash() {
        assert_eq!(
            super::Leaf::<32, Sha256>::new(
                vec![
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 26, 28, 29, 30, 31, 32
                ],
                1
            )
            .hash(),
            hex!("be7354c2c1c189bc64c3c4092e7141d6880936f15cd08e8498a53df99de724c4")
        )
    }

    #[test]
    fn test_branch_with_empty_leaves() {
        assert_eq!(
            Branch::<32, Sha256>::empty_branch().node_hash,
            hex!("5a61e238f07e3a8114e39670c1e5ff430913d5793028258cf8a49282efee4411")
        )
    }
}
