use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fmt::Display;
use std::{marker::PhantomData, sync::Arc};

impl Hasher<32> for Sha256 {
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

pub type Sum = u64;

/// Simple hash trait required to hash the nodes in the tree
pub trait Hasher<const HASH_SIZE: usize> {
    fn hash(data: &[u8]) -> [u8; HASH_SIZE];
}

/// All the possible nodes in the tree.
/// * `HASH_SIZE` - is the size of the hash digest in bytes.
///
/// Note: the Hasher should be cloneable in order to make the [`Node`] type cloneable
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    Leaf(Leaf<HASH_SIZE, H>),
    Branch(Branch<HASH_SIZE, H>),
    Empty(EmptyLeaf<HASH_SIZE, H>),
}

/// Utils for debugging purpose.
#[cfg(test)]
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Node<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(self.hash()).as_str())
    }
}

/// Represents an empty leaf in the tree. Those leaves have no `value` and hold `0` as sum value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyLeaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    node_hash: [u8; HASH_SIZE],
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
}

/// A Leaf is a node that has no children and simply hold information.
/// They are the last row of the tree.
/// Each leaf contains a `value`
/// represented as bytes and a `sum` which is an integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    value: [u8; HASH_SIZE],
    sum: Sum,
    node_hash: [u8; HASH_SIZE],
    _phantom: PhantomData<H>,
}

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
    pub fn new_leaf(value: [u8; HASH_SIZE], sum: Sum) -> Self {
        Self::Leaf(Leaf::<HASH_SIZE, H>::new(value, sum))
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Branch(branch) => branch.hash(),
            Self::Empty(empty) => empty.hash(),
        }
    }

    /// Returns the sum of a [`Node`]. NO OPERATION IS DONE HERE.
    pub fn sum(&self) -> Sum {
        match self {
            Self::Leaf(leaf) => leaf.sum,
            Self::Branch(branch) => branch.sum,
            Self::Empty(_) => 0,
        }
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Leaf<HASH_SIZE, H> {
    /// Creates a new [`Leaf`]. This function performs a hash.
    pub fn new(value: [u8; HASH_SIZE], sum: Sum) -> Self {
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

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
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

    /// Creates a new branch with 2 empty leaves.
    pub fn empty_branch() -> Self {
        let leaf = Node::<HASH_SIZE, H>::Empty(EmptyLeaf::<HASH_SIZE, H>::new());
        Self::new(leaf.clone(), leaf)
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
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
                [
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
