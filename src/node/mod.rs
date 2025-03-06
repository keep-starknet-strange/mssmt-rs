mod branch;
mod compact;
mod computed;
mod empty;
mod leaf;

use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::fmt::Display;

pub use branch::Branch;
pub use compact::CompactLeaf;
pub use computed::ComputedNode;
pub use empty::EmptyLeaf;
pub use leaf::Leaf;

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
#[derive(Clone, PartialEq, Eq)]
pub enum Node<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    /// A leaf node containing a value and sum
    Leaf(Leaf<HASH_SIZE, H>),
    /// A branch node with two children
    Branch(Branch<HASH_SIZE, H>),
    /// A compact leaf node containing a value and sum
    Compact(CompactLeaf<HASH_SIZE, H>),
    /// A computed node
    Computed(ComputedNode<HASH_SIZE>),
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Debug for Node<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Leaf(leaf) => {
                write!(
                    f,
                    "Leaf {{ sum: {}, hash: {:?}, value: {:?} }}",
                    leaf.sum(),
                    leaf.hash(),
                    leaf.value()
                )
            }
            Self::Branch(branch) => write!(
                f,
                "Branch {{ sum: {}, hash: {:?} }}",
                branch.sum(),
                branch.hash()
            ),
            Self::Compact(compact) => write!(
                f,
                "Compact {{ sum: {}, hash: {:?} }}",
                compact.sum(),
                compact.hash()
            ),
            Self::Computed(computed) => write!(
                f,
                "Computed {{ sum: {}, hash: {:?} }}",
                computed.sum(),
                computed.hash()
            ),
        }
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Node<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            Self::Leaf(leaf) => format!("{}", leaf),
            Self::Branch(branch) => format!("{}", branch),
            Self::Compact(compact) => format!("{}", compact),
            Self::Computed(computed) => format!("{}", computed),
        })
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
    pub fn new_empty_leaf() -> Self {
        Self::Leaf(Leaf::<HASH_SIZE, H>::Empty(EmptyLeaf::<HASH_SIZE, H>::new()))
    }

    /// Returns the hash of the node. NO HASHING IS DONE HERE.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Branch(branch) => branch.hash(),
            Self::Compact(compact) => compact.hash(),
            Self::Computed(computed) => computed.hash(),
        }
    }

    /// Returns the sum of a [`Node`]. NO OPERATION IS DONE HERE.
    pub fn sum(&self) -> Sum {
        match self {
            Self::Leaf(leaf) => leaf.sum(),
            Self::Branch(branch) => branch.sum(),
            Self::Compact(compact) => compact.sum(),
            Self::Computed(computed) => computed.sum(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{node::ComputedNode, CompactLeaf, Leaf};

    use super::Node;
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_computed_node() {
        let computed = ComputedNode::<32>::new(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            1,
        );
        let computed_node = Node::<32, Sha256>::Computed(computed.clone());
        assert_eq!(computed_node.hash(), computed.hash());
        assert_eq!(computed_node.sum(), computed.sum());
    }

    #[test]
    fn test_new_leaf() {
        let leaf = Node::<32, Sha256>::new_leaf(vec![1, 2, 3], 1);
        assert_eq!(
            leaf.hash(),
            hex!("8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d")
        );
    }

    #[test]
    fn test_node_display() {
        let leaf = Node::<32, Sha256>::new_leaf(vec![1, 2, 3], 1);
        assert_eq!(format!("{}", leaf), "Leaf { sum: 1, hash: 8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d, value: [1, 2, 3] }");
        let branch = Node::<32, Sha256>::new_branch(leaf.clone(), leaf.clone());
        assert_eq!(format!("{}", branch), "Branch { sum: 2, hash: 8ddaeb6bfdb6365fa5ec597b706b71ab8cf3bfca3a36d66493fc790aeac2d157 }");
        let compact = Node::<32, Sha256>::Compact(CompactLeaf::<32, Sha256>::new(
            1,
            hex!("8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d"),
            Leaf::<32, Sha256>::new(vec![1, 2, 3], 1),
        ));
        assert_eq!(format!("{}", compact), "Compact { hash: 64e1cbaf8280fe4e534d612276ab9d3988adc8174278c28d528202a936c402dc, leaf: Leaf { sum: 1, hash: 8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d, value: [1, 2, 3] } }");
        let empty = Node::<32, Sha256>::new_empty_leaf();
        assert_eq!(format!("{}", empty), "Empty { sum: 0, hash: af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc }");
        let computed = Node::<32, Sha256>::Computed(ComputedNode::<32>::new(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            1,
        ));
        assert_eq!(format!("{}", computed), "Computed { sum: 1, hash: 0000000000000000000000000000000000000000000000000000000000000000 }");
    }

    #[test]
    fn test_node_debug() {
        let leaf = Node::<32, Sha256>::new_leaf(vec![1, 2, 3], 1);
        assert_eq!(format!("{:?}", leaf), "Leaf { sum: 1, hash: [139, 172, 169, 78, 212, 159, 203, 83, 48, 115, 66, 204, 16, 162, 73, 112, 201, 214, 99, 9, 121, 77, 85, 175, 21, 50, 186, 96, 41, 231, 221, 141], value: [1, 2, 3] }");
        let branch = Node::<32, Sha256>::new_branch(leaf.clone(), leaf.clone());
        assert_eq!(format!("{:?}", branch), "Branch { sum: 2, hash: [141, 218, 235, 107, 253, 182, 54, 95, 165, 236, 89, 123, 112, 107, 113, 171, 140, 243, 191, 202, 58, 54, 214, 100, 147, 252, 121, 10, 234, 194, 209, 87] }");
        let compact = Node::<32, Sha256>::Compact(CompactLeaf::<32, Sha256>::new(
            1,
            hex!("8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d"),
            Leaf::<32, Sha256>::new(vec![1, 2, 3], 1),
        ));
        assert_eq!(format!("{:?}", compact), "Compact { sum: 1, hash: [100, 225, 203, 175, 130, 128, 254, 78, 83, 77, 97, 34, 118, 171, 157, 57, 136, 173, 200, 23, 66, 120, 194, 141, 82, 130, 2, 169, 54, 196, 2, 220] }");
        let empty = Node::<32, Sha256>::new_empty_leaf();
        assert_eq!(format!("{:?}", empty), "Leaf { sum: 0, hash: [175, 85, 112, 245, 161, 129, 11, 122, 247, 140, 175, 75, 199, 10, 102, 15, 13, 245, 30, 66, 186, 249, 29, 77, 229, 178, 50, 141, 224, 232, 61, 252], value: [] }");
        let computed = Node::<32, Sha256>::Computed(ComputedNode::<32>::new(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            1,
        ));
        assert_eq!(format!("{:?}", computed), "Computed { sum: 1, hash: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }");
    }
}
