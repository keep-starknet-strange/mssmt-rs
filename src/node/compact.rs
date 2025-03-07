use std::fmt::Display;

use crate::EmptyTree;

use super::leaf::Leaf;
use super::Hasher;
use super::Node;
use crate::tree::bit_index;

/// A compact leaf is a leaf doesn't require all the empty parts of the path to be inserted.
/// When required we can extract all the branches on that path.
/// The node hash is the hash of the node at the top of the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactLeaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    node_hash: [u8; HASH_SIZE],
    leaf: Leaf<HASH_SIZE, H>,
    key: [u8; HASH_SIZE],
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> CompactLeaf<HASH_SIZE, H> {
    /// Creates a new compact leaf.
    pub fn new(height: usize, key: [u8; HASH_SIZE], leaf: Leaf<HASH_SIZE, H>) -> Self {
        // Walk up the path from the leaf to the top of the path
        let mut current = Node::Leaf(leaf.clone());
        let empty_tree = EmptyTree::<HASH_SIZE, H>::empty_tree();

        // Start from the last height of the tree (the leaf) and walk up to the `height` required.
        // This height is the last bit that is common with another leaf.
        for i in (height..HASH_SIZE * 8).rev() {
            // Construct all the branches on the path to the height.
            if bit_index(i, &key) == 0 {
                current = Node::new_branch(current, empty_tree[i + 1].clone());
            } else {
                current = Node::new_branch(empty_tree[i + 1].clone(), current);
            }
        }
        // Return the compact leaf with the node hash, leaf and key.
        Self {
            node_hash: current.hash(),
            leaf,
            key,
        }
    }
    /// # Safety
    ///
    /// The node hash won't be recomputed so if the provided hash is incorrect the whole tree will be incorrect
    pub unsafe fn new_with_hash(
        node_hash: [u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
        key: [u8; HASH_SIZE],
    ) -> Self {
        Self {
            node_hash,
            leaf,
            key,
        }
    }
    /// Returns the hash of the node at the top of the path.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }
    /// Returns the leaf of the compact leaf.
    pub fn leaf(&self) -> &Leaf<HASH_SIZE, H> {
        &self.leaf
    }
    /// Returns the key of the compact leaf.
    pub fn key(&self) -> &[u8; HASH_SIZE] {
        &self.key
    }
    /// Returns the sum of the leaf.
    pub fn sum(&self) -> u64 {
        self.leaf.sum()
    }
    /// Extracts the branches on the path to the leaf.
    pub fn extract(&self, height: usize) -> Node<HASH_SIZE, H> {
        let mut current = Node::Leaf(self.leaf.clone());
        let empty_tree = EmptyTree::<HASH_SIZE, H>::empty_tree();

        // Walk up and recreate the missing branches
        for j in (height + 2..=(HASH_SIZE * 8)).rev() {
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
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for CompactLeaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compact {{ hash: {}, leaf: {} }}",
            hex::encode(self.hash().as_slice()),
            self.leaf(),
        )
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use sha2::Sha256;

    use crate::{CompactLeaf, Leaf};

    #[test]
    fn test_compact_leaf_new() {
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        let compact_leaf = CompactLeaf::new(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            leaf,
        );
        assert_eq!(
            compact_leaf.hash(),
            hex!("acd89d5503896be78b9cc1162604ddd0c2a25fe77b73d2420b816b5da28e1f5d")
        );
    }

    #[test]
    fn test_compact_leaf_extract_keep_sum() {
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        let compact_leaf = CompactLeaf::new(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            leaf,
        );
        let extracted = compact_leaf.extract(0);
        assert_eq!(extracted.sum(), 1);
    }

    #[test]
    fn test_compact_leaf_new_with_hash() {
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        let compact_leaf = CompactLeaf::new(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            leaf.clone(),
        );
        let compact_leaf = unsafe {
            CompactLeaf::new_with_hash(
                compact_leaf.hash(),
                leaf,
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            )
        };
        assert_eq!(
            compact_leaf.hash(),
            hex!("acd89d5503896be78b9cc1162604ddd0c2a25fe77b73d2420b816b5da28e1f5d")
        );
    }

    #[test]
    fn test_compact_leaf_display() {
        let leaf = Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        let compact_leaf = CompactLeaf::new(
            0,
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            leaf,
        );
        assert_eq!(format!("{}", compact_leaf), "Compact { hash: acd89d5503896be78b9cc1162604ddd0c2a25fe77b73d2420b816b5da28e1f5d, leaf: Leaf { sum: 1, hash: 8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d, value: [1, 2, 3] } }");
    }
}
