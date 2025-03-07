use std::{fmt::Display, marker::PhantomData};

use super::{EmptyLeaf, Hasher, Sum};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    NonEmpty(NonEmptyLeaf<HASH_SIZE, H>),
    Empty(EmptyLeaf<HASH_SIZE, H>),
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Leaf<HASH_SIZE, H> {
    pub fn new(value: Vec<u8>, sum: Sum) -> Self {
        if value.is_empty() {
            Self::Empty(EmptyLeaf::new())
        } else {
            Self::NonEmpty(NonEmptyLeaf::new(value, sum))
        }
    }

    /// Creates a new leaf with a pre-computed hash.
    ///
    /// # Safety
    ///
    /// The provided hash must be correctly computed from the value and sum.
    /// If an incorrect hash is provided, the tree's integrity will be compromised.
    pub unsafe fn new_with_hash(value: Vec<u8>, sum: Sum, node_hash: [u8; HASH_SIZE]) -> Self {
        Self::NonEmpty(NonEmptyLeaf::new_with_hash(value, sum, node_hash))
    }

    /// Returns the hash of the node.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        match self {
            Self::NonEmpty(leaf) => leaf.hash(),
            Self::Empty(leaf) => leaf.hash(),
        }
    }

    /// Returns the sum of the node.
    pub fn sum(&self) -> Sum {
        match self {
            Self::NonEmpty(leaf) => leaf.sum(),
            Self::Empty(leaf) => leaf.sum(),
        }
    }

    /// Returns the value of the node.
    pub fn value(&self) -> &[u8] {
        match self {
            Self::NonEmpty(leaf) => leaf.value(),
            Self::Empty(_) => &[],
        }
    }
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for Leaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonEmpty(leaf) => write!(f, "{}", leaf),
            Self::Empty(leaf) => write!(f, "{}", leaf),
        }
    }
}

/// A Leaf is a node that has no children and simply hold information.
/// They are the last row of the tree.
/// Each leaf contains a `value`
/// represented as bytes and a `sum` which is an integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyLeaf<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    value: Vec<u8>,
    sum: Sum,
    node_hash: [u8; HASH_SIZE],
    _phantom: PhantomData<H>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> NonEmptyLeaf<HASH_SIZE, H> {
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

    /// Creates a new leaf with a pre-computed hash.
    ///
    /// # Safety
    ///
    /// The provided hash must be correctly computed from the value and sum.
    /// If an incorrect hash is provided, the tree's integrity will be compromised.
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

    /// Returns the sum of the node.
    pub fn sum(&self) -> Sum {
        self.sum
    }

    /// Returns the value of the node.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for NonEmptyLeaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Leaf {{ sum: {}, hash: {}, value: {:?} }}",
            self.sum(),
            hex::encode(self.hash().as_slice()),
            self.value()
        )
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_leaf_node_hash() {
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
    fn test_leaf_sum() {
        assert_eq!(super::Leaf::<32, Sha256>::new(vec![1, 2, 3], 1).sum(), 1);
    }

    #[test]
    fn test_leaf_display() {
        assert_eq!(format!("{}", super::Leaf::<32, Sha256>::new(vec![1, 2, 3], 1)), "Leaf { sum: 1, hash: 8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d, value: [1, 2, 3] }");
    }

    #[test]
    fn test_leaf_value() {
        assert_eq!(
            super::Leaf::<32, Sha256>::new(vec![1, 2, 3], 1).value(),
            &[1, 2, 3]
        );
    }

    #[test]
    fn test_leaf_hash() {
        assert_eq!(
            super::Leaf::<32, Sha256>::new(vec![1, 2, 3], 1).hash(),
            hex!("8baca94ed49fcb53307342cc10a24970c9d66309794d55af1532ba6029e7dd8d")
        );
    }

    #[test]
    fn test_leaf_new_with_hash() {
        let leaf = super::Leaf::<32, Sha256>::new(vec![1, 2, 3], 1);
        let leaf_with_hash =
            unsafe { super::Leaf::<32, Sha256>::new_with_hash(vec![1, 2, 3], 1, leaf.hash()) };
        assert_eq!(leaf.hash(), leaf_with_hash.hash());
        assert_eq!(leaf.sum(), leaf_with_hash.sum());
        assert_eq!(leaf.value(), leaf_with_hash.value());
    }
}
