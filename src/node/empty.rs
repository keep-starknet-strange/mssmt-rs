use std::fmt::Display;
use std::marker::PhantomData;

use super::{Hasher, Sum};

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

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Display for EmptyLeaf<HASH_SIZE, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Empty {{ sum: {}, hash: {} }}",
            self.sum(),
            hex::encode(self.hash().as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_empty_leaf_node_hash() {
        assert_eq!(
            super::EmptyLeaf::<32, Sha256>::new().hash(),
            hex!("af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc")
        );
        assert_eq!(
            super::EmptyLeaf::<32, Sha256>::default().hash(),
            hex!("af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc")
        );
    }

    #[test]
    fn test_empty_leaf_sum() {
        assert_eq!(super::EmptyLeaf::<32, Sha256>::new().sum(), 0);
    }

    #[test]
    fn test_empty_leaf_display() {
        assert_eq!(format!("{}", super::EmptyLeaf::<32, Sha256>::new()), "Empty { sum: 0, hash: af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc }");
    }
}
