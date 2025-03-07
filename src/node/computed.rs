use std::fmt::Display;

use super::Sum;

/// A computed node. Useful for traversing the tree without reconstructing branches
/// which contains their children and are expensive to reconstruct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputedNode<const HASH_SIZE: usize> {
    node_hash: [u8; HASH_SIZE],
    sum: Sum,
}
impl<const HASH_SIZE: usize> ComputedNode<HASH_SIZE> {
    pub fn new(node_hash: [u8; HASH_SIZE], sum: Sum) -> Self {
        Self { node_hash, sum }
    }
    /// Returns the hash of the node.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.node_hash
    }
    /// Returns the sum of the node.
    pub fn sum(&self) -> Sum {
        self.sum
    }
}

impl<const HASH_SIZE: usize> Display for ComputedNode<HASH_SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Computed {{ sum: {}, hash: {} }}",
            self.sum(),
            hex::encode(self.hash().as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use super::ComputedNode;
    use hex_literal::hex;
    #[test]
    fn test_computed_node_new() {
        let computed_node = ComputedNode::new(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            1,
        );
        assert_eq!(
            computed_node.hash(),
            hex!("0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(computed_node.sum(), 1);
    }

    #[test]
    fn test_computed_node_display() {
        let computed_node = ComputedNode::new(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            1,
        );
        assert_eq!(format!("{}", computed_node), "Computed { sum: 1, hash: 0000000000000000000000000000000000000000000000000000000000000000 }");
    }
}
