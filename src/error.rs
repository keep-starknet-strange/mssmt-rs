//! Error types for the Merkle Sum Sparse Merkle Tree implementation

/// Error type for tree operations
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TreeError<DbError> {
    /// Node was not found in the tree
    NodeNotFound,
    /// Node is not a branch node
    ExpectedBranch,
    /// Node is not a leaf node
    ExpectedLeaf,
    /// Node is not a compact leaf node
    ExpectedCompactLeaf,
    /// Node is not an empty tree node
    ExpectedEmptyLeaf,
    /// Database error
    DbError(DbError),
    /// Sum overflow
    SumOverflow,
    /// Invalid merkle proof
    InvalidMerkleProof,
}
