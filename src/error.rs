//! Error types for the Merkle Sum Sparse Merkle Tree implementation

use std::error::Error;
use std::fmt::{Debug, Display};

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

impl<DbError: Display> Display for TreeError<DbError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::NodeNotFound => write!(f, "Node not found in tree"),
            TreeError::ExpectedBranch => write!(f, "Node is not a branch node"),
            TreeError::ExpectedLeaf => write!(f, "Node is not a leaf node"),
            TreeError::ExpectedCompactLeaf => write!(f, "Node is not a compact leaf node"),
            TreeError::ExpectedEmptyLeaf => write!(f, "Node is not an empty tree node"),
            TreeError::DbError(e) => write!(f, "Database error: {}", e),
            TreeError::SumOverflow => write!(f, "Sum overflow"),
            TreeError::InvalidMerkleProof => write!(f, "Invalid merkle proof"),
        }
    }
}

impl<DbError: Debug + Display> Error for TreeError<DbError> {}
