use crate::proof::{CompressedProof, Proof};
use crate::{Leaf, TreeError};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str::FromStr;

/// Parse a hex string into a proof
pub fn parse_proof(proof_hex: &str) -> Result<Proof<32, Sha256>, TreeError<()>> {
    let proof_bytes = hex::decode(proof_hex).unwrap();
    let compressed = CompressedProof::<32, Sha256>::decode(&proof_bytes[..]);
    compressed.decompress()
}

/// Represents a leaf node in the tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestLeafNode {
    pub value: String,
    pub sum: String,
}

impl TestLeafNode {
    /// Create a new test leaf node
    pub fn new(value: impl Into<String>, sum: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sum: sum.into(),
        }
    }

    /// Get the sum as u64
    pub fn sum_as_u64(&self) -> Result<u64, std::num::ParseIntError> {
        u64::from_str(&self.sum)
    }

    /// Get the value as bytes
    pub fn value_as_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.value)
    }
}

/// Represents a key-node pair in the tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestLeaf {
    pub key: String,
    pub node: TestLeafNode,
}

impl TestLeaf {
    /// Create a new test leaf
    pub fn new(key: impl Into<String>, node: TestLeafNode) -> Self {
        Self {
            key: key.into(),
            node,
        }
    }

    /// Convert to a regular leaf node
    pub fn to_leaf_node(&self) -> Result<Leaf<32, Sha256>, Box<dyn std::error::Error>> {
        let value = self.node.value_as_bytes()?;
        let sum = self.node.sum_as_u64()?;
        Ok(Leaf::new(value, sum))
    }

    /// Get the key as bytes
    pub fn key_as_bytes(&self) -> Result<[u8; 32], hex::FromHexError> {
        let bytes = hex::decode(&self.key)?;
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}

/// Represents a node in the tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestNode {
    pub hash: String,
    pub sum: String,
}

impl TestNode {
    /// Create a new test node
    pub fn new(hash: impl Into<String>, sum: impl Into<String>) -> Self {
        Self {
            hash: hash.into(),
            sum: sum.into(),
        }
    }

    /// Get the hash as bytes
    pub fn hash_as_bytes(&self) -> Result<[u8; 32], hex::FromHexError> {
        let bytes = hex::decode(&self.hash)?;
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }

    /// Get the sum as u64
    pub fn sum_as_u64(&self) -> Result<u64, std::num::ParseIntError> {
        u64::from_str(&self.sum)
    }
}

/// Represents a Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestProofCase {
    pub proof_key: String,
    pub compressed_proof: String,
}

impl TestProofCase {
    /// Create a new test proof case
    pub fn new(proof_key: impl Into<String>, compressed_proof: impl Into<String>) -> Self {
        Self {
            proof_key: proof_key.into(),
            compressed_proof: compressed_proof.into(),
        }
    }

    /// Convert to a regular proof
    pub fn to_proof(&self) -> Proof<32, Sha256> {
        parse_proof(&self.compressed_proof).unwrap()
    }

    /// Get the proof key as bytes
    pub fn proof_key_as_bytes(&self) -> Result<[u8; 32], hex::FromHexError> {
        let bytes = hex::decode(&self.proof_key)?;
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }

    /// Get the compressed proof as bytes
    pub fn compressed_proof_as_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(&self.compressed_proof)
    }
}

/// Represents a test case for tree operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidTestCase {
    pub root_hash: Option<String>,
    pub root_sum: Option<String>,
    pub inserted_leaves: Option<Vec<String>>,
    pub deleted_leaves: Option<Vec<String>>,
    pub replaced_leaves: Option<Vec<TestLeaf>>,
    pub inclusion_proofs: Option<Vec<TestProofCase>>,
    pub exclusion_proofs: Option<Vec<TestProofCase>>,
    pub comment: Option<String>,
}

impl ValidTestCase {
    /// Check if a key should be inserted
    pub fn should_insert(&self, key: &str) -> bool {
        self.inserted_leaves
            .as_ref()
            .map_or(false, |leaves| leaves.iter().any(|k| k == key))
    }

    /// Check if a key should be deleted
    pub fn should_delete(&self, key: &str) -> bool {
        self.deleted_leaves
            .as_ref()
            .map_or(false, |leaves| leaves.iter().any(|k| k == key))
    }
}

/// Represents an error test case
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorTestCase {
    pub inserted_leaves: Vec<String>,
    pub error: String,
    pub comment: Option<String>,
}

impl ErrorTestCase {
    /// Check if a key should be inserted
    pub fn should_insert(&self, key: &str) -> bool {
        self.inserted_leaves.iter().any(|k| k == key)
    }
}

/// Root structure for the test data files
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestVectors {
    pub all_tree_leaves: Vec<TestLeaf>,
    pub valid_test_cases: Option<Vec<ValidTestCase>>,
    pub error_test_cases: Option<Vec<ErrorTestCase>>,
}

impl TestVectors {
    /// Load test vectors from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Find a leaf by its key
    pub fn find_leaf(&self, key: &str) -> Option<&TestLeaf> {
        self.all_tree_leaves.iter().find(|leaf| leaf.key == key)
    }
}

/// Generate a random leaf amount
pub fn rand_leaf_amount() -> u64 {
    let mut rng = thread_rng();
    let min_sum: u64 = 1;
    let max_sum: u64 = u32::MAX as u64;
    rng.gen_range(min_sum..=max_sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_node_conversion() {
        let node = TestLeafNode::new("0102030405", "1234");
        assert_eq!(node.sum_as_u64().unwrap(), 1234);
        assert_eq!(node.value_as_bytes().unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_test_leaf_conversion() {
        let leaf = TestLeaf::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            TestLeafNode::new("0102030405", "1234"),
        );
        let key_bytes = leaf.key_as_bytes().unwrap();
        assert_eq!(key_bytes[31], 1);
        assert_eq!(&key_bytes[..31], &[0; 31]);
    }

    #[test]
    fn test_test_node_conversion() {
        let node = TestNode::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "1234",
        );
        let hash_bytes = node.hash_as_bytes().unwrap();
        assert_eq!(hash_bytes[31], 1);
        assert_eq!(&hash_bytes[..31], &[0; 31]);
        assert_eq!(node.sum_as_u64().unwrap(), 1234);
    }

    #[test]
    fn test_proof_case_conversion() {
        let proof = TestProofCase::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0102030405",
        );
        let key_bytes = proof.proof_key_as_bytes().unwrap();
        assert_eq!(key_bytes[31], 1);
        assert_eq!(&key_bytes[..31], &[0; 31]);
        assert_eq!(
            proof.compressed_proof_as_bytes().unwrap(),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn test_test_vectors() {
        let test_vectors = TestVectors {
            all_tree_leaves: vec![TestLeaf::new(
                "0000000000000000000000000000000000000000000000000000000000000001",
                TestLeafNode::new("0102030405", "1234"),
            )],
            valid_test_cases: Some(vec![ValidTestCase {
                root_hash: Some(
                    "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
                ),
                root_sum: Some("5678".to_string()),
                inserted_leaves: Some(vec![
                    "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
                ]),
                deleted_leaves: None,
                replaced_leaves: None,
                inclusion_proofs: None,
                exclusion_proofs: None,
                comment: Some("test".to_string()),
            }]),
            error_test_cases: None,
        };

        let json = serde_json::to_string_pretty(&test_vectors).unwrap();
        let parsed = TestVectors::from_json(&json).unwrap();
        assert_eq!(test_vectors, parsed);

        let leaf = test_vectors
            .find_leaf("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        assert_eq!(leaf.node.sum, "1234");

        if let Some(test_cases) = test_vectors.valid_test_cases {
            let test_case = &test_cases[0];
            assert!(test_case
                .should_insert("0000000000000000000000000000000000000000000000000000000000000001"));
            assert!(!test_case
                .should_insert("0000000000000000000000000000000000000000000000000000000000000002"));
            assert!(!test_case
                .should_delete("0000000000000000000000000000000000000000000000000000000000000001"));
        }
    }

    #[test]
    fn test_rand_leaf_amount() {
        for _ in 0..100 {
            let amount = rand_leaf_amount();
            assert!(amount > 0);
            assert!(amount <= u32::MAX as u64);
        }
    }
}
