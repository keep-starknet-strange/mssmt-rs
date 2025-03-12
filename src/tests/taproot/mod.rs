use std::path::PathBuf;
mod types;
use crate::{tests::taproot::types::TestVectors, CompactMSSMT, EmptyLeaf, Leaf, MemoryDb, MSSMT};
use sha2::Sha256;
use std::fs;

fn run_bip_test_vector(test_vectors: &TestVectors) {
    // For each valid test case
    if let Some(valid_cases) = &test_vectors.valid_test_cases {
        for valid_case in valid_cases {
            let comment = valid_case.comment.as_deref().unwrap_or("unnamed test");
            println!("Running test case: {}", comment);

            // Create both a full tree and a compact tree
            let full_db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut full_tree = MSSMT::<32, Sha256, ()>::new(full_db);

            let compact_db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut compact_tree = CompactMSSMT::<32, Sha256, ()>::new(compact_db);

            // Insert all leaves declared in the test vector
            println!("insertion");
            for leaf in &test_vectors.all_tree_leaves {
                if !valid_case.should_insert(&leaf.key) {
                    continue;
                }

                let key = leaf.key_as_bytes().unwrap();
                let leaf_node = leaf.to_leaf_node().unwrap();

                full_tree.insert(&key, leaf_node.clone()).unwrap();
                compact_tree.insert(&key, leaf_node).unwrap();
            }

            // Delete all leaves declared in the test vector
            println!("deletion");
            if let Some(deleted_leaves) = &valid_case.deleted_leaves {
                for key_hex in deleted_leaves {
                    if !valid_case.should_delete(key_hex) {
                        continue;
                    }

                    let key = hex::decode(key_hex).unwrap().try_into().unwrap();
                    full_tree.delete(&key).unwrap();
                    compact_tree.delete(&key).unwrap();
                }
            }

            // Replace all leaves declared in the test vector
            if let Some(replaced_leaves) = &valid_case.replaced_leaves {
                for leaf in replaced_leaves {
                    let key = leaf.key_as_bytes().unwrap();
                    let leaf_node = leaf.to_leaf_node().unwrap();

                    full_tree.insert(&key, leaf_node.clone()).unwrap();
                    compact_tree.insert(&key, leaf_node).unwrap();
                }
            }

            // Verify the expected root hash and sum
            if let (Some(root_hash), Some(root_sum)) = (&valid_case.root_hash, &valid_case.root_sum)
            {
                let expected_hash: [u8; 32] = hex::decode(root_hash).unwrap().try_into().unwrap();
                let expected_sum = root_sum.parse::<u64>().unwrap();

                let full_root = full_tree.root().unwrap();
                let compact_root = compact_tree.root().unwrap();
                println!("root check");
                assert_eq!(expected_hash, full_root.hash());
                assert_eq!(expected_hash, compact_root.hash());
                assert_eq!(expected_sum, full_root.sum());
                assert_eq!(expected_sum, compact_root.sum());
            }

            // Verify all inclusion proofs
            if let Some(inclusion_proofs) = &valid_case.inclusion_proofs {
                println!("inclusion_proofs");
                for proof_case in inclusion_proofs {
                    let key = proof_case.proof_key_as_bytes().unwrap();
                    let proof = proof_case.to_proof();
                    let leaf = test_vectors.find_leaf(&proof_case.proof_key).unwrap();
                    let leaf_node = leaf.to_leaf_node().unwrap();

                    let full_root = full_tree.root().unwrap();
                    let compact_root = compact_tree.root().unwrap();

                    proof
                        .verify_merkle_proof::<()>(&key, leaf_node.clone(), full_root.hash())
                        .unwrap();
                    proof
                        .verify_merkle_proof::<()>(&key, leaf_node, compact_root.hash())
                        .unwrap();
                }
            }

            // Verify all exclusion proofs
            if let Some(exclusion_proofs) = &valid_case.exclusion_proofs {
                println!("exclusion_proofs");
                for proof_case in exclusion_proofs {
                    let key = proof_case.proof_key_as_bytes().unwrap();
                    let proof = proof_case.to_proof();
                    let empty_leaf = Leaf::Empty(EmptyLeaf::new());

                    let full_root = full_tree.root().unwrap();
                    let compact_root = compact_tree.root().unwrap();

                    assert!(proof
                        .verify_merkle_proof::<()>(&key, empty_leaf.clone(), full_root.hash())
                        .is_ok());
                    assert!(proof
                        .verify_merkle_proof::<()>(&key, empty_leaf, compact_root.hash())
                        .is_ok());
                }
            }
        }
    }

    // For each error test case
    if let Some(error_cases) = &test_vectors.error_test_cases {
        for error_case in error_cases {
            let comment = error_case
                .comment
                .as_deref()
                .unwrap_or("unnamed error test");
            println!("Running error test case: {}", comment);

            let full_db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut full_tree = MSSMT::<32, Sha256, ()>::new(full_db);

            let compact_db = Box::new(MemoryDb::<32, Sha256>::new());
            let mut compact_tree = CompactMSSMT::<32, Sha256, ()>::new(compact_db);

            let last_idx = test_vectors.all_tree_leaves.len() - 1;
            for (idx, leaf) in test_vectors.all_tree_leaves.iter().enumerate() {
                if !error_case.should_insert(&leaf.key) {
                    continue;
                }

                let key = leaf.key_as_bytes().unwrap();
                let leaf_node = leaf.to_leaf_node().unwrap();

                // For the last leaf that should be inserted, we expect an error
                if idx == last_idx {
                    assert!(full_tree.insert(&key, leaf_node.clone()).is_err());
                    assert!(compact_tree.insert(&key, leaf_node).is_err());
                } else {
                    full_tree.insert(&key, leaf_node.clone()).unwrap();
                    compact_tree.insert(&key, leaf_node).unwrap();
                }
            }
        }
    }
}

#[test]
fn test_bip_tree_deletion() {
    let path = PathBuf::from("src/tests/taproot/testdata/mssmt_tree_deletion.json");
    let json = fs::read_to_string(&path).unwrap();
    let test_vectors = serde_json::from_str::<TestVectors>(&json).unwrap();
    run_bip_test_vector(&test_vectors);
}

#[test]
fn test_bip_tree_error_cases() {
    let path = PathBuf::from("src/tests/taproot/testdata/mssmt_tree_error_cases.json");
    let json = fs::read_to_string(&path).unwrap();
    let test_vectors = serde_json::from_str::<TestVectors>(&json).unwrap();
    run_bip_test_vector(&test_vectors);
}

#[test]
fn test_bip_tree_proofs() {
    let path = PathBuf::from("src/tests/taproot/testdata/mssmt_tree_proofs.json");
    let json = fs::read_to_string(&path).unwrap();
    let test_vectors = serde_json::from_str::<TestVectors>(&json).unwrap();
    run_bip_test_vector(&test_vectors);
}

#[test]
fn test_bip_tree_replacement() {
    let path = PathBuf::from("src/tests/taproot/testdata/mssmt_tree_replacement.json");
    let json = fs::read_to_string(&path).unwrap();
    let test_vectors = serde_json::from_str::<TestVectors>(&json).unwrap();
    run_bip_test_vector(&test_vectors);
}
