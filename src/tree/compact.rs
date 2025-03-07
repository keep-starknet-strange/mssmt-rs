//! A compact representation of a Merkle Sum Sparse Merkle Tree (MS-SMT).
//!
//! This implementation optimizes storage by compacting subtrees that contain only a single leaf.
//! Instead of storing all intermediate branch nodes, it stores just the leaf and its path information.
//! This significantly reduces the storage requirements while maintaining the same cryptographic properties.

use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    node::{Branch, CompactLeaf, Hasher, Leaf, Node},
    Db, TreeError, TreeSize,
};

use super::regular::bit_index;

/// A compact Merkle Sum Sparse Merkle Tree implementation.
///
/// This tree structure maintains the same cryptographic properties as a regular MS-SMT
/// but uses an optimized storage format that compacts single-leaf subtrees.
///
/// # Type Parameters
///
/// * `HASH_SIZE`: The size of the hash output in bytes
/// * `H`: The hash function implementation that implements the [`Hasher`] trait
pub struct CompactMSSMT<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone, DbError> {
    /// The database backend for storing tree nodes
    db: Box<dyn Db<HASH_SIZE, H, DbError = DbError>>,
    /// PhantomData for the hash function type
    _phantom: PhantomData<H>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone, DbError>
    CompactMSSMT<HASH_SIZE, H, DbError>
{
    /// Creates a new empty compact MS-SMT with the given database backend.
    pub fn new(
        db: Box<dyn Db<HASH_SIZE, H, DbError = DbError>>,
    ) -> Result<Self, TreeError<DbError>> {
        Ok(Self {
            db,
            _phantom: PhantomData,
        })
    }

    /// Returns the maximum number of levels in the tree (HASH_SIZE * 8)
    pub fn max_levels() -> usize {
        TreeSize::USIZE - 1
    }

    /// Returns a reference to the underlying database.
    pub fn db(&self) -> &dyn Db<HASH_SIZE, H, DbError = DbError> {
        self.db.as_ref()
    }

    /// Returns the root node of the tree.
    ///
    /// If the tree is empty, returns the default empty root node.
    pub fn root(&self) -> Result<Branch<HASH_SIZE, H>, TreeError<DbError>> {
        if let Some(branch) = self.db.get_root_node() {
            Ok(branch)
        } else {
            let Node::Branch(branch) = self.db.empty_tree().as_ref()[0].clone() else {
                unreachable!("Invalid empty tree. The root node should always be a branch.");
            };
            Ok(branch)
        }
    }

    /// Walks down the tree following the given path, calling the provided function at each level.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to follow, represented as a byte array
    /// * `for_each` - A closure called at each level with:
    ///   * The current height
    ///   * The next node in the path
    ///   * The sibling node
    ///   * The current node
    ///
    /// # Returns
    ///
    /// Returns the leaf node found at the end of the path
    pub fn walk_down(
        &self,
        path: &[u8; HASH_SIZE],
        mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>),
    ) -> Result<Leaf<HASH_SIZE, H>, TreeError<DbError>> {
        // Start from the root node
        let mut current = Node::Branch(self.db.get_root_node().ok_or(TreeError::NodeNotFound)?);
        for i in 0..Self::max_levels() {
            // Get the children of the current node
            let (left, right) = self.db.get_children(i, current.hash())?;
            // Order the children based on the path
            let (mut next, mut sibling) = Self::step_order(i, path, left, right);
            match next {
                // If the next node is a compact leaf we can extract the branches
                // on the path to the leaf.
                Node::Compact(compact) => {
                    next = compact.extract(i);
                    // If the sibling is also a compact leaf we can extract the branches
                    // on the path to the sibling.
                    if let Node::Compact(comp_sibling) = sibling {
                        sibling = comp_sibling.extract(i);
                    }
                    // Now that all required branches are reconstructed we
                    // can continue the search for the leaf matching the
                    // passed key.
                    for j in i..Self::max_levels() {
                        // Call the callback for each level
                        for_each(j, &next, &sibling, &current);
                        // Update the current node
                        current = next.clone();
                        // If we're not at the last level we can continue
                        // walking down.
                        if j < Self::max_levels() - 1 {
                            // Since we have all the branches we
                            // need extracted already we can just
                            // continue walking down.
                            let branch = match &current {
                                Node::Branch(b) => b,
                                _ => return Err(TreeError::ExpectedBranch),
                            };
                            // Get the next and sibling nodes
                            let (n, s) = Self::step_order(
                                j + 1,
                                path,
                                branch.left().clone(),
                                branch.right().clone(),
                            );
                            next = n;
                            sibling = s;
                        }
                    }
                    // Return the leaf node
                    let Node::Leaf(leaf) = current else {
                        return Err(TreeError::ExpectedLeaf);
                    };
                    return Ok(leaf);
                }
                // If the next node is not a compact leaf we can continue
                // walking down.
                _ => {
                    // Call the callback for each level
                    for_each(i, &next, &sibling, &current);
                    // Update the current node
                    current = next;
                }
            }
        }
        // Return the leaf node
        let Node::Leaf(leaf) = current else {
            return Err(TreeError::ExpectedLeaf);
        };
        Ok(leaf)
    }

    /// Creates a common subtree from two leaves that share a partial path.
    ///
    /// # Arguments
    ///
    /// * `height` - The current height in the tree
    /// * `key1` - The key of the first leaf
    /// * `leaf1` - The first leaf node
    /// * `key2` - The key of the second leaf  
    /// * `leaf2` - The second leaf node
    ///
    /// # Returns
    ///
    /// Returns a branch node that is the root of the merged subtree
    pub fn merge(
        &mut self,
        height: usize,
        key1: [u8; HASH_SIZE],
        leaf1: Leaf<HASH_SIZE, H>,
        key2: [u8; HASH_SIZE],
        leaf2: Leaf<HASH_SIZE, H>,
    ) -> Result<Branch<HASH_SIZE, H>, TreeError<DbError>> {
        // Find the common prefix first
        let mut i = 0;
        // As long as the key bits are the same we can continue
        while i < Self::max_levels() && bit_index(i, &key1) == bit_index(i, &key2) {
            i += 1;
        }

        // Now we create two compacted leaves and insert them as children of
        // a newly created branch
        let node1 = CompactLeaf::new(i + 1, key1, leaf1.clone());
        let node2 = CompactLeaf::new(i + 1, key2, leaf2.clone());
        // Insert the leaves into the database. This is not strictly necessary but it's useful
        // If we want to avoid inserting the same leaf twice.
        self.db.insert_leaf(leaf1)?;
        self.db.insert_leaf(leaf2)?;
        // Insert the compacted leaves into the database
        self.db.insert_compact_leaf(node1.clone())?;
        self.db.insert_compact_leaf(node2.clone())?;
        let (left, right) = Self::step_order(i, &key1, Node::Compact(node1), Node::Compact(node2));
        let mut parent = Branch::new(left, right);
        self.db.insert_branch(parent.clone())?;

        // From here we'll walk up to the current level and create branches
        // along the way.
        for i in (height..i).rev() {
            let (left, right) = Self::step_order(
                i,
                &key1,
                Node::Branch(parent),
                self.db.empty_tree()[i + 1].clone(),
            );
            parent = Branch::new(left, right);
            self.db.insert_branch(parent.clone())?;
        }

        Ok(parent)
    }

    /// Inserts a leaf at the given height in the tree.
    ///
    /// This function handles three cases:
    /// 1. Inserting into an empty subtree (creates a new compact leaf)
    /// 2. Replacing an existing leaf at the same key
    /// 3. Merging with an existing leaf at a different key (creates a new subtree)
    fn insert_leaf(
        &mut self,
        key: &[u8; HASH_SIZE],
        height: usize,
        root_hash: &[u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
    ) -> Result<Branch<HASH_SIZE, H>, TreeError<DbError>> {
        // Get the children of the current node
        let (left, right) = self.db.get_children(height, *root_hash)?;
        // Order the children based on the path
        let is_left = bit_index(height, key) == 0;
        let (next, sibling) = if is_left {
            (left, right)
        } else {
            (right, left)
        };

        let next_height = height + 1;

        let new_node = match next {
            Node::Branch(node) => {
                if node.hash() == self.db.empty_tree()[next_height].hash() {
                    // This is an empty subtree, so we can just walk up
                    // from the leaf to recreate the node key for this
                    // subtree then replace it with a compacted leaf.
                    let new_leaf = CompactLeaf::new(next_height, *key, leaf.clone());
                    self.db.insert_leaf(leaf)?;
                    self.db.insert_compact_leaf(new_leaf.clone())?;
                    Node::Compact(new_leaf)
                } else {
                    // Not an empty subtree, recurse down the tree to find
                    // the insertion point for the leaf.
                    Node::Branch(self.insert_leaf(key, next_height, &node.hash(), leaf)?)
                }
            }
            Node::Compact(node) => {
                // First delete the old leaf.
                self.db.delete_leaf(&node.leaf().hash())?;
                self.db.delete_compact_leaf(&node.hash())?;

                if *key == *node.key() {
                    // Replace of an existing leaf.
                    // TODO: change to handle delete
                    let new_leaf = CompactLeaf::new(next_height, *key, leaf.clone());
                    self.db.insert_leaf(leaf)?;
                    self.db.insert_compact_leaf(new_leaf.clone())?;
                    Node::Compact(new_leaf)
                } else {
                    // Merge the two leaves into a subtree.
                    Node::Branch(self.merge(
                        next_height,
                        *key,
                        leaf,
                        *node.key(),
                        node.leaf().clone(),
                    )?)
                }
            }
            Node::Computed(node) => {
                if node.hash() == self.db.empty_tree()[next_height].hash() {
                    // This is an empty subtree, so we can just walk up
                    // from the leaf to recreate the node key for this
                    // subtree then replace it with a compacted leaf.
                    let new_leaf = CompactLeaf::new(next_height, *key, leaf.clone());
                    self.db.insert_leaf(leaf)?;
                    self.db.insert_compact_leaf(new_leaf.clone())?;
                    Node::Compact(new_leaf)
                } else {
                    // Not an empty subtree, recurse down the tree to find
                    // the insertion point for the leaf.
                    Node::Branch(self.insert_leaf(key, next_height, &node.hash(), leaf)?)
                }
            }
            _ => return Err(TreeError::ExpectedBranch),
        };

        // Delete the old root if not empty
        if *root_hash != self.db.empty_tree()[height].hash() {
            self.db.delete_branch(root_hash)?;
        }
        // Create the new root
        let branch = if is_left {
            Branch::new(new_node, sibling)
        } else {
            Branch::new(sibling, new_node)
        };

        // Only insert this new branch if not a default one
        if branch.hash() != self.db.empty_tree()[height].hash() {
            self.db.insert_branch(branch.clone())?;
        }

        Ok(branch)
    }

    /// Inserts a leaf node at the given key within the MS-SMT.
    ///
    /// # Arguments
    ///
    /// * `key` - The key where the leaf should be inserted
    /// * `leaf` - The leaf node to insert
    ///
    /// # Returns
    ///
    /// Returns an error if inserting the leaf would cause the tree's sum to overflow
    pub fn insert(
        &mut self,
        key: [u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
    ) -> Result<(), TreeError<DbError>> {
        // Get the root node
        let root = if let Some(branch) = self.db.get_root_node() {
            branch
        } else {
            let Node::Branch(branch) = self.db.empty_tree()[0].clone() else {
                unreachable!("Invalid empty tree. The root node should always be a branch.");
            };
            branch
        };

        // First we'll check if the sum of the root and new leaf will
        // overflow. If so, we'll return an error.
        let sum_root = root.sum();
        let sum_leaf = leaf.sum();
        if sum_root.checked_add(sum_leaf).is_none() {
            return Err(TreeError::SumOverflow);
        }

        let new_root = self.insert_leaf(&key, 0, &root.hash(), leaf)?;
        self.db.update_root(new_root)
    }

    /// Helper function to order nodes based on a key bit at the given height.
    ///
    /// Returns the nodes in (next, sibling) order based on whether the key bit is 0 or 1.
    #[inline]
    fn step_order(
        height: usize,
        key: &[u8; HASH_SIZE],
        left: Node<HASH_SIZE, H>,
        right: Node<HASH_SIZE, H>,
    ) -> (Node<HASH_SIZE, H>, Node<HASH_SIZE, H>) {
        if bit_index(height, key) == 0 {
            (left, right)
        } else {
            (right, left)
        }
    }

    /// Returns the merkle proof for the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the node to get the proof for
    ///
    /// # Returns
    ///
    /// Returns the merkle proof for the given key
    pub fn merkle_proof(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<Vec<Node<HASH_SIZE, H>>, TreeError<DbError>> {
        let mut proof = Vec::with_capacity(Self::max_levels());
        // Walk down the tree and collect the siblings
        self.walk_down(&key, |_, _next, sibling, _| {
            proof.push(sibling.clone());
        })?;
        // Reverse the proof to get the correct order
        proof.reverse();
        Ok(proof)
    }
}

#[cfg(test)]
mod test {
    use super::CompactMSSMT;
    use crate::{tree::verify_merkle_proof, Leaf, MemoryDb, TreeError};
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_compact_mssmt_new() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let compact_mssmt = CompactMSSMT::<32, Sha256, ()>::new(db).unwrap();
        assert_eq!(
            compact_mssmt.root().unwrap().hash(),
            compact_mssmt.db().empty_tree()[0].hash()
        );
    }

    #[test]
    fn test_compact_mssmt_sum_overflow() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut compact_mssmt = CompactMSSMT::<32, Sha256, ()>::new(db).unwrap();
        let leaf = Leaf::new(vec![1; 32], u64::MAX);
        compact_mssmt
            .insert(
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                leaf.clone(),
            )
            .unwrap();
        assert_eq!(
            compact_mssmt.insert(
                hex!("0000000000000000000000000000000000000000000000000000000000000001"),
                leaf
            ),
            Err(TreeError::SumOverflow)
        );
    }
    #[test]
    fn test_mssmt_merkle_proof() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut mssmt = CompactMSSMT::<32, Sha256, ()>::new(db).unwrap();
        let value = vec![0; 32];
        let leaf = Leaf::new(value, 1);
        mssmt.insert([0; 32], leaf.clone()).unwrap();
        let proof = mssmt.merkle_proof([0; 32]).unwrap();
        let root = mssmt.root().unwrap();
        verify_merkle_proof::<32, Sha256, ()>([0; 32], leaf, proof, root).unwrap();
    }

    #[test]
    fn test_mssmt_merkle_proof_invalid() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut mssmt = CompactMSSMT::<32, Sha256, ()>::new(db).unwrap();
        let value = vec![0; 32];
        let leaf = Leaf::new(value, 1);
        mssmt.insert([0; 32], leaf.clone()).unwrap();
        let proof = mssmt.merkle_proof([1; 32]).unwrap();
        let root = mssmt.root().unwrap();
        assert_eq!(
            verify_merkle_proof::<32, Sha256, ()>([0; 32], leaf, proof, root).unwrap_err(),
            TreeError::InvalidMerkleProof
        );
    }
}
