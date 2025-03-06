//! Core Merkle Sum Sparse Merkle Tree implementation

use std::{marker::PhantomData, sync::Arc};

use crate::{
    db::Db,
    node::{Branch, Hasher, Leaf, Node},
    TreeError,
};

use super::walk_up;

/// Merkle sum sparse merkle tree.
/// * `KVStore` - Key value store for nodes.
/// * `HASH_SIZE` - size of the hash digest in bytes.
/// * `H` - Hasher that will be used to hash nodes.
pub struct MSSMT<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone, DbError> {
    db: Box<dyn Db<HASH_SIZE, H, DbError = DbError>>,
    _phantom: PhantomData<H>,
}

/// Get the bit at the given index in the key.
pub fn bit_index(index: usize, key: &[u8]) -> u8 {
    // `index as usize / 8` to get the index of the interesting byte
    // `index % 8` to get the interesting bit index in the previously selected byte
    // right shift it and keep only this interesting bit with & 1.
    (key[index / 8] >> (index % 8)) & 1
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone, DbError> MSSMT<HASH_SIZE, H, DbError> {
    /// Creates a new mssmt. This will build an empty tree which will involve a lot of hashing.
    pub fn new(
        mut db: Box<dyn Db<HASH_SIZE, H, DbError = DbError>>,
    ) -> Result<Self, TreeError<DbError>> {
        let Node::Branch(branch) = db.empty_tree().as_ref()[0].clone() else {
            unreachable!("Invalid empty tree. The root node should always be a branch.");
        };
        db.update_root(branch)?;
        Ok(Self {
            db,
            _phantom: PhantomData,
        })
    }
    pub fn db(&self) -> &dyn Db<HASH_SIZE, H, DbError = DbError> {
        self.db.as_ref()
    }

    /// Max height of the tree
    pub const fn max_height() -> usize {
        HASH_SIZE * 8
    }

    /// Root node of the tree.
    pub fn root(&self) -> Result<Branch<HASH_SIZE, H>, TreeError<DbError>> {
        match self.db.get_root_node() {
            Some(branch) => Ok(branch),
            None => {
                let Node::Branch(branch) = self.db.empty_tree().as_ref()[0].clone() else {
                    return Err(TreeError::ExpectedBranch);
                };
                Ok(branch)
            }
        }
    }

    /// Walk down the tree from the root node to the node.
    /// * `for_each` - Closure that is executed at each step of the traversal of the tree.
    pub fn walk_down(
        &self,
        key: [u8; HASH_SIZE],
        mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, Node<HASH_SIZE, H>, Node<HASH_SIZE, H>),
    ) -> Result<Node<HASH_SIZE, H>, TreeError<DbError>> {
        let mut current = Node::Branch(self.root()?);
        for i in 0..Self::max_height() {
            let (left, right) = self.db.get_children(i, current.hash())?;
            let (next, sibling) = if bit_index(i, &key) == 0 {
                (left, right)
            } else {
                (right, left)
            };
            for_each(i, &next, sibling, current);
            current = next;
        }
        match current {
            Node::Leaf(leaf) => Ok(Node::Leaf(leaf)),
            Node::Branch(_) => Err(TreeError::ExpectedLeaf),
            Node::Compact(_) => Err(TreeError::ExpectedLeaf),
            Node::Computed(_) => Err(TreeError::NodeNotFound),
        }
    }

    /// Insert a leaf in the tree.
    pub fn insert(
        &mut self,
        key: [u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
    ) -> Result<(), TreeError<DbError>> {
        let mut prev_parents = Vec::with_capacity(Self::max_height());
        let mut siblings = Vec::with_capacity(Self::max_height());

        self.walk_down(key, |_, _next, sibling, parent| {
            prev_parents.push(parent.hash());
            siblings.push(Arc::new(sibling));
        })?;
        prev_parents.reverse();
        siblings.reverse();

        let mut branches_delete = Vec::new();
        let mut branches_insertion = Vec::new();
        let root = walk_up(
            key,
            leaf.clone(),
            siblings,
            |height, _current, _sibling, parent| {
                let prev_parent = prev_parents[Self::max_height() - height - 1];
                if prev_parent != self.db.empty_tree()[height].hash() {
                    branches_delete.push(prev_parent);
                }
                if parent.hash() != self.db.empty_tree()[height].hash() {
                    if let Node::Branch(parent) = parent {
                        branches_insertion.push(parent.clone());
                    }
                }
            },
        )?;

        for branch in branches_insertion {
            self.db.insert_branch(branch)?;
        }
        for key in branches_delete {
            self.db.delete_branch(&key)?;
        }

        self.db.insert_leaf(leaf)?;
        self.db.update_root(root)
    }

    pub fn merkle_proof(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<Vec<Node<HASH_SIZE, H>>, TreeError<DbError>> {
        let mut proof = Vec::with_capacity(Self::max_height());
        self.walk_down(key, |_, _next, sibling, _| {
            proof.push(sibling);
        })?;
        proof.reverse();
        Ok(proof)
    }
}

#[cfg(test)]
mod test {
    use super::MSSMT;
    use crate::{tree::verify_merkle_proof, Leaf, MemoryDb, TreeError};
    use sha2::Sha256;

    #[test]
    fn test_mssmt_new() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mssmt = MSSMT::<32, Sha256, ()>::new(db).unwrap();
        assert_eq!(
            mssmt.root().unwrap().hash(),
            mssmt.db().empty_tree()[0].hash()
        );
    }

    #[test]
    fn test_mssmt_merkle_proof() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut mssmt = MSSMT::<32, Sha256, ()>::new(db).unwrap();
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
        let mut mssmt = MSSMT::<32, Sha256, ()>::new(db).unwrap();
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
