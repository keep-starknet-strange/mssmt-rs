use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    node::{Branch, CompactLeaf, Hasher, Leaf, Node},
    tree::{bit_index, Db, TreeSize},
};

pub struct CompactMSSMT<
    KVStore: Db<HASH_SIZE, H>,
    const HASH_SIZE: usize,
    H: Hasher<HASH_SIZE> + Clone,
> {
    db: KVStore,
    _phantom: PhantomData<H>,
}

impl<KVStore: Db<HASH_SIZE, H>, const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    CompactMSSMT<KVStore, HASH_SIZE, H>
{
    pub fn new(db: KVStore) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }
    pub fn new_with_tree(db: KVStore) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }
    pub fn max_height() -> usize {
        TreeSize::USIZE
    }
    pub fn db(&self) -> &KVStore {
        &self.db
    }
    pub fn root(&self) -> Branch<HASH_SIZE, H> {
        self.db.get_root_node().unwrap_or_else(|| {
            let Node::Branch(branch) = self.db.empty_tree().as_ref()[0].clone() else {
                panic!("Root should be a branch")
            };
            branch
        })
    }
    pub fn walk_down(
        &self,
        path: &[u8; HASH_SIZE],
        mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>),
    ) -> Leaf<HASH_SIZE, H> {
        let mut current = Node::Branch(self.db.get_root_node().unwrap());
        for i in 0..Self::max_height() {
            let (left, right) = self.db.get_children(i, current.hash());
            let (mut next, mut sibling) = Self::step_order(i, path, left, right);
            match next {
                Node::Compact(compact) => {
                    next = compact.extract(i);
                    if let Node::Compact(comp_sibling) = sibling {
                        sibling = comp_sibling.extract(i);
                    }
                    // Now that all required branches are reconstructed we
                    // can continue the search for the leaf matching the
                    // passed key.
                    for j in i..Self::max_height() {
                        for_each(j, &next, &sibling, &current);
                        current = next.clone();

                        if j < Self::max_height() - 1 {
                            // Since we have all the branches we
                            // need extracted already we can just
                            // continue walking down.
                            let branch = match &current {
                                Node::Branch(b) => b,
                                _ => panic!("expected branch node"),
                            };
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
                    let Node::Leaf(leaf) = current else {
                        panic!("expected leaf found branch");
                    };
                    return leaf;
                }
                _ => {
                    for_each(i, &next, &sibling, &current);
                    current = next;
                }
            }
        }
        let Node::Leaf(leaf) = current else {
            panic!("expected leaf found branch");
        };
        leaf
    }

    /// merge is a helper function to create the common subtree from two leafs lying
    /// on the same (partial) path. The resulting subtree contains branch nodes from
    /// diverging bit of the passed key's.
    pub fn merge(
        &mut self,
        height: usize,
        key1: [u8; HASH_SIZE],
        leaf1: Leaf<HASH_SIZE, H>,
        key2: [u8; HASH_SIZE],
        leaf2: Leaf<HASH_SIZE, H>,
    ) -> Branch<HASH_SIZE, H> {
        // Find the common prefix first
        let mut common_prefix_len = 0;
        for i in 0..Self::max_height() {
            if bit_index(i, &key1) == bit_index(i, &key2) {
                common_prefix_len += 1;
            } else {
                break;
            }
        }

        // Now we create two compacted leaves and insert them as children of
        // a newly created branch
        let node1 = Node::Compact(CompactLeaf::new_compact_leaf(
            common_prefix_len + 1,
            key1,
            leaf1,
        ));
        let node2 = CompactLeaf::new_compact_leaf(common_prefix_len + 1, key2, leaf2);

        self.db.insert_compact_leaf(node2.clone());
        let (left, right) = Self::step_order(common_prefix_len, &key1, node1, Node::Compact(node2));
        let mut parent = Branch::new(left, right);
        self.db.insert_branch(parent.clone());

        // From here we'll walk up to the current level and create branches
        // along the way. Optionally we could compact these branches too.
        for i in (height..common_prefix_len).rev() {
            let (left, right) = Self::step_order(
                i,
                &key1,
                Node::Branch(parent),
                self.db.empty_tree()[i + 1].clone(),
            );
            parent = Branch::new(left, right);
            self.db.insert_branch(parent.clone());
        }

        parent
    }

    /// insert inserts the key at the current height either by adding a new compacted
    /// leaf, merging an existing leaf with the passed leaf in a new subtree or by
    /// recursing down further.
    pub(crate) fn insert_leaf(
        &mut self,
        key: &[u8; HASH_SIZE],
        height: usize,
        root: &Branch<HASH_SIZE, H>,
        leaf: Leaf<HASH_SIZE, H>,
    ) -> Branch<HASH_SIZE, H> {
        let (left, right) = self.db.get_children(height, root.hash());

        let (next, sibling) = Self::step_order(height, key, left, right);

        let next_height = height + 1;

        let new_node = match next {
            Node::Branch(node) => {
                if node.hash() == self.db.empty_tree()[next_height].hash() {
                    // This is an empty subtree, so we can just walk up
                    // from the leaf to recreate the node key for this
                    // subtree then replace it with a compacted leaf.
                    let new_leaf = CompactLeaf::new_compact_leaf(next_height, *key, leaf);
                    self.db.insert_compact_leaf(new_leaf.clone());
                    Node::Compact(new_leaf)
                } else {
                    // Not an empty subtree, recurse down the tree to find
                    // the insertion point for the leaf.
                    Node::Branch(self.insert_leaf(key, next_height, root, leaf))
                }
            }
            Node::Compact(node) => {
                // First delete the old leaf.
                self.db.delete_compact_leaf(&node.hash());

                if *key == *node.key() {
                    // Replace of an existing leaf.
                    // TODO: change to handle delete
                    let new_leaf = CompactLeaf::new_compact_leaf(next_height, *key, leaf);
                    self.db.insert_compact_leaf(new_leaf.clone());
                    Node::Compact(new_leaf)
                } else {
                    // Merge the two leaves into a subtree.
                    Node::Branch(self.merge(
                        next_height,
                        *key,
                        leaf,
                        *node.key(),
                        node.leaf().clone(),
                    ))
                }
            }
            _ => panic!("unexpected node type"),
        };

        // Delete the old root if not empty
        if root.hash() != self.db.empty_tree()[height].hash() {
            self.db.delete_branch(&root.hash());
        }

        // Create the new root
        let (left, right) = Self::step_order(height, key, new_node, sibling);
        let branch = Branch::new(left, right);

        // Only insert this new branch if not a default one
        if branch.hash() != self.db.empty_tree()[height].hash() {
            self.db.insert_branch(branch.clone());
        }

        branch
    }

    /// Insert inserts a leaf node at the given key within the MS-SMT.
    pub fn insert(&mut self, key: [u8; HASH_SIZE], leaf: Leaf<HASH_SIZE, H>) {
        let root = self.db.get_root_node().unwrap_or_else(|| {
            let Node::Branch(branch) = self.db.empty_tree()[0].clone() else {
                panic!("expected branch node")
            };
            branch
        });

        // First we'll check if the sum of the root and new leaf will
        // overflow. If so, we'll return an error.
        let sum_root = root.sum();
        let sum_leaf = leaf.sum();
        if sum_root.checked_add(sum_leaf).is_none() {
            panic!(
                "compact tree leaf insert sum overflow, root: {}, leaf: {}",
                sum_root, sum_leaf
            );
        }

        let new_root = self.insert_leaf(&key, 0, &root, leaf);
        self.db.update_root(new_root);
    }

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
}
