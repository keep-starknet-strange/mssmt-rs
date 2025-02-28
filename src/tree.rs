use std::{borrow::Borrow, cell::LazyCell, marker::PhantomData, sync::Arc};
use typenum::{Prod, Sum, Unsigned, U1, U8};

use crate::node::{Branch, CompactLeaf, EmptyLeaf, Hasher, Leaf, Node};

/// Define the empty tree array size as (HASH_SIZE * 8) + 1
pub(crate) type TreeSize = Sum<Prod<U8, typenum::U32>, U1>;

/// Merkle sum sparse merkle tree.
/// * `KVStore` - Key value store for nodes.
/// * `HASH_SIZE` - size of the hash digest in bytes.
/// * `H` - Hasher that will be used to hash nodes.
pub struct MSSMT<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    db: Box<dyn Db<HASH_SIZE, H>>,
    _phantom: PhantomData<H>,
}

/// Helper struct to create an empty mssmt.
pub struct EmptyTree<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>(PhantomData<H>);

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> EmptyTree<HASH_SIZE, H> {
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY_TREE: LazyCell<Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]>> =
        LazyCell::new(|| Arc::new(Self::build_tree()));

    /// Gets an empty mssmt.
    pub fn empty_tree() -> Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]> {
        #[allow(clippy::borrow_interior_mutable_const)]
        Self::EMPTY_TREE.clone()
    }

    /// builds the empty tree
    fn build_tree() -> [Node<HASH_SIZE, H>; TreeSize::USIZE] {
        let max_height = HASH_SIZE * 8;
        let mut empty_tree = Vec::with_capacity(max_height + 1);
        let empty_leaf = Node::<HASH_SIZE, H>::Empty(EmptyLeaf::new());
        empty_tree.push(empty_leaf);

        for i in 1..=max_height {
            empty_tree.push(Node::new_branch(
                empty_tree[i - 1].clone(),
                empty_tree[i - 1].clone(),
            ));
        }
        empty_tree.reverse();

        let Node::Branch(_branch) = &empty_tree[0] else {
            panic!("Root should be a branch")
        };

        empty_tree
            .try_into()
            .unwrap_or_else(|_| panic!("Incorrect array size"))
    }
}

/// Store for the tree nodes
///
/// This trait must be implemented by any storage backend used with the tree.
/// It provides the basic operations needed to store and retrieve nodes.
pub trait Db<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    fn get_root_node(&self) -> Option<Branch<HASH_SIZE, H>>;
    fn get_children(
        &self,
        height: usize,
        key: [u8; HASH_SIZE],
    ) -> (Node<HASH_SIZE, H>, Node<HASH_SIZE, H>);
    fn insert_leaf(&mut self, leaf: Leaf<HASH_SIZE, H>);
    fn insert_branch(&mut self, branch: Branch<HASH_SIZE, H>);
    fn insert_compact_leaf(&mut self, compact_leaf: CompactLeaf<HASH_SIZE, H>);
    fn empty_tree(&self) -> Arc<[Node<HASH_SIZE, H>; TreeSize::USIZE]>;
    fn update_root(&mut self, root: Branch<HASH_SIZE, H>);
    fn delete_branch(&mut self, key: &[u8; HASH_SIZE]);
    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]);
    fn delete_compact_leaf(&mut self, key: &[u8; HASH_SIZE]);
}

pub(crate) fn bit_index(index: usize, key: &[u8]) -> u8 {
    // `index as usize / 8` to get the index of the interesting byte
    // `index % 8` to get the interesting bit index in the previously selected byte
    // right shift it and keep only this interesting bit with & 1.
    (key[index / 8] >> (index % 8)) & 1
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone>
    MSSMT<HASH_SIZE, H>
{
    /// Creates a new mssmt. This will build an empty tree which will involve a lot of hashing.
    pub fn new(mut db: Box<dyn Db<HASH_SIZE, H>>) -> Self {
        let Node::Branch(branch) = db.empty_tree().as_ref()[0].clone() else {
            panic!("Root should be a branch")
        };
        db.update_root(branch);
        Self {
            db,
            _phantom: PhantomData,
        }
    }
    pub fn db(&self) -> &dyn Db<HASH_SIZE, H> {
        self.db.as_ref()
    }

    /// Max height of the tree
    pub const fn max_height() -> usize {
        HASH_SIZE * 8
    }

    /// Root node of the tree.
    pub fn root(&self) -> Branch<HASH_SIZE, H> {
        self.db.get_root_node().unwrap_or_else(|| {
            let Node::Branch(branch) = self.db.empty_tree().as_ref()[0].clone() else {
                panic!("Root should be a branch")
            };
            branch
        })
    }

    pub fn get_leaf_from_top(&self, key: [u8; HASH_SIZE]) -> Leaf<HASH_SIZE, H> {
        let mut current_branch = Node::Branch(self.db.get_root_node().unwrap());
        for i in 0..Self::max_height() {
            if bit_index(i, &key) == 0 {
                let (left, _) = self.db.get_children(i, current_branch.hash());
                current_branch = left;
            } else {
                let (_, right) = self.db.get_children(i, current_branch.hash());
                current_branch = right;
            }
        }
        match current_branch {
            Node::Leaf(leaf) => leaf,
            Node::Branch(_) => panic!("expected leaf found branch"),
            Node::Empty(_) => panic!("Empty node"),
            Node::Compact(_) => unreachable!("tree isn't compact"),
            Node::Computed(_) => unreachable!("Only used for dbs"),
        }
    }

    /// Walk down the tree from the root node to the node.
    /// * `for_each` - Closure that is executed at each step of the traversal of the tree.
    pub fn walk_down(
        &self,
        key: [u8; HASH_SIZE],
        mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, Node<HASH_SIZE, H>, Node<HASH_SIZE, H>),
    ) -> Node<HASH_SIZE, H> {
        let mut current = Node::Branch(self.root());
        for i in 0..Self::max_height() {
            let (left, right) = self.db.get_children(i, current.hash());
            let (next, sibling) = if bit_index(i, &key) == 0 {
                (left, right)
            } else {
                (right, left)
            };
            for_each(i, &next, sibling, current);
            current = next;
        }
        match current {
            Node::Leaf(leaf) => Node::Leaf(leaf),
            Node::Branch(_) => panic!("expected leaf found branch"),
            Node::Empty(empty) => Node::Empty(empty),
            Node::Compact(_) => unreachable!("tree isn't compact"),
            Node::Computed(_) => unreachable!("Only used for dbs"),
        }
    }

    /// Walk up the tree from the node to the root node.
    /// * `key` - key of the node we want to reach.
    /// * `start` - starting leaf.
    /// * `siblings` - All the sibling nodes on the path (from the leaf to the target node).
    /// * `for_each` - Closure that is executed at each step of the traversal of the tree.
    ///     * `height: usize` - current height in the tree
    ///     * `current: &Node<HASH_SIZE, H>` - current node on the way to the asked node
    ///     * `sibling: &Node<HASH_SIZE, H>` - sibling node of the current node on the way to the asked node
    ///     * `parent: &Node<HASH_SIZE, H>` - parent node of the current node on the way to the asked node
    pub fn walk_up(
        &self,
        key: [u8; HASH_SIZE],
        start: Leaf<HASH_SIZE, H>,
        siblings: Vec<Arc<Node<HASH_SIZE, H>>>,
        mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>),
    ) -> Branch<HASH_SIZE, H> {
        let mut current = Arc::new(Node::Leaf(start));
        for i in (0..Self::max_height()).rev() {
            let sibling = siblings[Self::max_height() - 1 - i].clone();
            let parent = if bit_index(i, &key) == 0 {
                Node::from((current.clone(), sibling.clone()))
            } else {
                Node::from((sibling.clone(), current.clone()))
            };
            for_each(i, &current, &sibling, &parent);
            current = Arc::new(parent);
        }
        if let Node::Branch(current) = current.borrow() {
            current.clone()
        } else {
            panic!("Shouldn't end on a leaf");
        }
    }

    /// Insert a leaf in the tree.
    pub fn insert(&mut self, key: [u8; HASH_SIZE], leaf: Leaf<HASH_SIZE, H>) {
        let mut prev_parents = Vec::with_capacity(Self::max_height());
        let mut siblings = Vec::with_capacity(Self::max_height());

        self.walk_down(key, |_, _next, sibling, parent| {
            prev_parents.push(parent.hash());
            siblings.push(Arc::new(sibling));
        });
        prev_parents.reverse();
        siblings.reverse();

        // Create a vector to store operations we'll perform after walk_up
        let mut branches_delete = Vec::new();
        let mut branches_insertion = Vec::new();
        let root = self.walk_up(
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
        );

        for branch in branches_insertion {
            self.db.insert_branch(branch);
        }
        // Perform the database operations after walk_up
        for key in branches_delete {
            self.db.delete_branch(&key);
        }

        self.db.insert_leaf(leaf);
        self.db.update_root(root);
    }
}
