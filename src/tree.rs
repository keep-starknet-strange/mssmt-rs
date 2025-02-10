use std::collections::HashMap;

use crate::node::{Branch, HashValue, Leaf, Node};

pub struct MSSMT<KVStore: Db> {
    db: KVStore,
    root: Branch,
    empty_tree: [Node; 256],
    branches: HashMap<HashValue, Branch>,
    leaves: HashMap<HashValue, Leaf>,
}

pub trait Db {
    fn get_root_node(&self) -> Branch;
    fn get(&self, key: [u8; 32]) -> Leaf;
}
fn bit_index(index: u32, key: HashValue) -> u8 {
    // index as usize / 8 to get the index of the interesting byte
    // index % 8 to get the interesting bit index in the previously selected byte
    // right shift it and keep only this interesting bit with & 1.
    (key[index as usize / 8] >> (index % 8)) & 1
}

impl<KVStore: Db> MSSMT<KVStore> {
    pub fn max_height() -> u32 {
        256
    }
    pub fn get(&self, key: [u8; 32]) -> Leaf {
        let mut current_branch = Node::Branch(self.db.get_root_node());
        for i in 0..Self::max_height() {
            if bit_index(i, key) == 0 {
                let (left, _) = self.get_children(i as usize, current_branch.hash());
                current_branch = left;
            } else {
                let (_, right) = self.get_children(i as usize, current_branch.hash());
                current_branch = right;
            }
        }
        match current_branch {
            Node::Leaf(leaf) => leaf,
            Node::Branch(_) => panic!("expected leaf found branch"),
        }
    }

    pub fn get_children(&self, height: usize, key: HashValue) -> (Node, Node) {
        let get_node = |height: usize, key: HashValue| {
            if key == self.empty_tree[height].hash() {
                return self.empty_tree[height].clone();
            }
            if let Some(branch) = self.branches.get(&key) {
                Node::Branch(branch.clone())
            } else if let Some(leaf) = self.leaves.get(&key) {
                Node::Leaf(leaf.clone())
            } else {
                panic!("Didn't find the node")
            }
        };
        let node = get_node(height, key);
        if key != self.empty_tree[height].hash() && node == self.empty_tree[height] {
            panic!("node not found")
        }
        if let Node::Branch(branch) = node {
            (
                get_node(height + 1, branch.left().hash()),
                get_node(height + 1, branch.left().hash()),
            )
        } else {
            panic!("Should be a branch node")
        }
    }
    pub fn insert(&mut self, key: HashValue, leaf: Leaf) {}
}
