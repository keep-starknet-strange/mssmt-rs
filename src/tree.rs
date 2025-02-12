use crate::node::{Branch, EmptyLeaf, HashValue, Leaf, Node};

pub struct MSSMT<KVStore: Db, const HASH_SIZE: usize> {
    db: KVStore,
    empty_tree: Vec<Node>,
    pub empty_tree_root_hash: HashValue,
}

pub trait Db {
    fn get_root_node(&self) -> Branch;
    fn get(&self, key: &HashValue) -> Option<Node>;
    fn insert(&self, key: HashValue, leaf: Leaf);
    fn update_root(&self, root: Branch);
    fn delete_branch(&self, key: HashValue);
    fn delete_leaf(&self, key: HashValue);
    fn insert_branch(&self, branch: Branch);
}
fn bit_index(index: usize, key: HashValue) -> u8 {
    // `index as usize / 8` to get the index of the interesting byte
    // `index % 8` to get the interesting bit index in the previously selected byte
    // right shift it and keep only this interesting bit with & 1.
    (key[index / 8] >> (index % 8)) & 1
}

impl<KVStore: Db, const HASH_SIZE: usize> MSSMT<KVStore, HASH_SIZE> {
    pub fn new(db: KVStore) -> Self {
        // let empty_node_hash = EmptyLeaf.hash();
        let mut empty_tree = Vec::with_capacity(Self::max_height() + 1);
        let empty_leaf = Node::Empty(EmptyLeaf::new());
        empty_tree.push(empty_leaf);
        for i in 1..=Self::max_height() {
            empty_tree.push(Node::new_branch(
                empty_tree[i - 1].clone(),
                empty_tree[i - 1].clone(),
            ));
        }
        empty_tree.reverse();
        Self {
            db,
            empty_tree_root_hash: empty_tree[0].hash(),
            empty_tree,
        }
    }
    pub const fn max_height() -> usize {
        HASH_SIZE * 8
    }
    pub fn get_leaf_from_top(&self, key: HashValue) -> Leaf {
        let mut current_branch = Node::Branch(self.db.get_root_node());
        for i in 0..Self::max_height() {
            if bit_index(i, key) == 0 {
                let (left, _) = self.get_children(i, current_branch.hash());
                current_branch = left;
            } else {
                let (_, right) = self.get_children(i, current_branch.hash());
                current_branch = right;
            }
        }
        match current_branch {
            Node::Leaf(leaf) => leaf,
            Node::Branch(_) => panic!("expected leaf found branch"),
            Node::Empty(_) => panic!("Empty node"),
        }
    }

    pub fn get_children(&self, height: usize, key: HashValue) -> (Node, Node) {
        let get_node = |height: usize, key: HashValue| {
            if key == self.empty_tree[height].hash() {
                return self.empty_tree[height].clone();
            }
            match self.db.get(&key) {
                Some(node) => node,
                None => panic!("Node not found"),
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

    pub fn walk_down(
        &self,
        key: HashValue,
        mut for_each: impl FnMut(usize, &Node, Node, Node),
    ) -> Leaf {
        let mut current = Node::Branch(self.db.get_root_node());
        for i in 0..Self::max_height() {
            let (left, right) = self.get_children(i, current.hash());
            let (next, sibling) = if bit_index(i, key) == 0 {
                (left, right)
            } else {
                (right, left)
            };
            for_each(i, &next, sibling, current);
            current = next;
        }
        match current {
            Node::Leaf(leaf) => leaf,
            Node::Branch(_) => panic!("expected leaf found branch"),
            Node::Empty(_) => panic!("Empty node"),
        }
    }

    pub fn walk_up(
        &self,
        key: HashValue,
        start: Leaf,
        mut siblings: Vec<Branch>,
        mut for_each: impl FnMut(usize, &Node, &Node, &Node),
    ) -> Branch {
        let mut current = Node::Leaf(start);
        for i in (Self::max_height() - 1)..=0 {
            let sibling = Node::Branch(siblings.pop().unwrap());
            let parent = if bit_index(i, key) == 0 {
                Node::from((current.clone(), sibling.clone()))
            } else {
                Node::from((sibling.clone(), current.clone()))
            };
            for_each(i, &current, &sibling, &parent);
            current = parent;
        }
        if let Node::Branch(current) = current {
            current
        } else {
            panic!("Shouldn't end on a leaf");
        }
    }

    pub fn insert(&mut self, key: HashValue, leaf: Leaf) {
        let mut parents = Vec::with_capacity(Self::max_height());
        let mut siblings = Vec::with_capacity(Self::max_height());
        self.walk_down(key, |height, _next, sibling, parent| {
            parents[Self::max_height() - height - 1] = parent.hash();
            siblings[Self::max_height() - height - 1] = sibling;
        });
        let root = self.walk_up(
            key,
            leaf.clone(),
            siblings
                .into_iter()
                .map(|node| match node {
                    Node::Branch(branch) => branch,
                    _ => panic!("Expected branch found leaf"),
                })
                .collect(),
            |height, _current, _sibling, parent| {
                let prev_parent = parents[Self::max_height() - height - 1];
                if prev_parent != self.empty_tree[height].hash() {
                    self.db.delete_branch(prev_parent);
                }
                if parent.hash() != self.empty_tree[height].hash() {
                    match parent {
                        Node::Branch(parent) => self.db.insert_branch(parent.clone()),
                        Node::Leaf(_) => panic!("Should be a branch"),
                        Node::Empty(_) => panic!("Empty node"),
                    }
                }
            },
        );
        self.db.insert(leaf.hash(), leaf);
        self.db.update_root(root);
    }
}
