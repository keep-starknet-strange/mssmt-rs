use hex_literal::hex;
use std::collections::HashMap;

use crate::{
    node::{Branch, HashValue, Leaf},
    tree::{Db, MSSMT},
};
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TestDb {
    branches: HashMap<HashValue, Branch>,
    leaves: HashMap<HashValue, Leaf>,
    root_node: Option<Branch>,
}
impl Db for TestDb {
    fn get_root_node(&self) -> crate::node::Branch {
        self.root_node.clone().unwrap()
    }

    fn get_branch(&self, key: &HashValue) -> Option<crate::node::Branch> {
        self.branches.get(key).cloned()
    }
    fn get_leaf(&self, key: &HashValue) -> Option<crate::node::Leaf> {
        self.leaves.get(key).cloned()
    }

    fn insert(&mut self, key: HashValue, leaf: crate::node::Leaf) {
        self.leaves.insert(key, leaf);
    }

    fn update_root(&mut self, root: crate::node::Branch) {
        self.root_node = Some(root)
    }

    fn delete_branch(&mut self, key: &HashValue) {
        self.branches.remove(key);
    }

    fn delete_leaf(&mut self, key: &HashValue) {
        self.leaves.remove(key);
    }

    fn insert_branch(&mut self, branch: crate::node::Branch) {
        self.branches.insert(branch.hash(), branch);
    }
}
#[test]
fn test_empty_tree() {
    let tree = MSSMT::<_, 32>::new(TestDb::default());
    assert_eq!(
        tree.empty_tree_root_hash,
        hex! {"b1e8e8f2dc3b266452988cfe169aa73be25405eeead02ab5dd6b3c6fd0ca8d67"}
    );
}

#[test]
fn test_insertion() {
    let leaf1 = Leaf::new([1; 32], 1);
    let leaf2 = Leaf::new([2; 32], 2);
    let leaf3 = Leaf::new([3; 32], 3);

    let mut tree = MSSMT::<_, 32>::new(TestDb::default());
    tree.insert([1; 32], leaf1);
    assert_eq!(
        tree.root().hash(),
        hex!("b46e250d98aa9917abdd1012f72c03ab9a59f6de5253d963a99b7d69c2eca3da")
    );
    tree.insert([2; 32], leaf2);
    assert_eq!(
        tree.root().hash(),
        hex!("dc5ab9a0f0b56e215b550b2946cdc72aae2b013aa4790ee4d809a9b43cf2d9aa")
    );
    tree.insert([3; 32], leaf3);
    assert_eq!(
        tree.root().hash(),
        hex!("37cb0517efdaaeb2c2c32fac206d8f14070864a1fd69d5368127dba161569ca2")
    );
}
