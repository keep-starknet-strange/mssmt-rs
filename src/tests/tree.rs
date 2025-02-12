use hex_literal::hex;
use std::collections::HashMap;

use crate::{
    node::{Branch, HashValue, Leaf},
    tree::{Db, MSSMT},
};
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct TestDb {
    branches: HashMap<HashValue, Branch>,
    leaves: HashMap<HashValue, Leaf>,
}
impl Db for TestDb {
    fn get_root_node(&self) -> crate::node::Branch {
        todo!()
    }

    fn get(&self, key: &HashValue) -> Option<crate::node::Node> {
        todo!()
    }

    fn insert(&self, key: HashValue, leaf: crate::node::Leaf) {
        todo!()
    }

    fn update_root(&self, root: crate::node::Branch) {
        todo!()
    }

    fn delete_branch(&self, key: HashValue) {
        todo!()
    }

    fn delete_leaf(&self, key: HashValue) {
        todo!()
    }

    fn insert_branch(&self, branch: crate::node::Branch) {
        todo!()
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
