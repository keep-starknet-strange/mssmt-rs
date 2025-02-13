use hex_literal::hex;
use sha2::Sha256;
use std::collections::HashMap;

use crate::{
    node::{Branch, EmptyLeaf, Hasher, Leaf, Node},
    tree::{Db, MSSMT},
};
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TestDb<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    branches: HashMap<[u8; HASH_SIZE], Branch<HASH_SIZE, H>>,
    leaves: HashMap<[u8; HASH_SIZE], Leaf<HASH_SIZE, H>>,
    root_node: Option<Branch<HASH_SIZE, H>>,
}
impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Db<HASH_SIZE, H>
    for TestDb<HASH_SIZE, H>
{
    fn get_root_node(&self) -> crate::node::Branch<HASH_SIZE, H> {
        self.root_node.clone().unwrap()
    }

    fn get_branch(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Branch<HASH_SIZE, H>> {
        self.branches.get(key).cloned()
    }
    fn get_leaf(&self, key: &[u8; HASH_SIZE]) -> Option<crate::node::Leaf<HASH_SIZE, H>> {
        self.leaves.get(key).cloned()
    }

    fn insert(&mut self, leaf: crate::node::Leaf<HASH_SIZE, H>) {
        self.leaves.insert(leaf.hash(), leaf);
    }

    fn update_root(&mut self, root: crate::node::Branch<HASH_SIZE, H>) {
        self.root_node = Some(root)
    }

    fn delete_branch(&mut self, key: &[u8; HASH_SIZE]) {
        self.branches.remove(key);
    }

    fn delete_leaf(&mut self, key: &[u8; HASH_SIZE]) {
        self.leaves.remove(key);
    }

    fn insert_branch(&mut self, branch: crate::node::Branch<HASH_SIZE, H>) {
        self.branches.insert(branch.hash(), branch);
    }
}
#[test]
fn test_empty_tree() {
    let tree = MSSMT::<_, 32, Sha256>::new(TestDb::default());
    assert_eq!(
        tree.empty_tree_root_hash,
        hex!("b1e8e8f2dc3b266452988cfe169aa73be25405eeead02ab5dd6b3c6fd0ca8d67")
    );
}

#[test]
fn test_leaves_insertion() {
    let leaf1 = Leaf::new([1; 32], 1);
    let leaf2 = Leaf::new([2; 32], 2);
    let leaf3 = Leaf::new([3; 32], 3);

    let mut tree = MSSMT::<_, 32, Sha256>::new(TestDb::default());
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

#[test]
fn test_history_independant() {
    let leaf1 = Leaf::new([1; 32], 1);
    let leaf2 = Leaf::new([2; 32], 2);
    let leaf3 = Leaf::new([3; 32], 3);

    let mut tree = MSSMT::<_, 32, Sha256>::new(TestDb::default());
    tree.insert([1; 32], leaf1);
    tree.insert([3; 32], leaf3);
    tree.insert([2; 32], leaf2);
    assert_eq!(
        tree.root().hash(),
        hex!("37cb0517efdaaeb2c2c32fac206d8f14070864a1fd69d5368127dba161569ca2")
    );
}

#[test]
fn test_insertion() {
    let empty_tree = MSSMT::<_, 32, Sha256>::new(TestDb::default());
    let l1 = Leaf::new([1; 32], 1);
    let l2 = Leaf::new([2; 32], 2);
    let l3 = Leaf::<32, Sha256>::new([3; 32], 3);
    let l4 = Leaf::new([4; 32], 4);
    let el = EmptyLeaf::new();

    let branch_l1_l2 = Branch::new(Node::Leaf(l1.clone()), Node::Leaf(l2.clone()));
    let branch_l3_l4 = Branch::new(Node::Leaf(l3), Node::Leaf(l4));
    let branch_l1_el = Branch::new(Node::Leaf(l1.clone()), Node::Empty(el.clone()));
    let branch_el_l1 = Branch::new(Node::Empty(el), Node::Leaf(l1.clone()));
    let root_branch = Branch::new(
        Node::Branch(branch_l1_l2.clone()),
        empty_tree.empty_tree[256].clone(),
    );
    let mut db = TestDb::default();
    db.insert(l1);
    db.insert(l2);
    db.insert_branch(branch_l1_l2.clone());
    db.insert_branch(root_branch.clone());

    //       R
    //     /  \
    //    B1  Empty
    //   /  \
    //  L1  L2
    let mut tree = MSSMT::<_, 32, Sha256>::new(db);
    let (left, right) = tree.get_children(254, branch_l1_l2.hash());
    assert_eq!(branch_l1_l2.left().hash(), left.hash());
    assert_eq!(branch_l1_l2.right().hash(), right.hash());
    let (left, right) = tree.get_children(254, root_branch.hash());
    assert_eq!(root_branch.left().hash(), left.hash());
    assert_eq!(root_branch.right().hash(), right.hash());
}
