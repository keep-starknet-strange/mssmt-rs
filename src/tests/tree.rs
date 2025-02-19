//! Tests for the Merkle Sum Sparse Merkle Tree implementation

use hex_literal::hex;
use sha2::Sha256;

use crate::{
    node::{Branch, EmptyLeaf, Hasher, Leaf, Node},
    tree::{Db, TreeBuilder, MSSMT},
    MemoryDb,
};

#[test]
fn test_empty_tree() {
    let tree = MSSMT::<_, 32, Sha256>::new(MemoryDb::default());
    assert_eq!(
        tree.empty_tree_root_hash,
        hex!("b1e8e8f2dc3b266452988cfe169aa73be25405eeead02ab5dd6b3c6fd0ca8d67")
    );
}

#[test]
fn test_leaves_insertion() {
    let leaf1 = Leaf::new([1; 32].to_vec(), 1);
    let leaf2 = Leaf::new([2; 32].to_vec(), 2);
    let leaf3 = Leaf::new([3; 32].to_vec(), 3);

    let mut tree = MSSMT::<_, 32, Sha256>::new(MemoryDb::default());
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
    let leaf1 = Leaf::new([1; 32].to_vec(), 1);
    let leaf2 = Leaf::new([2; 32].to_vec(), 2);
    let leaf3 = Leaf::new([3; 32].to_vec(), 3);

    let mut tree = MSSMT::<_, 32, Sha256>::new(MemoryDb::default());
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
    // tests that inserting leaves, branches and compacted leaves
    // in an orderly manner results in the expected tree structure in the database.
    fn test_children<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone + Default>(
        leaves: Vec<Leaf<HASH_SIZE, H>>,
        check_branches: Vec<Vec<Branch<HASH_SIZE, H>>>,
        leaf_level: usize,
    ) {
        let mut db = MemoryDb::default();
        for leaf in leaves {
            db.insert_leaf(leaf);
        }
        for branches in check_branches.clone() {
            for branch in branches {
                db.insert_branch(branch);
            }
        }
        let tree = TreeBuilder::build(db);
        for (index, level) in check_branches.into_iter().enumerate() {
            for branch in level {
                let (left, right) = tree.get_children(leaf_level + index, branch.hash());
                assert_eq!(branch.left().hash(), left.hash());
                assert_eq!(branch.right().hash(), right.hash());
            }
        }
    }
    let empty_tree = TreeBuilder::<32, Sha256>::empty_tree();
    let l1 = Leaf::new([1; 32].to_vec(), 1);
    let l2 = Leaf::new([2; 32].to_vec(), 2);
    let l3 = Leaf::<32, Sha256>::new([3; 32].to_vec(), 3);
    let l4 = Leaf::new([4; 32].to_vec(), 4);
    let el = EmptyLeaf::new();
    let branch_l1_l2 = Branch::new(Node::Leaf(l1.clone()), Node::Leaf(l2.clone()));
    let branch_l3_l4 = Branch::new(Node::Leaf(l3.clone()), Node::Leaf(l4.clone()));
    let branch_l1_el = Branch::new(Node::Leaf(l1.clone()), Node::Empty(el.clone()));
    let branch_el_l1 = Branch::new(Node::Empty(el), Node::Leaf(l1.clone()));
    //       R
    //     /  \
    //    B1  Empty
    //   /  \
    //  L1  L2
    let root_branch = Branch::new(Node::Branch(branch_l1_l2.clone()), empty_tree[255].clone());
    test_children(
        vec![l1.clone(), l2.clone()],
        vec![vec![root_branch], vec![branch_l1_l2.clone()]],
        254,
    );

    //         R
    //       /  \
    //  Empty    B1
    //          /  \
    //         L1  L2
    let root_branch = Branch::new(empty_tree[255].clone(), Node::Branch(branch_l1_l2.clone()));
    test_children(
        vec![l1.clone(), l2.clone()],
        vec![vec![root_branch], vec![branch_l1_l2.clone()]],
        254,
    );

    //       R
    //     /  \
    //    B2  Empty
    //   /  \
    //  L1  Empty
    let root_branch = Branch::new(Node::Branch(branch_l1_el.clone()), empty_tree[255].clone());
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_l1_el.clone()]],
        254,
    );

    //         R
    //       /  \
    //      B2  Empty
    //     /  \
    // Empty  L1
    let root_branch = Branch::new(Node::Branch(branch_el_l1.clone()), empty_tree[255].clone());
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_el_l1.clone()]],
        254,
    );
    //        R
    //      /  \
    //  Empty  B2
    //        /  \
    //      L1  Empty
    //

    let root_branch = Branch::new(empty_tree[255].clone(), Node::Branch(branch_l1_el.clone()));
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_l1_el.clone()]],
        254,
    );
    //         R
    //       /  \
    //   Empty  B2
    //         /  \
    //     Empty  L1
    let root_branch = Branch::new(empty_tree[255].clone(), Node::Branch(branch_el_l1.clone()));
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_el_l1.clone()]],
        254,
    );
    //          R
    //        /   \
    //      B1     B2
    //     /  \   /  \
    //    L1  L2 L3  L4
    let root_branch = Branch::new(
        Node::Branch(branch_l1_l2.clone()),
        Node::Branch(branch_l3_l4.clone()),
    );
    test_children(
        vec![l1.clone(), l2.clone(), l3.clone(), l4.clone()],
        vec![
            vec![root_branch],
            vec![branch_l1_l2.clone(), branch_l3_l4.clone()],
        ],
        254,
    );

    //             R
    //           /  \
    //         B3    B4
    //        /  \  /  \
    //      B1   E E   B2
    //     / \        /  \
    //    L1 L2      L3  L4
    let b3 = Branch::new(Node::Branch(branch_l1_l2.clone()), empty_tree[255].clone());
    let b4 = Branch::new(empty_tree[255].clone(), Node::Branch(branch_l1_l2.clone()));
    let root_branch = Branch::new(Node::Branch(b3.clone()), Node::Branch(b4.clone()));
    test_children(
        vec![l1.clone(), l2.clone(), l3.clone(), l4.clone()],
        vec![
            vec![root_branch],
            vec![b3, b4],
            vec![branch_l1_l2.clone(), branch_l3_l4],
        ],
        253,
    );
}
