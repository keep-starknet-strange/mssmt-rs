use hex_literal::hex;
use sha2::{Digest, Sha512};

use crate::{
    node::{Branch, CompactLeaf, Hasher, Leaf, Node},
    tree::{CompactMSSMT, MSSMT},
    Db, EmptyTree, MemoryDb, ThreadSafe,
};

impl Hasher<64> for Sha512 {
    fn hash(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[test]
fn test_empty_tree() {
    let tree = MSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));
    let compact_tree = CompactMSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));
    assert_eq!(
        tree.root().unwrap().hash(),
        hex!("45cf5fc060eace3bfd5f51bcc6dc6fa4c3a32c0fbada3e544a842a8ce8a5416c35345b878f3a11d9fef0f17ad285971426025664c3923a9cc0d11d2363e41975")
    );
    assert_eq!(
        compact_tree.root().unwrap().hash(),
        hex!("45cf5fc060eace3bfd5f51bcc6dc6fa4c3a32c0fbada3e544a842a8ce8a5416c35345b878f3a11d9fef0f17ad285971426025664c3923a9cc0d11d2363e41975")
    );
    assert_eq!(
        tree.db().empty_tree().as_ref()[0].hash(),
        hex!("45cf5fc060eace3bfd5f51bcc6dc6fa4c3a32c0fbada3e544a842a8ce8a5416c35345b878f3a11d9fef0f17ad285971426025664c3923a9cc0d11d2363e41975")
    );
    assert_eq!(
        compact_tree.db().empty_tree().as_ref()[0].hash(),
        hex!("45cf5fc060eace3bfd5f51bcc6dc6fa4c3a32c0fbada3e544a842a8ce8a5416c35345b878f3a11d9fef0f17ad285971426025664c3923a9cc0d11d2363e41975")
    );
}

#[test]
fn test_leaves_insertion() {
    let leaf1 = Leaf::<64, Sha512>::new([1; 64].to_vec(), 1);
    let leaf2 = Leaf::<64, Sha512>::new([2; 64].to_vec(), 2);
    let leaf3 = Leaf::<64, Sha512>::new([3; 64].to_vec(), 3);

    let leaf4 = Leaf::<64, Sha512>::new(
        vec![
            2, 140, 120, 40, 192, 9, 98, 114, 244, 120, 64, 72, 171, 79, 80, 112, 181, 15, 155, 49,
            210, 19, 22, 216, 74, 168, 143, 149, 16, 184, 63, 25, 192,
        ],
        4,
    );
    let key4 = [
        177_u8, 231, 231, 200, 71, 83, 63, 150, 221, 247, 213, 231, 188, 27, 190, 148, 112, 218,
        129, 131, 93, 195, 197, 44, 143, 203, 191, 17, 154, 100, 103, 100, 177_u8, 231, 231, 200,
        71, 83, 63, 150, 221, 247, 213, 231, 188, 27, 190, 148, 112, 218, 129, 131, 93, 195, 197,
        44, 143, 203, 191, 17, 154, 100, 103, 100,
    ];
    assert_eq!(
        leaf4.hash(),
        hex!("bd6fe6e7d33ee372467e746e21672708ab7e4982354e44bca98f11763f1fcb0fb1f7b112259bc297d1c15f5e42c6ee87915eb469284a2b0b3d1d32ecef3158a2")
    );

    let mut tree = MSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));
    let mut compact_tree = CompactMSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));

    tree.insert(&[1; 64], leaf1.clone()).unwrap();
    compact_tree.insert(&[1; 64], leaf1.clone()).unwrap();
    assert_eq!(
        tree.root().unwrap().hash(),
        hex!("19ed12c23395e30b128ac17e42728e0af08b2d15c9c2cea7950ef4be3547901562c5c2d1a4ef8c578bffcec8262b067c13dfe24c078f6a237f50eeb3242b2c00")
    );
    assert_eq!(
        compact_tree.root().unwrap().hash(),
        hex!("19ed12c23395e30b128ac17e42728e0af08b2d15c9c2cea7950ef4be3547901562c5c2d1a4ef8c578bffcec8262b067c13dfe24c078f6a237f50eeb3242b2c00")
    );

    tree.insert(&[2; 64], leaf2.clone()).unwrap();
    compact_tree.insert(&[2; 64], leaf2.clone()).unwrap();
    assert_eq!(
        tree.root().unwrap().hash(),
        hex!("ddeced697e31a7c68ffe385bfc6b959099eb9b52a1512d11ce4b96c007c08cb5b743f2de5dd64719e968534c249a322b91486fdc697372900485fd18a8d7996c")
    );
    assert_eq!(
        compact_tree.root().unwrap().hash(),
        hex!("ddeced697e31a7c68ffe385bfc6b959099eb9b52a1512d11ce4b96c007c08cb5b743f2de5dd64719e968534c249a322b91486fdc697372900485fd18a8d7996c")
    );

    tree.insert(&[3; 64], leaf3.clone()).unwrap();
    compact_tree.insert(&[3; 64], leaf3.clone()).unwrap();
    assert_eq!(
        tree.root().unwrap().hash(),
        hex!("f449d7cbc8783352fcd5f7d33496a32cab342d455d5be026794c19849027db3f893f30a017a63002f36fa97cfbfc0039ce3c660652a89e681cf2ba1ef2670d22")
    );
    assert_eq!(
        compact_tree.root().unwrap().hash(),
        hex!("f449d7cbc8783352fcd5f7d33496a32cab342d455d5be026794c19849027db3f893f30a017a63002f36fa97cfbfc0039ce3c660652a89e681cf2ba1ef2670d22")
    );
    tree.insert(&key4, leaf4.clone()).unwrap();
    compact_tree.insert(&key4, leaf4.clone()).unwrap();

    assert_eq!(
        tree.root().unwrap().hash(),
        compact_tree.root().unwrap().hash()
    );
}

#[test]
fn test_history_independant() {
    let leaf1 = Leaf::new([1; 64].to_vec(), 1);
    let leaf2 = Leaf::new([2; 64].to_vec(), 2);
    let leaf3 = Leaf::new([3; 64].to_vec(), 3);

    let mut tree = MSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));
    let mut compact_tree = CompactMSSMT::<64, Sha512, ()>::new(Box::new(MemoryDb::default()));
    tree.insert(&[1; 64], leaf1.clone()).unwrap();
    tree.insert(&[3; 64], leaf3.clone()).unwrap();
    tree.insert(&[2; 64], leaf2.clone()).unwrap();
    compact_tree.insert(&[3; 64], leaf3.clone()).unwrap();
    compact_tree.insert(&[2; 64], leaf2.clone()).unwrap();
    compact_tree.insert(&[1; 64], leaf1.clone()).unwrap();

    assert_eq!(
        tree.root().unwrap().hash(),
        hex!("f449d7cbc8783352fcd5f7d33496a32cab342d455d5be026794c19849027db3f893f30a017a63002f36fa97cfbfc0039ce3c660652a89e681cf2ba1ef2670d22")
    );
    assert_eq!(
        compact_tree.root().unwrap().hash(),
        hex!("f449d7cbc8783352fcd5f7d33496a32cab342d455d5be026794c19849027db3f893f30a017a63002f36fa97cfbfc0039ce3c660652a89e681cf2ba1ef2670d22")
    );
}

#[test]
fn test_insertion() {
    // tests that inserting leaves, branches and compacted leaves
    // in an orderly manner results in the expected tree structure in the database.
    fn test_children<
        const HASH_SIZE: usize,
        H: Hasher<HASH_SIZE> + Clone + Default + ThreadSafe,
    >(
        leaves: Vec<Leaf<HASH_SIZE, H>>,
        check_branches: Vec<Vec<Branch<HASH_SIZE, H>>>,
        leaf_level: usize,
    ) {
        let mut db = MemoryDb::default();
        for leaf in leaves {
            db.insert_leaf(leaf).unwrap();
        }
        for branches in check_branches.clone() {
            for branch in branches {
                db.insert_branch(branch).unwrap();
            }
        }
        for (index, level) in check_branches.into_iter().enumerate() {
            for branch in level {
                let (left, right) = db.get_children(leaf_level + index, branch.hash()).unwrap();
                assert_eq!(branch.left().hash(), left.hash());
                assert_eq!(branch.right().hash(), right.hash());
            }
        }
    }

    let l1 = Leaf::new([1; 64].to_vec(), 1);
    let l2 = Leaf::new([2; 64].to_vec(), 2);
    let l3 = Leaf::<64, Sha512>::new([3; 64].to_vec(), 3);
    let l4 = Leaf::new([4; 64].to_vec(), 4);
    let branch_l1_l2 = Branch::new(Node::Leaf(l1.clone()), Node::Leaf(l2.clone()));
    let branch_l3_l4 = Branch::new(Node::Leaf(l3.clone()), Node::Leaf(l4.clone()));
    let branch_l1_el = Branch::new(Node::Leaf(l1.clone()), Node::new_empty_leaf());
    let branch_el_l1 = Branch::new(Node::new_empty_leaf(), Node::Leaf(l1.clone()));
    let k1 = [1_u8; 64];
    let k2 = [2_u8; 64];
    let k3 = [3_u8; 64];
    let k4 = [4_u8; 64];

    let empty_tree = EmptyTree::<64, Sha512>::empty_tree();

    let cl1 = CompactLeaf::new(100, k1, l1.clone(), empty_tree.clone());
    let cl2 = CompactLeaf::new(100, k2, l2.clone(), empty_tree.clone());
    let cl3 = CompactLeaf::new(99, k3, l3.clone(), empty_tree.clone());
    let cl4 = CompactLeaf::new(99, k4, l4.clone(), empty_tree.clone());
    let branch_cl1_cl2 = Branch::new(Node::Compact(cl1.clone()), Node::Compact(cl2.clone()));
    let branch_cl1_cl2_cl3 = Branch::new(
        Node::Branch(branch_cl1_cl2.clone()),
        Node::Compact(cl3.clone()),
    );
    let branch_cl4_eb = Branch::new(Node::Compact(cl4.clone()), empty_tree[99].clone());

    //       R
    //     /  \
    //    B1  Empty
    //   /  \
    //  L1  L2
    let root_branch = Branch::new(Node::Branch(branch_l1_l2.clone()), empty_tree[511].clone());
    test_children(
        vec![l1.clone(), l2.clone()],
        vec![vec![root_branch], vec![branch_l1_l2.clone()]],
        510,
    );

    //         R
    //       /  \
    //  Empty    B1
    //          /  \
    //         L1  L2
    let root_branch = Branch::new(empty_tree[511].clone(), Node::Branch(branch_l1_l2.clone()));
    test_children(
        vec![l1.clone(), l2.clone()],
        vec![vec![root_branch], vec![branch_l1_l2.clone()]],
        510,
    );

    //       R
    //     /  \
    //    B2  Empty
    //   /  \
    //  L1  Empty
    let root_branch = Branch::new(Node::Branch(branch_l1_el.clone()), empty_tree[511].clone());
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_l1_el.clone()]],
        510,
    );

    //         R
    //       /  \
    //      B2  Empty
    //     /  \
    // Empty  L1
    let root_branch = Branch::new(Node::Branch(branch_el_l1.clone()), empty_tree[511].clone());
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_el_l1.clone()]],
        510,
    );

    //        R
    //      /  \
    //  Empty  B2
    //        /  \
    //      L1  Empty
    let root_branch = Branch::new(empty_tree[511].clone(), Node::Branch(branch_l1_el.clone()));
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_l1_el.clone()]],
        510,
    );

    //         R
    //       /  \
    //   Empty  B2
    //         /  \
    //     Empty  L1
    let root_branch = Branch::new(empty_tree[511].clone(), Node::Branch(branch_el_l1.clone()));
    test_children(
        vec![l1.clone()],
        vec![vec![root_branch], vec![branch_el_l1.clone()]],
        510,
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
        510,
    );

    //             R
    //           /  \
    //         B3    B4
    //        /  \  /  \
    //      B1   E E   B2
    //     / \        /  \
    //    L1 L2      L3  L4
    let b3 = Branch::new(Node::Branch(branch_l1_l2.clone()), empty_tree[511].clone());
    let b4 = Branch::new(empty_tree[511].clone(), Node::Branch(branch_l1_l2.clone()));
    let root_branch = Branch::new(Node::Branch(b3.clone()), Node::Branch(b4.clone()));
    test_children(
        vec![l1.clone(), l2.clone(), l3.clone(), l4.clone()],
        vec![
            vec![root_branch],
            vec![b3, b4],
            vec![branch_l1_l2.clone(), branch_l3_l4],
        ],
        509,
    );

    //            R
    //          /   \
    //        B2     B3
    //       /  \   /  \
    //     B1  CL3 CL4 E
    //    /  \
    //  CL1 CL2
    let b2 = branch_cl1_cl2_cl3.clone();
    let root_branch = Branch::new(
        Node::Branch(b2.clone()),
        Node::Branch(branch_cl4_eb.clone()),
    );
    let mut db = MemoryDb::default();
    for cl in [cl1, cl2, cl3, cl4] {
        db.insert_compact_leaf(cl).unwrap();
    }
    let branches = [
        vec![root_branch],
        vec![b2, branch_cl4_eb],
        vec![branch_cl1_cl2],
    ];
    for branches in branches.clone() {
        for branch in branches {
            db.insert_branch(branch).unwrap();
        }
    }
    for (index, level) in branches.into_iter().enumerate() {
        for branch in level {
            let (left, right) = db.get_children(97 + index, branch.hash()).unwrap();
            assert_eq!(branch.left().hash(), left.hash());
            assert_eq!(branch.right().hash(), right.hash());
        }
    }
}
