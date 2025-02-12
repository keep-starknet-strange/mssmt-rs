use std::sync::Arc;

use sha2::{Digest, Sha256};

pub type HashValue = [u8; 32];
pub type Sum = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Leaf(Leaf),
    Branch(Branch),
    Empty(EmptyLeaf),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyLeaf(HashValue);
impl Default for EmptyLeaf {
    fn default() -> Self {
        Self::new()
    }
}

impl EmptyLeaf {
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update([]);
        hasher.update([0; 8]);

        Self(hasher.finalize().into())
    }
    pub fn hash(&self) -> HashValue {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    value: HashValue,
    sum: Sum,
    node_hash: HashValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    left: Arc<Node>,
    right: Arc<Node>,
    sum: Sum,
    node_hash: HashValue,
}

impl From<(Branch, Branch)> for Node {
    fn from((left, right): (Branch, Branch)) -> Self {
        Self::new_branch(Self::Branch(left), Self::Branch(right))
    }
}
impl From<(Node, Node)> for Node {
    fn from((left, right): (Node, Node)) -> Self {
        Self::new_branch(left, right)
    }
}
impl From<(Node, Branch)> for Node {
    fn from((left, right): (Self, Branch)) -> Self {
        Self::new_branch(left, Self::Branch(right))
    }
}
impl From<(Branch, Node)> for Node {
    fn from((left, right): (Branch, Self)) -> Self {
        Self::new_branch(Self::Branch(left), right)
    }
}

impl Node {
    pub fn new_branch(left: Node, right: Node) -> Self {
        Self::Branch(Branch::new(left, right))
    }
    pub fn new_leaf(value: HashValue, sum: Sum) -> Self {
        Self::Leaf(Leaf::new(value, sum))
    }
    pub fn hash(&self) -> HashValue {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Branch(branch) => branch.hash(),
            Self::Empty(empty) => empty.hash(),
        }
    }
    pub fn sum(&self) -> Sum {
        match self {
            Self::Leaf(leaf) => leaf.sum,
            Self::Branch(branch) => branch.sum,
            Self::Empty(_) => 0,
        }
    }
}
impl Leaf {
    pub fn new(value: HashValue, sum: Sum) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.update(sum.to_be_bytes());
        let hash = hasher.finalize().into();
        Self {
            value,
            sum,
            node_hash: hash,
        }
    }
    pub fn hash(&self) -> HashValue {
        self.node_hash
    }
}
impl Branch {
    pub fn new(left: Node, right: Node) -> Self {
        let sum = left.sum() + right.sum();
        let mut hasher = Sha256::new();
        hasher.update(left.hash());
        hasher.update(right.hash());
        hasher.update(sum.to_be_bytes());

        Self {
            sum,
            left: Arc::new(left),
            right: Arc::new(right),
            node_hash: hasher.finalize().into(),
        }
    }
    pub fn empty_branch() -> Self {
        let leaf = Node::Empty(EmptyLeaf::new());
        Self::new(leaf.clone(), leaf)
    }
    pub fn hash(&self) -> HashValue {
        self.node_hash
    }
    pub fn children(&self) -> (&Node, &Node) {
        (&self.left, &self.right)
    }
    pub fn left(&self) -> &Node {
        &self.left
    }
    pub fn right(&self) -> &Node {
        &self.right
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use crate::node::Branch;
    #[test]
    fn test_empty_leaf_node_hash() {
        assert_eq!(
            super::EmptyLeaf::new().hash(),
            hex!("af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc")
        )
    }
    #[test]
    fn test_non_empty_leaf_node_hash() {
        assert_eq!(
            super::Leaf::new(
                [
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 26, 28, 29, 30, 31, 32
                ],
                1
            )
            .hash(),
            hex!("be7354c2c1c189bc64c3c4092e7141d6880936f15cd08e8498a53df99de724c4")
        )
    }

    #[test]
    fn test_branch_with_empty_leaves() {
        assert_eq!(
            Branch::empty_branch().node_hash,
            hex!("5a61e238f07e3a8114e39670c1e5ff430913d5793028258cf8a49282efee4411")
        )
    }
}
