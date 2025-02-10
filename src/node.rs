use sha2::{Digest, Sha256};

pub type HashValue = [u8; 32];
pub type Sum = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Leaf(Leaf),
    Branch(Branch),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    value: HashValue,
    sum: Sum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    left: Box<Node>,
    right: Box<Node>,
    sum: Sum,
}

impl Node {
    pub fn hash(&self) -> HashValue {
        match self {
            Self::Leaf(leaf) => leaf.hash(),
            Self::Branch(branch) => branch.hash(),
        }
    }
}
impl Leaf {
    pub fn hash(&self) -> HashValue {
        let mut hasher = Sha256::new();
        hasher.update(self.value);
        hasher.update(self.sum.to_be_bytes());
        hasher.finalize().into()
    }
}
impl Branch {
    pub fn hash(&self) -> HashValue {
        let mut hasher = Sha256::new();
        hasher.update(self.left.hash());
        hasher.update(self.right.hash());
        hasher.update(self.sum.to_be_bytes());
        hasher.finalize().into()
    }
    pub fn children(&self) -> (&Box<Node>, &Box<Node>) {
        (&self.left, &self.right)
    }
    pub fn left(&self) -> &Box<Node> {
        &self.left
    }
    pub fn right(&self) -> &Box<Node> {
        &self.right
    }
}
