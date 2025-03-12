mod compact;
mod empty;
mod regular;

use std::borrow::Borrow;
use std::sync::Arc;

pub use compact::CompactMSSMT;
pub use empty::EmptyTree;
pub use regular::bit_index;
pub use regular::MSSMT;

use crate::Branch;
use crate::Hasher;
use crate::Leaf;
use crate::Node;
use crate::TreeError;

/// Walk up the tree from the node to the root node.
/// * `key` - key of the node we want to reach.
/// * `start` - starting leaf.
/// * `siblings` - All the sibling nodes on the path (from the leaf to the target node).
/// * `for_each` - Closure that is executed at each step of the traversal of the tree.
///     * `height: usize` - current height in the tree
///     * `current: &Node<HASH_SIZE, H>` - current node on the way to the asked node
///     * `sibling: &Node<HASH_SIZE, H>` - sibling node of the current node on the way to the asked node
///     * `parent: &Node<HASH_SIZE, H>` - parent node of the current node on the way to the asked node
pub fn walk_up<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone, DbError>(
    key: &[u8; HASH_SIZE],
    start: Leaf<HASH_SIZE, H>,
    siblings: &[Arc<Node<HASH_SIZE, H>>],
    mut for_each: impl FnMut(usize, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>, &Node<HASH_SIZE, H>),
) -> Result<Branch<HASH_SIZE, H>, TreeError<DbError>> {
    let mut current = Arc::new(Node::Leaf(start));
    for i in (0..MSSMT::<HASH_SIZE, H, DbError>::max_levels()).rev() {
        let sibling = siblings[MSSMT::<HASH_SIZE, H, DbError>::max_levels() - 1 - i].clone();
        // order the children based on the path
        let parent = if bit_index(i, key) == 0 {
            Node::Branch(Branch::new_with_arc_children(
                current.clone(),
                sibling.clone(),
            ))
        } else {
            Node::Branch(Branch::new_with_arc_children(
                sibling.clone(),
                current.clone(),
            ))
        };
        for_each(i, &current, &sibling, &parent);
        current = Arc::new(parent);
    }
    if let Node::Branch(current) = current.borrow() {
        Ok(current.clone())
    } else {
        Err(TreeError::ExpectedBranch)
    }
}
