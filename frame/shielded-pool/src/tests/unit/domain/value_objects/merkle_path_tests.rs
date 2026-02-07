//! Tests for merkle_path

use crate::domain::value_objects::DEFAULT_TREE_DEPTH;

#[test]
fn tree_depth_constants_are_consistent() {
	const MAX_TREE_DEPTH: u32 = 20;
	assert_eq!(DEFAULT_TREE_DEPTH, MAX_TREE_DEPTH as usize);
}
