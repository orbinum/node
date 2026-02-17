//! TreeDepth value object - Merkle tree depth

use core::fmt;

/// Merkle tree depth.
///
/// Represents tree height (number of levels from leaf to root).
/// Computed as: `depth = ceil(log2(tree_size))`.
///
/// # Validation
/// - Must be `>= 0`
/// - Typically `<= 32` (for trees up to `2^32` leaves)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreeDepth(u32);

impl TreeDepth {
	/// Creates a `TreeDepth` from a numeric value.
	pub fn new(depth: u32) -> Self {
		Self(depth)
	}

	/// Returns the internal value.
	pub fn value(&self) -> u32 {
		self.0
	}

	/// Computes required depth for a given tree size.
	///
	/// Formula: `depth = ceil(log2(tree_size))`
	///
	/// # Examples
	/// ```
	/// # use fc_rpc_v2::orbinum::domain::TreeDepth;
	/// assert_eq!(TreeDepth::from_tree_size(1).value(), 1);
	/// assert_eq!(TreeDepth::from_tree_size(2).value(), 1);
	/// assert_eq!(TreeDepth::from_tree_size(3).value(), 2);
	/// assert_eq!(TreeDepth::from_tree_size(4).value(), 2);
	/// assert_eq!(TreeDepth::from_tree_size(5).value(), 3);
	/// ```
	pub fn from_tree_size(tree_size: u32) -> Self {
		if tree_size <= 1 {
			Self(tree_size)
		} else {
			// ceil(log2(n)) = 32 - leading_zeros(n - 1)
			Self(32 - (tree_size - 1).leading_zeros())
		}
	}

	/// Computes the maximum number of leaves for this depth.
	///
	/// Formula: `max_leaves = 2^depth`
	pub fn max_leaves(&self) -> u32 {
		2u32.saturating_pow(self.0)
	}
}

impl From<u32> for TreeDepth {
	fn from(depth: u32) -> Self {
		Self::new(depth)
	}
}

impl fmt::Display for TreeDepth {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_and_read_tree_depth() {
		let depth = TreeDepth::new(12);
		assert_eq!(depth.value(), 12);
	}

	#[test]
	fn should_compute_depth_from_tree_size() {
		assert_eq!(TreeDepth::from_tree_size(0).value(), 0);
		assert_eq!(TreeDepth::from_tree_size(1).value(), 1);
		assert_eq!(TreeDepth::from_tree_size(2).value(), 1);
		assert_eq!(TreeDepth::from_tree_size(3).value(), 2);
		assert_eq!(TreeDepth::from_tree_size(4).value(), 2);
		assert_eq!(TreeDepth::from_tree_size(5).value(), 3);
	}

	#[test]
	fn should_compute_max_leaves() {
		assert_eq!(TreeDepth::new(0).max_leaves(), 1);
		assert_eq!(TreeDepth::new(1).max_leaves(), 2);
		assert_eq!(TreeDepth::new(5).max_leaves(), 32);
	}

	#[test]
	fn should_support_from_and_display() {
		let depth: TreeDepth = 9u32.into();
		assert_eq!(depth.to_string(), "9");
	}
}
