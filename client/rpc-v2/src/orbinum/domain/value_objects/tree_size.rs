//! TreeSize value object - Merkle tree size

use core::fmt;

/// Merkle tree size (number of leaves/commitments).
///
/// Represents the total number of commitments inserted in the tree.
///
/// # Validation
/// - Must be `>= 0`
/// - Should not exceed the maximum leaves allowed by tree depth
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreeSize(u32);

impl TreeSize {
	/// Creates a `TreeSize` from a numeric value.
	pub fn new(size: u32) -> Self {
		Self(size)
	}

	/// Returns the internal value.
	pub fn value(&self) -> u32 {
		self.0
	}

	/// Checks if the tree is empty.
	pub fn is_empty(&self) -> bool {
		self.0 == 0
	}

	/// Increments size by 1 (saturating).
	pub fn increment(&mut self) {
		self.0 = self.0.saturating_add(1);
	}

	/// Returns the next available index.
	pub fn next_index(&self) -> u32 {
		self.0
	}
}

impl From<u32> for TreeSize {
	fn from(size: u32) -> Self {
		Self::new(size)
	}
}

impl fmt::Display for TreeSize {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_and_read_tree_size() {
		let size = TreeSize::new(15);
		assert_eq!(size.value(), 15);
		assert!(!size.is_empty());
	}

	#[test]
	fn should_report_empty_state() {
		let empty = TreeSize::new(0);
		assert!(empty.is_empty());
		assert_eq!(empty.next_index(), 0);
	}

	#[test]
	fn should_increment_with_saturation() {
		let mut size = TreeSize::new(u32::MAX - 1);
		size.increment();
		assert_eq!(size.value(), u32::MAX);

		size.increment();
		assert_eq!(size.value(), u32::MAX);
	}

	#[test]
	fn should_support_from_and_display() {
		let size: TreeSize = 21u32.into();
		assert_eq!(size.to_string(), "21");
	}
}
