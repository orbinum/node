//! Domain Constants
//!
//! Domain-level constants representing business rules and invariants.

/// Maximum depth of the Merkle tree (2^32 = 4,294,967,296 notes)
pub const MERKLE_TREE_DEPTH: usize = 32;

/// Maximum number of leaves in the Merkle tree
pub const MAX_MERKLE_LEAVES: u64 = 1 << MERKLE_TREE_DEPTH; // 2^32

/// Default asset ID for native tokens
pub const NATIVE_ASSET_ID: u64 = 0;

/// Maximum allowed asset ID
pub const MAX_ASSET_ID: u64 = u64::MAX;

/// Minimum note value (0 allowed for dummy notes)
pub const MIN_NOTE_VALUE: u64 = 0;

/// Maximum note value
pub const MAX_NOTE_VALUE: u64 = u64::MAX;

/// Zero field element representation
pub const ZERO_FIELD: u64 = 0;

#[cfg(test)]
mod tests {
	use super::*;

	// ===== Merkle Tree Tests =====

	#[test]
	fn test_merkle_tree_depth() {
		assert_eq!(MERKLE_TREE_DEPTH, 32);
	}

	#[test]
	fn test_merkle_tree_depth_is_positive() {
		// MERKLE_TREE_DEPTH is always > 0 by definition
		assert_eq!(MERKLE_TREE_DEPTH, 32);
	}

	#[test]
	fn test_max_merkle_leaves() {
		// 2^32 = 4,294,967,296
		assert_eq!(MAX_MERKLE_LEAVES, 4_294_967_296);
		assert_eq!(MAX_MERKLE_LEAVES, 1u64 << MERKLE_TREE_DEPTH);
	}

	#[test]
	fn test_max_merkle_leaves_calculation() {
		// Verify the shift calculation is correct
		let expected = 2u64.pow(MERKLE_TREE_DEPTH as u32);
		assert_eq!(MAX_MERKLE_LEAVES, expected);
	}

	#[test]
	fn test_max_merkle_leaves_is_power_of_two() {
		// Verify it's a power of 2
		assert_eq!(MAX_MERKLE_LEAVES.count_ones(), 1);
	}

	// ===== Asset ID Tests =====

	#[test]
	fn test_native_asset_id() {
		assert_eq!(NATIVE_ASSET_ID, 0);
	}

	#[test]
	fn test_native_asset_id_is_zero() {
		assert_eq!(NATIVE_ASSET_ID, 0);
		// NATIVE_ASSET_ID is always 0
	}

	#[test]
	fn test_max_asset_id() {
		assert_eq!(MAX_ASSET_ID, u64::MAX);
	}

	#[test]
	fn test_max_asset_id_is_max() {
		assert_eq!(MAX_ASSET_ID, 18_446_744_073_709_551_615u64);
	}

	#[test]
	fn test_asset_id_range() {
		// Native asset is always within range (0 is minimum)
		assert_eq!(NATIVE_ASSET_ID, 0);
		assert_eq!(MAX_ASSET_ID, u64::MAX);
	}

	// ===== Note Value Tests =====

	#[test]
	fn test_min_note_value() {
		assert_eq!(MIN_NOTE_VALUE, 0);
	}

	#[test]
	fn test_min_note_value_is_zero() {
		assert_eq!(MIN_NOTE_VALUE, 0);
		// MIN_NOTE_VALUE is always 0
	}

	#[test]
	fn test_max_note_value() {
		assert_eq!(MAX_NOTE_VALUE, u64::MAX);
	}

	#[test]
	fn test_max_note_value_is_max() {
		assert_eq!(MAX_NOTE_VALUE, 18_446_744_073_709_551_615u64);
	}

	#[test]
	fn test_note_value_range() {
		// MIN is 0, MAX is u64::MAX - always valid
		assert_eq!(MIN_NOTE_VALUE, 0);
		assert_eq!(MAX_NOTE_VALUE, u64::MAX);
	}

	// ===== Zero Field Tests =====

	#[test]
	fn test_zero_field() {
		assert_eq!(ZERO_FIELD, 0);
	}

	#[test]
	fn test_zero_field_is_zero() {
		assert_eq!(ZERO_FIELD, 0u64);
		// ZERO_FIELD is always 0
	}

	// ===== Cross-Constant Relationship Tests =====

	#[test]
	fn test_native_asset_and_zero_field() {
		// Both should be zero
		assert_eq!(NATIVE_ASSET_ID, ZERO_FIELD);
	}

	#[test]
	fn test_min_note_value_and_zero_field() {
		// Both should be zero
		assert_eq!(MIN_NOTE_VALUE, ZERO_FIELD);
	}

	#[test]
	fn test_max_values_consistency() {
		// All max values should be u64::MAX
		assert_eq!(MAX_ASSET_ID, MAX_NOTE_VALUE);
	}

	// ===== Practical Bounds Tests =====

	#[test]
	fn test_merkle_tree_can_hold_many_notes() {
		// 2^32 is over 4 billion notes - always true
		assert_eq!(MAX_MERKLE_LEAVES, 4_294_967_296);
	}

	#[test]
	fn test_asset_id_supports_many_assets() {
		// Can support trillions of assets - always true for u64::MAX
		assert_eq!(MAX_ASSET_ID, u64::MAX);
	}

	#[test]
	fn test_note_value_supports_large_amounts() {
		// Can represent very large token amounts - always true for u64::MAX
		assert_eq!(MAX_NOTE_VALUE, u64::MAX);
	}

	// ===== Type Consistency Tests =====

	#[test]
	fn test_merkle_tree_depth_type() {
		// Ensure depth is usize for array indexing
		let _depth: usize = MERKLE_TREE_DEPTH;
	}

	#[test]
	fn test_numeric_constants_type() {
		// Ensure all numeric constants are u64
		let _: u64 = MAX_MERKLE_LEAVES;
		let _: u64 = NATIVE_ASSET_ID;
		let _: u64 = MAX_ASSET_ID;
		let _: u64 = MIN_NOTE_VALUE;
		let _: u64 = MAX_NOTE_VALUE;
		let _: u64 = ZERO_FIELD;
	}

	// ===== Compilation Tests =====

	#[test]
	fn test_constants_are_const() {
		// Constants can be used in const contexts
		const _DEPTH: usize = MERKLE_TREE_DEPTH;
		const _LEAVES: u64 = MAX_MERKLE_LEAVES;
		const _NATIVE: u64 = NATIVE_ASSET_ID;
	}
}
