//! PoolStatsResponse DTO - Pool statistics response

use serde::{Deserialize, Serialize};

/// Response DTO for pool statistics.
///
/// Maps from `domain::PoolStatistics` into JSON-friendly fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatsResponse {
	/// Merkle tree root (hex string).
	pub merkle_root: String,
	/// Number of commitments in the tree.
	pub commitment_count: u32,
	/// Total pool balance (in minimum units).
	pub total_balance: u128,
	/// Tree depth.
	pub tree_depth: u32,
}

impl PoolStatsResponse {
	/// Creates a new `PoolStatsResponse`.
	pub fn new(
		merkle_root: String,
		commitment_count: u32,
		total_balance: u128,
		tree_depth: u32,
	) -> Self {
		Self {
			merkle_root,
			commitment_count,
			total_balance,
			tree_depth,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_pool_stats_response() {
		let response = PoolStatsResponse::new("0x1234".to_string(), 42, 1_000_000u128, 32);

		assert_eq!(response.merkle_root, "0x1234");
		assert_eq!(response.commitment_count, 42);
		assert_eq!(response.total_balance, 1_000_000u128);
		assert_eq!(response.tree_depth, 32);
	}

	#[test]
	fn should_support_expected_traits() {
		fn assert_serialize<T: Serialize>() {}
		fn assert_deserialize<T: for<'de> Deserialize<'de>>() {}
		fn assert_clone<T: Clone>() {}
		fn assert_debug<T: core::fmt::Debug>() {}
		fn assert_eq_trait<T: Eq>() {}

		assert_serialize::<PoolStatsResponse>();
		assert_deserialize::<PoolStatsResponse>();
		assert_clone::<PoolStatsResponse>();
		assert_debug::<PoolStatsResponse>();
		assert_eq_trait::<PoolStatsResponse>();
	}
}
