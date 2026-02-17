//! MerkleProofResponse DTO - Merkle proof response for RPC

use serde::{Deserialize, Serialize};

/// Response DTO for Merkle proofs.
///
/// This DTO is serialized to JSON for RPC responses.
/// It maps from `domain::MerkleProofPath`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofResponse {
	/// Sibling hash path (hex strings).
	pub path: Vec<String>,
	/// Leaf index.
	pub leaf_index: u32,
	/// Tree depth.
	pub tree_depth: u32,
}

impl MerkleProofResponse {
	/// Creates a new `MerkleProofResponse`.
	pub fn new(path: Vec<String>, leaf_index: u32, tree_depth: u32) -> Self {
		Self {
			path,
			leaf_index,
			tree_depth,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_merkle_proof_response() {
		let response =
			MerkleProofResponse::new(vec!["0xaaaa".to_string(), "0xbbbb".to_string()], 7, 20);

		assert_eq!(response.path, vec!["0xaaaa", "0xbbbb"]);
		assert_eq!(response.leaf_index, 7);
		assert_eq!(response.tree_depth, 20);
	}

	#[test]
	fn should_support_expected_traits() {
		fn assert_serialize<T: Serialize>() {}
		fn assert_deserialize<T: for<'de> Deserialize<'de>>() {}
		fn assert_clone<T: Clone>() {}
		fn assert_debug<T: core::fmt::Debug>() {}
		fn assert_eq_trait<T: Eq>() {}

		assert_serialize::<MerkleProofResponse>();
		assert_deserialize::<MerkleProofResponse>();
		assert_clone::<MerkleProofResponse>();
		assert_debug::<MerkleProofResponse>();
		assert_eq_trait::<MerkleProofResponse>();
	}
}
