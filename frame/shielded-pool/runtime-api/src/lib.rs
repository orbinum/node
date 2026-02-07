#![cfg_attr(not(feature = "std"), no_std)]

use pallet_shielded_pool::{DefaultMerklePath, Hash};

sp_api::decl_runtime_apis! {
	pub trait ShieldedPoolRuntimeApi {
		/// Get the Merkle tree information (root, size, depth)
		fn get_merkle_tree_info() -> (Hash, u32, u32);

		/// Get the Merkle proof for a given leaf index
		fn get_merkle_proof(leaf_index: u32) -> Option<DefaultMerklePath>;

		/// Get the Merkle proof for a given commitment
		/// (This requires scanning the leaves in the runtime, which is expensive but convenient)
		fn get_merkle_proof_for_commitment(commitment: Hash) -> Option<(u32, DefaultMerklePath)>;
	}
}
