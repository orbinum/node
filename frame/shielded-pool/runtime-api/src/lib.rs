#![cfg_attr(not(feature = "std"), no_std)]

use pallet_shielded_pool::{DefaultMerklePath, Hash};

/// Configuration exposed by the runtime for the node-native EVM relay.
///
/// Returned by `ShieldedPoolRuntimeApi::relay_config()`. The relay reads this on every
/// call instead of using hardcoded constants — when the runtime performs a forkless
/// upgrade that changes `MinGaslessFee` or `RELAY_GAS_LIMIT`, the running node picks
/// up the new values automatically without recompilation.
#[derive(
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug,
	Clone,
	PartialEq
)]
pub struct RelayConfig {
	/// Minimum fee (in native token planck / wei) that must be embedded in the calldata.
	/// Corresponds to `T::MinGaslessFee::get()` in the runtime.
	pub min_fee_planck: u128,
	/// ABI selectors of operations the runtime currently accepts via unsigned dispatch.
	/// The relay uses this to validate the calldata selector whitelist.
	pub allowed_selectors: sp_std::vec::Vec<[u8; 4]>,
}

sp_api::decl_runtime_apis! {
	#[api_version(2)]
	pub trait ShieldedPoolRuntimeApi {
		/// Get the Merkle tree information (root, size, depth)
		fn get_merkle_tree_info() -> (Hash, u32, u32);

		/// Get the Merkle proof for a given leaf index
		fn get_merkle_proof(leaf_index: u32) -> Option<DefaultMerklePath>;

		/// Get the Merkle proof for a given commitment.
		/// O(1) index lookup plus O(depth) sibling reads from stored nodes.
		fn get_merkle_proof_for_commitment(commitment: Hash) -> Option<(u32, DefaultMerklePath)>;

		/// Forest summary: (active_root, global_size, depth, current_tree_id,
		/// sealed_tree_count).
		fn get_forest_info() -> (Hash, u32, u32, u32, u32);

		/// Root the given leaf's tree anchors to, plus its tree_id: the
		/// permanent sealed root for completed trees, the live PoseidonRoot
		/// for the active tree. None if the leaf does not exist.
		fn get_root_for_leaf(leaf_index: u32) -> Option<(Hash, u32)>;

		/// Return relay configuration sourced from the runtime.
		///
		/// Called by the node-native EVM relay on every `relay_shielded_call` to obtain
		/// the current `MinGaslessFee` and the set of accepted selectors. This ensures
		/// that forkless runtime upgrades are reflected immediately without restarting
		/// or recompiling the node.
		fn relay_config() -> RelayConfig;
	}
}
