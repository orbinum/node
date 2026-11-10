//! `Pallet<T>` helper methods — thin delegations to the underlying modules.
//!
//! Separating these from `lib.rs` keeps the FRAME interface file focused on
//! storage, events, errors, and extrinsic signatures. All non-trivial logic
//! lives in the modules being delegated to.

use crate::{
	Pallet,
	merkle::MerkleTreeService,
	pallet::Config,
	types::{Commitment, DefaultMerklePath, Hash},
};
use frame_support::{pallet_prelude::DispatchError, traits::Get};
use sp_runtime::traits::AccountIdConversion;

impl<T: Config> Pallet<T> {
	/// Pool account ID derived from the pallet's `PalletId` constant.
	pub fn pool_account_id() -> T::AccountId {
		T::PalletId::get().into_account_truncating()
	}

	// ── Merkle tree ──────────────────────────────────────────────────────────

	/// Insert a new leaf into the Merkle tree.
	pub fn insert_leaf(commitment: Commitment) -> Result<u32, DispatchError> {
		MerkleTreeService::insert_leaf::<T>(commitment)
	}

	/// Merkle path for a leaf at `leaf_index` (used by wallets to build proofs).
	pub fn get_merkle_path(leaf_index: u32) -> Option<DefaultMerklePath> {
		MerkleTreeService::get_merkle_path::<T>(leaf_index)
	}

	/// Verify a Merkle membership proof.
	pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
		MerkleTreeService::verify_merkle_proof(root, leaf, path)
	}

	/// Leaf index of a commitment, from the `CommitmentToLeafIndex` reverse index.
	pub fn get_leaf_index(commitment: &Commitment) -> Option<u32> {
		MerkleTreeService::find_leaf_index::<T>(commitment)
	}
}
