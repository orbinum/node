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

	/// Find the leaf index for a commitment (linear scan — expensive, only for RPC).
	pub fn get_leaf_index(commitment: &Commitment) -> Option<u32> {
		MerkleTreeService::find_leaf_index::<T>(commitment)
	}
}

#[cfg(test)]
mod tests {
	use crate::{
		mock::{Test, new_test_ext},
		storage::MerkleRepository,
		types::Commitment,
	};
	use frame_support::assert_ok;

	#[test]
	fn pool_account_id_is_non_zero() {
		new_test_ext().execute_with(|| {
			let pool = crate::Pallet::<Test>::pool_account_id();
			assert_ne!(pool, 0u64);
		});
	}

	#[test]
	fn pool_account_id_is_deterministic() {
		new_test_ext().execute_with(|| {
			let a = crate::Pallet::<Test>::pool_account_id();
			let b = crate::Pallet::<Test>::pool_account_id();
			assert_eq!(a, b);
		});
	}

	#[test]
	fn insert_leaf_succeeds_and_returns_zero() {
		new_test_ext().execute_with(|| {
			let c = Commitment::new([0x01u8; 32]);
			let idx = crate::Pallet::<Test>::insert_leaf(c).unwrap();
			assert_eq!(idx, 0);
		});
	}

	#[test]
	fn insert_leaf_sequential_indices() {
		new_test_ext().execute_with(|| {
			assert_ok!(crate::Pallet::<Test>::insert_leaf(Commitment::new(
				[0x01u8; 32]
			)));
			let idx = crate::Pallet::<Test>::insert_leaf(Commitment::new([0x02u8; 32])).unwrap();
			assert_eq!(idx, 1);
		});
	}

	#[test]
	fn get_merkle_path_none_for_empty_tree() {
		new_test_ext().execute_with(|| {
			assert!(crate::Pallet::<Test>::get_merkle_path(0).is_none());
		});
	}

	#[test]
	fn get_merkle_path_some_after_insert() {
		new_test_ext().execute_with(|| {
			crate::Pallet::<Test>::insert_leaf(Commitment::new([0x02u8; 32])).unwrap();
			assert!(crate::Pallet::<Test>::get_merkle_path(0).is_some());
		});
	}

	#[test]
	fn get_merkle_path_none_out_of_bounds() {
		new_test_ext().execute_with(|| {
			crate::Pallet::<Test>::insert_leaf(Commitment::new([0x03u8; 32])).unwrap();
			assert!(crate::Pallet::<Test>::get_merkle_path(99).is_none());
		});
	}

	#[test]
	fn verify_merkle_proof_valid_after_insert() {
		new_test_ext().execute_with(|| {
			let leaf = [0x10u8; 32];
			crate::Pallet::<Test>::insert_leaf(Commitment::new(leaf)).unwrap();
			let root = MerkleRepository::get_poseidon_root::<Test>();
			let path = crate::Pallet::<Test>::get_merkle_path(0).unwrap();
			assert!(crate::Pallet::<Test>::verify_merkle_proof(
				&root, &leaf, &path
			));
		});
	}

	#[test]
	fn verify_merkle_proof_fails_for_wrong_root() {
		new_test_ext().execute_with(|| {
			let leaf = [0x11u8; 32];
			crate::Pallet::<Test>::insert_leaf(Commitment::new(leaf)).unwrap();
			let path = crate::Pallet::<Test>::get_merkle_path(0).unwrap();
			assert!(!crate::Pallet::<Test>::verify_merkle_proof(
				&[0xFFu8; 32],
				&leaf,
				&path
			));
		});
	}

	#[test]
	fn get_leaf_index_none_for_unknown_commitment() {
		new_test_ext().execute_with(|| {
			assert!(
				crate::Pallet::<Test>::get_leaf_index(&Commitment::new([0xFFu8; 32])).is_none()
			);
		});
	}

	#[test]
	fn get_leaf_index_returns_correct_index_after_insert() {
		new_test_ext().execute_with(|| {
			let c = Commitment::new([0x20u8; 32]);
			crate::Pallet::<Test>::insert_leaf(c).unwrap();
			assert_eq!(crate::Pallet::<Test>::get_leaf_index(&c), Some(0));
		});
	}

	#[test]
	fn get_leaf_index_returns_correct_index_for_second_leaf() {
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0x30u8; 32]);
			let c1 = Commitment::new([0x31u8; 32]);
			crate::Pallet::<Test>::insert_leaf(c0).unwrap();
			crate::Pallet::<Test>::insert_leaf(c1).unwrap();
			assert_eq!(crate::Pallet::<Test>::get_leaf_index(&c1), Some(1));
		});
	}
}
