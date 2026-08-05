//! Genesis Configuration - Initial chain state setup

use crate::{
	pallet::{
		Assets, Config, HistoricPoseidonRoots, HistoricRootsHead, HistoricRootsQueue,
		HistoricRootsTail, MerkleTreeFrontier, NextAssetId, PoseidonRoot,
	},
	types::AssetMetadata,
	types::Hash,
};
use frame_support::traits::Get;
use sp_runtime::traits::AccountIdConversion;

/// Helper function to initialize genesis state
/// Called from the GenesisConfig in lib.rs
pub fn initialize_genesis<T: Config>(initial_root: Hash) {
	// Initialize Poseidon Merkle tree with genesis root
	PoseidonRoot::<T>::put(initial_root);

	// Initialize incremental frontier to all zeros (empty tree state).
	// Must be set before any insert_leaf call so the O(depth) algorithm
	// starts from the correct baseline.
	MerkleTreeFrontier::<T>::put([[0u8; 32]; 20]);

	// Seed the historic-root window with the genesis root, expiring one full
	// retention window from block zero like any other root.
	let expires_at = T::RootRetentionBlocks::get();
	HistoricPoseidonRoots::<T>::insert(initial_root, expires_at);
	HistoricRootsQueue::<T>::insert(0u64, (initial_root, expires_at));
	HistoricRootsHead::<T>::put(1u64);
	HistoricRootsTail::<T>::put(0u64);

	// Register native asset (asset_id = 0) at genesis
	let native_asset = AssetMetadata {
		id: 0,
		name: b"Orbinum Native Token"
			.to_vec()
			.try_into()
			.expect("native asset name fits the metadata bound"),
		symbol: b"ORB"
			.to_vec()
			.try_into()
			.expect("native asset symbol fits the metadata bound"),
		decimals: 18,
		is_verified: true,
		contract_address: None,
		created_at: 0u32.into(),
		creator: T::PalletId::get().into_account_truncating(),
	};
	Assets::<T>::insert(0, native_asset);
	NextAssetId::<T>::put(1);
}

#[cfg(test)]
mod tests {
	use crate::{
		mock::{Test, new_test_ext},
		pallet::{Assets, HistoricPoseidonRoots, NextAssetId, PoseidonRoot},
	};

	#[test]
	fn genesis_next_asset_id_is_one() {
		new_test_ext().execute_with(|| {
			assert_eq!(NextAssetId::<Test>::get(), 1);
		});
	}

	#[test]
	fn genesis_native_asset_registered_and_verified() {
		new_test_ext().execute_with(|| {
			let asset =
				Assets::<Test>::get(0).expect("Native asset (ORB) must exist after genesis");
			assert_eq!(asset.id, 0);
			assert!(asset.is_verified, "Native asset must be verified");
			assert_eq!(asset.symbol.as_slice(), b"ORB");
			assert_eq!(asset.decimals, 18);
			assert_eq!(asset.contract_address, None);
		});
	}

	#[test]
	fn genesis_root_added_to_historic_roots() {
		new_test_ext().execute_with(|| {
			let root = PoseidonRoot::<Test>::get();
			assert!(
				HistoricPoseidonRoots::<Test>::get(root).is_some(),
				"Genesis root must be in historic roots"
			);
		});
	}

	#[test]
	fn initialize_genesis_sets_custom_root() {
		new_test_ext().execute_with(|| {
			let custom_root = [0xABu8; 32];
			super::initialize_genesis::<Test>(custom_root);
			assert_eq!(PoseidonRoot::<Test>::get(), custom_root);
		});
	}

	#[test]
	fn initialize_genesis_registers_custom_root_in_historic() {
		new_test_ext().execute_with(|| {
			let custom_root = [0xCDu8; 32];
			super::initialize_genesis::<Test>(custom_root);
			assert!(
				HistoricPoseidonRoots::<Test>::get(custom_root).is_some(),
				"Custom root must be in historic roots"
			);
		});
	}

	#[test]
	fn initialize_genesis_resets_next_asset_id_to_one() {
		new_test_ext().execute_with(|| {
			super::initialize_genesis::<Test>([0xEFu8; 32]);
			// After re-initializing, NextAssetId should be 1 (native asset inserted at 0)
			assert_eq!(NextAssetId::<Test>::get(), 1);
		});
	}
}
