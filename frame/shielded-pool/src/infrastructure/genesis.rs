//! Genesis Configuration - Initial chain state setup

use crate::{
	domain::entities::AssetMetadata,
	domain::value_objects::Hash,
	pallet::{
		Assets, Config, HistoricPoseidonRoots, HistoricRootsOrder, NextAssetId, PoseidonRoot,
	},
};
use frame_support::{pallet_prelude::*, traits::Get};
use sp_runtime::traits::AccountIdConversion;

/// Helper function to initialize genesis state
/// Called from the GenesisConfig in lib.rs
pub fn initialize_genesis<T: Config>(initial_root: Hash) {
	// Initialize Poseidon Merkle tree with genesis root
	PoseidonRoot::<T>::put(initial_root);

	// Add genesis root to historic roots
	HistoricPoseidonRoots::<T>::insert(initial_root, true);

	// Initialize the order list with the genesis root
	let mut order = BoundedVec::new();
	let _ = order.try_push(initial_root);
	HistoricRootsOrder::<T>::put(order);

	// Register native asset (asset_id = 0) at genesis
	let native_asset = AssetMetadata {
		id: 0,
		name: b"Orbinum Native Token"
			.to_vec()
			.try_into()
			.unwrap_or_default(),
		symbol: b"ORB".to_vec().try_into().unwrap_or_default(),
		decimals: 18,
		is_verified: true, // Native token is pre-verified
		contract_address: None,
		created_at: 0u32.into(),
		creator: T::PalletId::get().into_account_truncating(),
	};
	Assets::<T>::insert(0, native_asset);
	NextAssetId::<T>::put(1); // Next asset ID starts at 1
}
