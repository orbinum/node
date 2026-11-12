// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Genesis state: the initial root, the historic-root window and the native
//! asset.

use crate::{
	pallet::{
		Assets, Config, HistoricPoseidonRoots, HistoricRootsHead, HistoricRootsQueue,
		HistoricRootsTail, MerkleTreeFrontier, NextAssetId, PoseidonRoot,
	},
	types::{AssetMetadata, Hash, NATIVE_ASSET_ID},
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

	// Register the native asset at genesis
	let native_asset = AssetMetadata {
		id: NATIVE_ASSET_ID,
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
	Assets::<T>::insert(NATIVE_ASSET_ID, native_asset);
	NextAssetId::<T>::put(NATIVE_ASSET_ID + 1);
}
