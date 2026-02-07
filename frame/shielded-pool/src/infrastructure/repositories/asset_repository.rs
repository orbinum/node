//! Asset Repository - Encapsulates asset registry storage access

use crate::{
	domain::entities::AssetMetadata,
	pallet::{Assets, Config, NextAssetId},
};
use frame_system::pallet_prelude::BlockNumberFor;

/// Repository for asset registry operations
pub struct AssetRepository;

impl AssetRepository {
	/// Get asset metadata
	pub fn get_asset<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		Assets::<T>::get(asset_id)
	}

	/// Store asset metadata
	pub fn store_asset<T: Config>(
		asset_id: u32,
		metadata: AssetMetadata<T::AccountId, BlockNumberFor<T>>,
	) {
		Assets::<T>::insert(asset_id, metadata);
	}

	/// Check if asset exists
	pub fn exists<T: Config>(asset_id: u32) -> bool {
		Assets::<T>::contains_key(asset_id)
	}

	/// Get next available asset ID
	pub fn get_next_asset_id<T: Config>() -> u32 {
		NextAssetId::<T>::get()
	}

	/// Increment and return next asset ID
	pub fn increment_asset_id<T: Config>() -> u32 {
		let current = Self::get_next_asset_id::<T>();
		NextAssetId::<T>::put(current.saturating_add(1));
		current
	}

	/// Update asset verification status
	pub fn set_verified<T: Config>(asset_id: u32, is_verified: bool) -> bool {
		Assets::<T>::mutate(asset_id, |maybe_asset| {
			if let Some(asset) = maybe_asset {
				asset.is_verified = is_verified;
				true
			} else {
				false
			}
		})
	}
}
