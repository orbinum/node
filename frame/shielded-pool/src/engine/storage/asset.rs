//! Asset registry storage.
//!
//! Asset metadata plus the monotonic id counter. `increment_asset_id` hands out
//! the next id; the caller is responsible for rejecting a collision, since the
//! counter alone cannot tell a fresh slot from a reused one.

use crate::{
	pallet::{Assets, Config, NextAssetId},
	types::AssetMetadata,
};
use frame_system::pallet_prelude::BlockNumberFor;

// AssetRepository

pub struct AssetRepository;

impl AssetRepository {
	pub fn get_asset<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		Assets::<T>::get(asset_id)
	}
	pub fn store_asset<T: Config>(
		asset_id: u32,
		metadata: AssetMetadata<T::AccountId, BlockNumberFor<T>>,
	) {
		Assets::<T>::insert(asset_id, metadata);
	}
	pub fn exists<T: Config>(asset_id: u32) -> bool {
		Assets::<T>::contains_key(asset_id)
	}
	pub fn get_next_asset_id<T: Config>() -> u32 {
		NextAssetId::<T>::get()
	}
	pub fn increment_asset_id<T: Config>() -> u32 {
		let current = Self::get_next_asset_id::<T>();
		NextAssetId::<T>::put(current.saturating_add(1));
		current
	}
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
