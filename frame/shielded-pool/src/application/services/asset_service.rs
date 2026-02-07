//! Asset service - Handles asset registration and verification

use crate::{
	domain::entities::AssetMetadata,
	pallet::{Assets, Config, Error, Event, NextAssetId, Pallet},
};
use frame_support::{BoundedVec, pallet_prelude::*};
use sp_runtime::traits::AccountIdConversion;

pub struct AssetService;

impl AssetService {
	/// Register a new asset
	pub fn register<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
	) -> Result<u32, DispatchError> {
		// Get next asset ID
		let asset_id = NextAssetId::<T>::mutate(|id| {
			let current_id = *id;
			*id += 1;
			current_id
		});

		let current_block = frame_system::Pallet::<T>::block_number();
		let creator = T::PalletId::get().into_account_truncating();

		let metadata = AssetMetadata {
			id: asset_id,
			name,
			symbol,
			decimals,
			is_verified: false,
			contract_address,
			created_at: current_block,
			creator,
		};

		Assets::<T>::insert(asset_id, metadata);

		Pallet::<T>::deposit_event(Event::AssetRegistered { asset_id });

		Ok(asset_id)
	}

	/// Verify an asset for use
	pub fn verify<T: Config>(asset_id: u32) -> DispatchResult {
		Assets::<T>::try_mutate(asset_id, |maybe_asset| -> DispatchResult {
			let asset = maybe_asset.as_mut().ok_or(Error::<T>::InvalidAssetId)?;
			asset.is_verified = true;
			Ok(())
		})?;

		Pallet::<T>::deposit_event(Event::AssetVerified { asset_id });

		Ok(())
	}

	/// Unverify an asset
	pub fn unverify<T: Config>(asset_id: u32) -> DispatchResult {
		Assets::<T>::try_mutate(asset_id, |maybe_asset| -> DispatchResult {
			let asset = maybe_asset.as_mut().ok_or(Error::<T>::InvalidAssetId)?;
			asset.is_verified = false;
			Ok(())
		})?;

		Pallet::<T>::deposit_event(Event::AssetUnverified { asset_id });

		Ok(())
	}
}
