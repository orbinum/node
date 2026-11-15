// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
	pallet::{Config, Error, Event, Pallet},
	storage::AssetRepository,
	types::{AssetBackend, AssetMetadata, NATIVE_ASSET_ID},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::AccountIdConversion;

pub struct AssetOperation;

impl AssetOperation {
	pub fn register<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
	) -> Result<u32, DispatchError> {
		let creator = T::PalletId::get().into_account_truncating();
		Self::register_asset::<T>(name, symbol, decimals, contract_address, creator)
	}

	pub fn register_asset<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
		creator: T::AccountId,
	) -> Result<u32, DispatchError> {
		Self::validate_metadata::<T>(&name, &symbol, decimals)?;

		let asset_id = AssetRepository::increment_asset_id::<T>();

		ensure!(
			!AssetRepository::exists::<T>(asset_id),
			Error::<T>::AssetIdAlreadyExists
		);
		let current_block = frame_system::Pallet::<T>::block_number();

		let metadata = AssetMetadata {
			id: asset_id,
			name,
			symbol,
			decimals,
			is_verified: false,
			contract_address,
			created_at: current_block,
			creator,
			backend: AssetBackend::Native,
		};

		AssetRepository::store_asset::<T>(asset_id, metadata);
		Pallet::<T>::deposit_event(Event::AssetRegistered { asset_id });
		Ok(asset_id)
	}

	/// Registers an asset its pallet issues and redeems through bound spends and
	/// `mint_note`. It is usable at once (verified) and governance can never
	/// unverify it: its holders' way out must not be frozen.
	pub fn register_pallet_asset<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		pallet_id: frame_support::PalletId,
	) -> Result<u32, DispatchError> {
		Self::validate_metadata::<T>(&name, &symbol, decimals)?;
		let asset_id = AssetRepository::increment_asset_id::<T>();
		ensure!(
			!AssetRepository::exists::<T>(asset_id),
			Error::<T>::AssetIdAlreadyExists
		);
		AssetRepository::store_asset::<T>(
			asset_id,
			AssetMetadata {
				id: asset_id,
				name,
				symbol,
				decimals,
				is_verified: true,
				contract_address: None,
				created_at: frame_system::Pallet::<T>::block_number(),
				// Not the pallet's own account: its sub-accounts may be in use.
				creator: pallet_id.into_sub_account_truncating(*b"asset"),
				backend: AssetBackend::Pallet(pallet_id.0),
			},
		);
		Pallet::<T>::deposit_event(Event::AssetRegistered { asset_id });
		Ok(asset_id)
	}

	pub fn verify<T: Config>(asset_id: u32) -> DispatchResult {
		Self::verify_asset::<T>(asset_id)
	}

	pub fn verify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		Self::ensure_governed::<T>(asset_id)?;
		ensure!(
			AssetRepository::set_verified::<T>(asset_id, true),
			Error::<T>::InvalidAssetId
		);
		Pallet::<T>::deposit_event(Event::AssetVerified { asset_id });
		Ok(())
	}

	pub fn unverify<T: Config>(asset_id: u32) -> DispatchResult {
		Self::unverify_asset::<T>(asset_id)
	}

	pub fn unverify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		Self::ensure_governed::<T>(asset_id)?;
		ensure!(
			AssetRepository::set_verified::<T>(asset_id, false),
			Error::<T>::InvalidAssetId
		);
		Pallet::<T>::deposit_event(Event::AssetUnverified { asset_id });
		Ok(())
	}

	pub fn get_asset_metadata<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		AssetRepository::get_asset::<T>(asset_id)
	}

	pub fn ensure_asset_verified<T: Config>(asset_id: u32) -> DispatchResult {
		let metadata =
			AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(metadata.is_verified, Error::<T>::AssetNotVerified);
		Ok(())
	}

	/// The asset a pool operation may move: registered, verified, and backed.
	/// Every transfer into or out of the pool moves `T::Currency`, so a note of
	/// any other asset would be backed by native funds; such ids are refused
	/// until they have their own backend.
	pub fn ensure_movable<T: Config>(asset_id: u32) -> Result<(), Error<T>> {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);
		ensure!(asset_id == NATIVE_ASSET_ID, Error::<T>::AssetNotSupported);
		Ok(())
	}

	/// The asset a spend may move inside the pool: a bound spend's input or a
	/// private transfer's notes. The native asset must be verified, as for every
	/// native move; a pallet-backed asset always moves, since its pallet, not
	/// governance, answers for it.
	pub fn ensure_spendable<T: Config>(asset_id: u32) -> Result<AssetBackend, Error<T>> {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		match asset.backend {
			AssetBackend::Pallet(_) => Ok(asset.backend),
			AssetBackend::Native => {
				ensure!(asset.is_verified, Error::<T>::AssetNotVerified);
				ensure!(asset_id == NATIVE_ASSET_ID, Error::<T>::AssetNotSupported);
				Ok(asset.backend)
			}
		}
	}

	/// An asset governance may verify or unverify: registered and not pallet-backed.
	fn ensure_governed<T: Config>(asset_id: u32) -> DispatchResult {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(
			asset.backend == AssetBackend::Native,
			Error::<T>::AssetManagedByPallet
		);
		Ok(())
	}

	pub fn get_next_asset_id<T: Config>() -> u32 {
		AssetRepository::get_next_asset_id::<T>()
	}

	pub fn validate_metadata<T: Config>(
		name: &BoundedVec<u8, ConstU32<64>>,
		symbol: &BoundedVec<u8, ConstU32<16>>,
		_decimals: u8,
	) -> DispatchResult {
		ensure!(!name.is_empty(), Error::<T>::InvalidAmount);
		ensure!(name.len() <= 64, Error::<T>::InvalidAmount);
		ensure!(
			!symbol.is_empty() && symbol.len() <= 16,
			Error::<T>::InvalidAmount
		);
		Ok(())
	}
}
