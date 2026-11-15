// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage migrations for `pallet-shielded-pool`.
//!
//! Only migrations that still have a chain to run on live here. Once every
//! deployment has passed a version, its code is removed — see the git history
//! for v1 to v3.

use crate::{
	pallet::{Assets, Config, Pallet},
	types::{AssetBackend, AssetMetadata},
};
use frame_support::{
	BoundedVec, migrations::VersionedMigration, pallet_prelude::*,
	traits::UncheckedOnRuntimeUpgrade, weights::Weight,
};
use frame_system::pallet_prelude::BlockNumberFor;

#[cfg(feature = "try-runtime")]
use sp_std::vec::Vec;

pub mod v4 {
	use super::*;

	/// `AssetMetadata` as v3 stored it: no backend.
	#[derive(Encode, Decode)]
	struct AssetMetadataV3<AccountId, BlockNumber> {
		id: u32,
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		is_verified: bool,
		contract_address: Option<[u8; 20]>,
		created_at: BlockNumber,
		creator: AccountId,
	}

	/// Gives every registered asset a backend (storage v3 -> v4). Every asset
	/// registered so far is `Native`: pallet-backed assets did not exist. Runs only
	/// from storage v3 ([`MigrateToV4`]); an entry that does not decode as v3 is
	/// logged before `translate` drops it.
	pub struct InnerMigrateToV4<T>(core::marker::PhantomData<T>);

	/// [`InnerMigrateToV4`], run only when the pallet's storage is at v3, then
	/// bumped to v4.
	pub type MigrateToV4<T> = VersionedMigration<
		3,
		4,
		InnerMigrateToV4<T>,
		Pallet<T>,
		<T as frame_system::Config>::DbWeight,
	>;

	impl<T: Config> UncheckedOnRuntimeUpgrade for InnerMigrateToV4<T> {
		fn on_runtime_upgrade() -> Weight {
			let keys = Assets::<T>::iter_keys().count() as u64;
			let mut migrated = 0u64;
			Assets::<T>::translate::<AssetMetadataV3<T::AccountId, BlockNumberFor<T>>, _>(
				|_, old| {
					migrated += 1;
					Some(AssetMetadata {
						id: old.id,
						name: old.name,
						symbol: old.symbol,
						decimals: old.decimals,
						is_verified: old.is_verified,
						contract_address: old.contract_address,
						created_at: old.created_at,
						creator: old.creator,
						backend: AssetBackend::Native,
					})
				},
			);
			if migrated < keys {
				log::error!(
					target: "runtime::shielded-pool",
					"v4: {} of {keys} assets did not decode as v3 and were dropped",
					keys - migrated
				);
			}
			T::DbWeight::get().reads_writes(2 * keys, migrated)
		}

		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
			let count = Assets::<T>::iter_keys().count() as u32;
			Ok(count.encode())
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
			let before = u32::decode(&mut state.as_slice())
				.map_err(|_| sp_runtime::TryRuntimeError::Other("bad pre-upgrade state"))?;
			let after = Assets::<T>::iter().count() as u32;
			frame_support::ensure!(
				before == after,
				sp_runtime::TryRuntimeError::Other("an asset failed to migrate")
			);
			Ok(())
		}
	}
}
