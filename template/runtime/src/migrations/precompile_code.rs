// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Code at the Orbinum precompile addresses, for a chain created before genesis
//! set it.

use super::db_weight;
use crate::Runtime;
use frame_support::{
	traits::{OnRuntimeUpgrade, StorageVersion},
	weights::Weight,
};

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// Stores [`PRECOMPILE_CODE`](crate::evm::precompiles::PRECOMPILE_CODE) at every
/// precompile that should carry it and has none, as genesis does for a new
/// chain. Runs once per chain and [`CURRENT_VERSION`]; an address that already holds
/// code is left alone.
pub struct PrecompileCode;

/// Bump it whenever `addresses_with_code` changes, so live chains get code at the new
/// addresses too.
pub const CURRENT_VERSION: StorageVersion = StorageVersion::new(1);

/// Runtime-level storage version of this migration: [`CURRENT_VERSION`] once it has run.
#[frame_support::storage_alias]
pub type Version =
	StorageValue<OrbinumMigrations, StorageVersion, frame_support::storage::types::ValueQuery>;

impl OnRuntimeUpgrade for PrecompileCode {
	fn on_runtime_upgrade() -> Weight {
		if Version::get() >= CURRENT_VERSION {
			return db_weight(1, 0);
		}
		Version::put(CURRENT_VERSION);
		let mut reads = 1u64;
		let mut written = 0u64;
		for address in
			crate::evm::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
		{
			reads += 1;
			if pallet_evm::AccountCodes::<Runtime>::contains_key(address) {
				continue;
			}
			// Only an inner-create origin check can fail, and none is passed.
			let _ = pallet_evm::Pallet::<Runtime>::create_account(
				address,
				crate::evm::precompiles::PRECOMPILE_CODE.to_vec(),
				None,
			);
			written += 1;
		}
		log::info!(target: "runtime::migrations", "stored code at {written} precompile address(es)");
		// Per write: the account's providers read and write, the code and its metadata;
		// and the version.
		db_weight(
			reads.saturating_add(written),
			written.saturating_mul(3).saturating_add(1),
		)
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		frame_support::ensure!(
			Version::get() == CURRENT_VERSION,
			"the migration did not record its run"
		);
		frame_support::ensure!(
			crate::evm::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
				.all(|a| !pallet_evm::AccountCodes::<Runtime>::get(a).is_empty()),
			"a precompile address has no code"
		);
		Ok(())
	}
}
