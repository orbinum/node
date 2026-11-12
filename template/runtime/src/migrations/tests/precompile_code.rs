// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Code at the precompile addresses, from genesis and from `PrecompileCode`.

use crate::{
	evm::precompiles::{FrontierPrecompiles, PRECOMPILE_CODE},
	genesis::{DEV_PRESET_ID, LOCAL_PRESET_ID, MAINNET_PRESET_ID, TESTNET_PRESET_ID},
	test_utils::{with_ext, with_preset},
	Runtime,
};
use sp_core::H160;

fn precompile_code(address: H160) -> Vec<u8> {
	pallet_evm::AccountCodes::<Runtime>::get(address)
}

#[test]
fn only_orbinum_precompiles_carry_code() {
	let with_code: Vec<u64> = FrontierPrecompiles::<Runtime>::addresses_with_code()
		.map(|a| a.to_low_u64_be())
		.collect();
	assert_eq!(with_code, vec![1024, 1025, 1026, 1027, 2049, 2050]);
}

/// The addresses with code as of each `PrecompileCode` version, oldest first. A new set
/// goes in a new entry with the bumped version: the migration has already run on live
/// chains at the old one and would skip the new addresses.
const PINNED_ADDRESSES_WITH_CODE: &[(u16, &[u64])] = &[(1, &[1024, 1025, 1026, 1027, 2049, 2050])];

#[test]
fn addresses_with_code_set_is_pinned_to_migration_version() {
	assert!(PINNED_ADDRESSES_WITH_CODE
		.windows(2)
		.all(|w| w[0].0 < w[1].0 && w[0].1 != w[1].1));
	let (version, pinned) = PINNED_ADDRESSES_WITH_CODE.last().unwrap();
	assert_eq!(
		crate::migrations::precompile_code::CURRENT_VERSION,
		*version,
		"pin the set for the new version"
	);
	let with_code: Vec<u64> = FrontierPrecompiles::<Runtime>::addresses_with_code()
		.map(|a| a.to_low_u64_be())
		.collect();
	assert_eq!(
		with_code,
		pinned.to_vec(),
		"the precompiles with code changed: bump `PrecompileCode`'s version and pin the new set"
	);
}

#[test]
fn every_preset_stores_code_at_orbinum_precompiles() {
	for id in [
		DEV_PRESET_ID,
		LOCAL_PRESET_ID,
		TESTNET_PRESET_ID,
		MAINNET_PRESET_ID,
	] {
		with_preset(id, || {
			for address in FrontierPrecompiles::<Runtime>::addresses_with_code() {
				assert_eq!(
					precompile_code(address),
					PRECOMPILE_CODE.to_vec(),
					"{id}: {address:?}"
				);
			}
			for n in 1..=9u64 {
				assert!(
					precompile_code(H160::from_low_u64_be(n)).is_empty(),
					"{id}: {n}"
				);
			}
		});
	}
}

#[test]
fn precompile_code_migration_fills_missing_code_once() {
	use frame_support::traits::OnRuntimeUpgrade;
	with_ext(|| {
		let custom = H160::from_low_u64_be(2049);
		pallet_evm::AccountCodes::<Runtime>::insert(custom, vec![0xfe]);

		crate::migrations::PrecompileCode::on_runtime_upgrade();

		assert_eq!(precompile_code(custom), vec![0xfe], "existing code is kept");
		for address in
			FrontierPrecompiles::<Runtime>::addresses_with_code().filter(|a| *a != custom)
		{
			assert_eq!(precompile_code(address), PRECOMPILE_CODE.to_vec());
			assert!(pallet_evm::AccountCodesMetadata::<Runtime>::contains_key(
				address
			));
		}

		// It runs once: a second run reads its version and stops, even with code
		// missing again.
		pallet_evm::AccountCodes::<Runtime>::remove(H160::from_low_u64_be(2050));
		let weight = crate::migrations::PrecompileCode::on_runtime_upgrade();
		let reads_only = <Runtime as frame_system::Config>::DbWeight::get().reads(1);
		assert_eq!(weight, reads_only);
		assert!(precompile_code(H160::from_low_u64_be(2050)).is_empty());
	});
}
