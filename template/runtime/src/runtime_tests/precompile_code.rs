//! Code at the precompile addresses, from genesis and from `PrecompileCode`.

use super::with_ext;
use crate::Runtime;
use sp_core::H160;
use sp_io::TestExternalities;

fn precompile_code(address: H160) -> Vec<u8> {
	pallet_evm::AccountCodes::<Runtime>::get(address)
}

#[test]
fn only_orbinum_precompiles_carry_code() {
	let with_code: Vec<u64> =
		crate::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
			.map(|a| a.to_low_u64_be())
			.collect();
	assert_eq!(with_code, vec![1024, 1025, 1026, 1027, 2049, 2050]);
}

#[test]
fn every_preset_stores_code_at_orbinum_precompiles() {
	use crate::genesis_config_preset as presets;
	for id in [
		presets::DEV_PRESET_ID,
		presets::LOCAL_PRESET_ID,
		presets::TESTNET_PRESET_ID,
		presets::MAINNET_PRESET_ID,
	] {
		let json = presets::get_preset(&id.into()).expect("preset exists");
		TestExternalities::default().execute_with(|| {
			frame_support::genesis_builder_helper::build_state::<crate::RuntimeGenesisConfig>(json)
				.expect("preset builds");
			for address in crate::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
			{
				assert_eq!(
					precompile_code(address),
					crate::precompiles::PRECOMPILE_CODE.to_vec(),
					"{id}: {address:?}"
				);
			}
			for n in 1..=5u64 {
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
		for address in crate::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
			.filter(|a| *a != custom)
		{
			assert_eq!(
				precompile_code(address),
				crate::precompiles::PRECOMPILE_CODE.to_vec()
			);
			assert!(pallet_evm::AccountCodesMetadata::<Runtime>::contains_key(
				address
			));
		}

		// A second run writes nothing.
		let weight = crate::migrations::PrecompileCode::on_runtime_upgrade();
		let reads_only = <Runtime as frame_system::Config>::DbWeight::get().reads(6);
		assert_eq!(weight, reads_only);
	});
}
