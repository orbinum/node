// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The genesis presets: which are offered, that each builds, and what differs
//! between them.

use crate::{
	genesis::{
		get_preset, preset_names, DEV_PRESET_ID, LOCAL_PRESET_ID, MAINNET_PRESET_ID,
		TESTNET_PRESET_ID,
	},
	test_utils::with_preset,
	Runtime, RuntimeGenesisConfig,
};
use frame_support::genesis_builder_helper;
use hex_literal::hex;
use sp_core::H160;
use sp_genesis_builder::PresetId;
use sp_io::TestExternalities;

/// The node loads presets by these ids; mainnet stays out until it is configured.
#[test]
fn the_listed_presets_are_dev_local_and_testnet() {
	let names: Vec<String> = preset_names()
		.into_iter()
		.map(|id| String::from_utf8(id.into()).unwrap())
		.collect();
	let mut expected = vec![
		"development",
		"orbinum_local_testnet_runtime_preset",
		"orbinum_testnet_runtime_preset",
	];
	if cfg!(feature = "runtime-benchmarks") {
		expected.push("benchmark");
	}
	assert_eq!(names, expected);
	assert_eq!(DEV_PRESET_ID, sp_genesis_builder::DEV_RUNTIME_PRESET);
	assert_eq!(MAINNET_PRESET_ID, "orbinum_mainnet_runtime_preset");
}

/// Each listed preset resolves the way the `GenesisBuilder` API serves it (a patch
/// over the default config) and builds; an unknown id and mainnet resolve to nothing.
#[test]
fn every_listed_preset_resolves_and_builds_and_mainnet_does_not() {
	let api_get = |id: &str| {
		genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(&Some(id.into()), get_preset)
	};
	for id in preset_names() {
		let id = String::from_utf8(id.into()).unwrap();
		let json = api_get(&id).unwrap_or_else(|| panic!("{id} resolves"));
		TestExternalities::default().execute_with(|| {
			crate::genesis::build_state(json).unwrap_or_else(|e| panic!("{id} builds: {e}"));
		});
	}
	assert!(api_get(MAINNET_PRESET_ID).is_none());
	assert!(get_preset(&PresetId::from(MAINNET_PRESET_ID)).is_none());
	assert!(api_get("orbinum_unknown_preset").is_none());
	// No id: the default config, which builds too.
	let default =
		genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(&None, get_preset).unwrap();
	TestExternalities::default().execute_with(|| {
		crate::genesis::build_state(default).expect("the default config builds");
	});
}

/// `build_state` refuses a state that already holds a genesis: on a live chain
/// (`state_call`) it would run genesis-only code, such as a caller-sized
/// `devAccounts` loop, with no bound. Nothing is written.
#[test]
fn build_state_refuses_a_built_genesis() {
	let mut config: serde_json::Value = serde_json::from_slice(
		&genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(&None, get_preset).unwrap(),
	)
	.unwrap();
	config["balances"]["devAccounts"] = serde_json::json!([
		100,
		1,
		"0x0000000000000000000000000000000000000000000000000000000000000001//{}"
	]);
	let config = serde_json::to_vec(&config).unwrap();
	with_preset(DEV_PRESET_ID, || {
		let accounts = frame_system::Account::<Runtime>::iter().count();
		assert!(crate::genesis::build_state(config.clone()).is_err());
		assert_eq!(frame_system::Account::<Runtime>::iter().count(), accounts);
	});
	TestExternalities::default().execute_with(|| {
		crate::genesis::build_state(config).expect("empty storage builds");
		assert!(frame_system::Account::<Runtime>::iter().count() >= 100);
	});
}

/// Only the development preset carries the EVM benchmark account.
#[test]
fn only_development_has_the_evm_benchmark_account() {
	let helper = H160(hex!("1000000000000000000000000000000000000001"));
	for (id, expected) in [
		(DEV_PRESET_ID, true),
		(LOCAL_PRESET_ID, true),
		(TESTNET_PRESET_ID, false),
		(MAINNET_PRESET_ID, false),
	] {
		with_preset(id, || {
			assert_eq!(
				pallet_evm::AccountCodes::<Runtime>::contains_key(helper),
				expected,
				"{id}"
			);
		});
	}
}

/// The benchmark preset: no minimum bonds, room for pools, no commission ceiling,
/// an issuance that fits `u64` (vote weight equals stake), and a one-planck
/// existential deposit.
#[cfg(feature = "runtime-benchmarks")]
#[test]
fn the_benchmark_preset_opens_what_upstream_benchmarks_need() {
	with_preset(crate::genesis::BENCHMARK_PRESET_ID, || {
		use pallet_staking_async as staking;
		assert_eq!(staking::MinNominatorBond::<crate::Runtime>::get(), 0);
		assert_eq!(staking::MinValidatorBond::<crate::Runtime>::get(), 0);
		assert_eq!(
			staking::MaxCommission::<crate::Runtime>::get(),
			sp_runtime::Perbill::one()
		);
		assert_eq!(
			pallet_nomination_pools::MaxPools::<crate::Runtime>::get(),
			Some(16)
		);
		assert_eq!(
			pallet_nomination_pools::MinCreateBond::<crate::Runtime>::get(),
			crate::primitives::constants::ORB / 1_000_000
		);
		assert!(crate::Balances::total_issuance() <= u64::MAX as u128);
		assert_eq!(crate::EXISTENTIAL_DEPOSIT, 1);
	});
}

/// Validators whose account is their Aura key's bytes, in `genesis`: that key
/// sits in the node's keystore, so whoever reads it could move the bond.
fn accounts_that_are_their_aura_key(genesis: &serde_json::Value) -> Vec<String> {
	genesis["session"]["keys"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|keys| keys[0] == keys[2]["aura"])
		.map(|keys| keys[0].to_string())
		.collect()
}

/// Mainnet's validators bond from accounts other than their Aura keys; the
/// testnet started with each account its Aura key.
#[test]
fn mainnet_validators_are_not_their_aura_keys() {
	assert!(accounts_that_are_their_aura_key(&crate::genesis::mainnet::mainnet()).is_empty());
	assert_eq!(
		accounts_that_are_their_aura_key(&crate::genesis::testnet::testnet()).len(),
		3
	);
}
