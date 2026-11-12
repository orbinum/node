// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Every spec the node ships builds its genesis storage.

use sc_chain_spec::ChainSpec as _;
use sp_runtime::BuildStorage;

use super::*;

fn patch(spec: &ChainSpec) -> serde_json::Value {
	let json = spec.as_json(false).expect("spec serialises");
	let spec: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
	spec["genesis"]["runtimeGenesis"]["patch"].clone()
}

#[test]
fn dev_builds_its_genesis() {
	for manual_seal in [false, true] {
		development_config(manual_seal)
			.unwrap()
			.build_storage()
			.unwrap();
	}
}

#[test]
fn local_builds_its_genesis() {
	local_testnet_config().unwrap().build_storage().unwrap();
}

#[test]
fn testnet_builds_its_genesis() {
	orbinum_testnet_config().unwrap().build_storage().unwrap();
}

#[test]
fn dev_spec_has_alice_as_its_only_validator() {
	let spec = development_config(false).unwrap();
	assert_eq!(spec.chain_type(), ChainType::Development);
	let patch = patch(&spec);
	assert_eq!(patch["session"]["keys"].as_array().unwrap().len(), 1);
	assert_eq!(patch["staking"]["validatorCount"], 1);
	assert_eq!(patch["manualSeal"]["enable"], false);
}

#[test]
fn local_spec_has_three_validators() {
	let spec = local_testnet_config().unwrap();
	assert_eq!(spec.chain_type(), ChainType::Local);
	let patch = patch(&spec);
	assert_eq!(patch["session"]["keys"].as_array().unwrap().len(), 3);
	assert_eq!(
		patch["validatorSet"]["initialValidators"]
			.as_array()
			.unwrap()
			.len(),
		3
	);
	assert_eq!(patch["staking"]["stakers"].as_array().unwrap().len(), 3);
	assert_eq!(patch["staking"]["validatorCount"], 3);
	assert_eq!(patch["manualSeal"]["enable"], false);
}

#[test]
fn validator_accounts_are_their_aura_keys() {
	let patch = validators_patch(&["Alice"]);
	let alice = aura_to_account(&from_seed::<AuraId>("Alice"));
	assert_eq!(
		patch["validatorSet"]["initialValidators"][0],
		serde_json::json!(alice)
	);
	assert_eq!(patch["session"]["keys"][0][0], serde_json::json!(alice));
	assert_eq!(patch["session"]["keys"][0][1], serde_json::json!(alice));
	assert_eq!(patch["staking"]["stakers"][0][0], serde_json::json!(alice));
}

#[test]
fn mainnet_is_refused_until_configured() {
	let err = orbinum_mainnet_config()
		.err()
		.expect("mainnet is not configured");
	assert!(err.starts_with("mainnet genesis not configured"), "{err}");
}
