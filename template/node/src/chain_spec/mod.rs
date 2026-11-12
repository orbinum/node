// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Chain specifications.
//!
//! - `dev`: single validator (Alice), optional manual seal (`--dev`).
//! - `local`: three validators (Alice, Bob, Charlie) on one machine (`--chain local`).
//! - `testnet`: the public Orbinum Testnet, EVM chain ID 2700.
//! - `mainnet`: Orbinum Mainnet, EVM chain ID 270; refused until the runtime configures it.
//!
//! Genesis state comes from the runtime's presets (`template/runtime/src/genesis`); the
//! dev and local specs patch in their validators.

mod dev;
mod local;
mod mainnet;
mod testnet;
#[cfg(test)]
mod tests;

pub use dev::development_config;
pub use local::local_testnet_config;
pub use mainnet::orbinum_mainnet_config;
pub use testnet::orbinum_testnet_config;

use sc_chain_spec::{ChainSpecBuilder, ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{Pair, Public};

use orbinum_runtime::{
	opaque::SessionKeys, staking::params::TEST_MIN_VALIDATOR_BOND, AccountId, SS58Prefix,
};

pub type ChainSpec = sc_service::GenericChainSpec;

/// The runtime every spec starts from.
fn wasm_binary() -> Result<&'static [u8], String> {
	orbinum_runtime::WASM_BINARY.ok_or_else(|| {
		"the runtime WASM is not built into this binary (built with SKIP_WASM_BUILD?)".into()
	})
}

/// A builder with the runtime, name, id, chain type and the properties every spec shares.
fn base_builder(name: &str, id: &str, chain_type: ChainType) -> Result<ChainSpecBuilder, String> {
	Ok(ChainSpec::builder(wasm_binary()?, Default::default())
		.with_name(name)
		.with_id(id)
		.with_chain_type(chain_type)
		.with_properties(properties()))
}

/// Token symbol, decimals and SS58 prefix.
fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenSymbol".into(), "ORB".into());
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties
}

/// Genesis patch that makes the validators of `seeds` (well-known dev keys) era 0's
/// authorities: session keys, the validator-set allowlist, and staking at the test
/// networks' minimum bond. Aura and GRANDPA authorities are left empty: pallet-session
/// fills them.
fn validators_patch(seeds: &[&str]) -> serde_json::Value {
	let validators: Vec<(AccountId, SessionKeys)> = seeds
		.iter()
		.map(|seed| {
			let aura = from_seed::<AuraId>(seed);
			let grandpa = from_seed::<GrandpaId>(seed);
			(aura_to_account(&aura), SessionKeys { aura, grandpa })
		})
		.collect();
	let accounts: Vec<&AccountId> = validators.iter().map(|(account, _)| account).collect();
	let keys: Vec<_> = validators
		.iter()
		.map(|(account, keys)| (account, account, keys))
		.collect();
	let stakers: Vec<_> = accounts
		.iter()
		.map(|account| serde_json::json!([account, TEST_MIN_VALIDATOR_BOND, "Validator"]))
		.collect();

	serde_json::json!({
		"aura": { "authorities": [] },
		"grandpa": { "authorities": [] },
		"session": { "keys": keys },
		"validatorSet": { "initialValidators": accounts },
		"staking": {
			"validatorCount": validators.len() as u32,
			"stakers": stakers,
		},
	})
}

/// The public key of a well-known dev seed (e.g. `"Alice"`).
fn from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static seed is valid")
		.public()
}

/// A validator's account is its Aura (sr25519) key: the same 32 bytes.
fn aura_to_account(aura: &AuraId) -> AccountId {
	let raw = <[u8; 32]>::try_from(aura.as_ref()).expect("AuraId is 32 bytes");
	AccountId::from(raw)
}
