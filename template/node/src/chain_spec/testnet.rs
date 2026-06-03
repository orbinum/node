//! Orbinum public testnet chain configuration.
//!
//! Activated with `--chain testnet` or `--chain orbinum_testnet`.
//!
//! EVM chain ID: **2700** (registered in ChainList).
//!
//! All keys were generated with `scripts/testnet-keys/generate-keys.sh`.
//! Session keys must be inserted into each running validator node after
//! deployment using `scripts/testnet-keys/insert-session-keys.sh`.

use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
use sc_chain_spec::ChainType;
use sp_core::{H160, U256};

use orbinum_runtime::{AccountId, Balance, WASM_BINARY};

use super::{
	aura_id, ethereum_account_id, grandpa_id, properties, session_keys, AuraId, ChainSpec,
	GrandpaId, DEV_BALANCE, FAUCET_BALANCE, TESTNET_BASE_FEE, TESTNET_EVM_CHAIN_ID, TOTAL_SUPPLY,
};

/// Orbinum public testnet configuration.
///
/// **Genesis balances:**
/// - Treasury (`0xb868…5608`): 900,000,000 ORB
/// - Faucet   (`0xf4d9…2F2F`): 100,000,000 ORB
/// - Sudo (operational):            10,000 ORB
///
/// **Validators:** 3 nodes with real keys generated for testnet launch.
/// **EVM chain ID:** 2700
/// **Base fee:** 1 gwei — EIP-1559 adjusts dynamically with traffic.
pub fn orbinum_testnet_config() -> ChainSpec {
	let sudo_key = AccountId::from(hex!(
		"76eb8fe6dbed156f72f4f6c62c2430375fb51a46f09c2d86ffe1e2153e3d5524"
	));
	let treasury = ethereum_account_id(hex!("0bFEF65000b390F5E00e551451e5ce00a9c9930c"));
	let faucet = ethereum_account_id(hex!("0d4313eAa69c90c45DB96f2828Ff0D5e3BFE6BD5"));

	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Orbinum Testnet")
		.with_id("orbinum_testnet")
		.with_chain_type(ChainType::Live)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			sudo_key.clone(),
			vec![
				(treasury, TOTAL_SUPPLY - FAUCET_BALANCE),
				(faucet, FAUCET_BALANCE),
				(sudo_key, DEV_BALANCE),
				// Validators need enough balance for the 1 000 ORB registration bond + fees.
				// These AccountIds are the same bytes as each validator's Aura (sr25519) public key,
				// because testnet_genesis derives AccountId directly from aura.as_ref().
				(
					AccountId::from(hex!(
						"b873599c026d0066aebe213d7984e7f84a6e3425d39f5fafcf681528a555ce47"
					)),
					DEV_BALANCE,
				), // Validator 1
				(
					AccountId::from(hex!(
						"641a682160d6298090cf1b1998dc3dad0c3df962fd29728fa1f7d3253c260362"
					)),
					DEV_BALANCE,
				), // Validator 2
				(
					AccountId::from(hex!(
						"0e24a46982207bc39fb1aa11724e127784b0b155330680583170a50fcd2bd052"
					)),
					DEV_BALANCE,
				), // Validator 3
			],
			vec![
				// Validator 1
				(
					aura_id(hex!(
						"b873599c026d0066aebe213d7984e7f84a6e3425d39f5fafcf681528a555ce47"
					)),
					grandpa_id(hex!(
						"c8f990b25f78f7aa7a25c00a62f9d62ca5f45ed7fc83a419b75e5131130f2346"
					)),
				),
				// Validator 2
				(
					aura_id(hex!(
						"641a682160d6298090cf1b1998dc3dad0c3df962fd29728fa1f7d3253c260362"
					)),
					grandpa_id(hex!(
						"edd77017b97db02805b19060ca28aca163e52fa0d299fd2864447247f6c3229d"
					)),
				),
				// Validator 3
				(
					aura_id(hex!(
						"0e24a46982207bc39fb1aa11724e127784b0b155330680583170a50fcd2bd052"
					)),
					grandpa_id(hex!(
						"75a964ae2ac4b5df490c57949ef030f5857b4b84b611ff48ea880d1637eca18c"
					)),
				),
			],
			TESTNET_EVM_CHAIN_ID,
			TESTNET_BASE_FEE,
			false,
		))
		.build()
}

/// Builds the testnet genesis JSON patch.
///
/// - `base_fee_per_gas` is serialised as a hex string because `U256` expects it.
/// - A sentinel EVM account (`0x1000…0001`) is pre-deployed as required by the
///   Frontier pallet to signal that EVM state is initialised.
/// - Aura and GRANDPA authorities are **empty**; pallet-session initialises them
///   via `on_genesis_session` from the `session.keys` list.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, Balance)>,
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	base_fee_per_gas: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	// Sentinel account required by pallet-evm to mark EVM genesis as initialised.
	let evm_accounts = {
		let mut map = BTreeMap::new();
		map.insert(
			H160::from_str("1000000000000000000000000000000000000001")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::zero(),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	// `U256` is deserialised from a hex string in genesis JSON (e.g. "0x3b9aca00").
	let base_fee_hex = format!("{base_fee_per_gas:#x}");

	// Derive each validator's AccountId from their Aura (sr25519) public key.
	// The validator's on-chain identity IS their sr25519 key bytes.
	let validator_accounts: Vec<AccountId> = initial_authorities
		.iter()
		.map(|(aura, _)| {
			let raw: [u8; 32] =
				<[u8; 32]>::try_from(aura.as_ref()).expect("AuraId is always 32 bytes");
			AccountId::from(raw)
		})
		.collect();

	// Build session keys list: (stash, validator_id, { aura, grandpa })
	let session_key_list: Vec<serde_json::Value> = initial_authorities
		.iter()
		.zip(validator_accounts.iter())
		.map(|((aura, grandpa), account)| {
			serde_json::json!([
				account,
				account,
				session_keys(aura.clone(), grandpa.clone())
			])
		})
		.collect();

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"balances": { "balances": endowed_accounts },
		// Aura and GRANDPA are populated by pallet-session on genesis — leave empty.
		"aura": { "authorities": [] },
		"grandpa": { "authorities": [] },
		// pallet-session: initial session keys for each validator.
		"session": { "keys": session_key_list },
		// pallet-validator-set: approved validator accounts (sudo can add/remove).
		"validatorSet": { "initialValidators": validator_accounts },
		"evmChainId": { "chainId": chain_id },
		"baseFee": { "baseFeePerGas": base_fee_hex },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal }
	})
}
