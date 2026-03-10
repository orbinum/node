use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
// Substrate
use sc_chain_spec::{ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{Pair, Public, H160, U256};
use sp_runtime::traits::{IdentifyAccount, Verify};

use orbinum_runtime::{
	evm_bytes_to_account_id_bytes, AccountId, Balance, SS58Prefix, Signature, WASM_BINARY,
};

pub type ChainSpec = sc_service::GenericChainSpec;

fn ethereum_account_id(eth_address: [u8; 20]) -> AccountId {
	evm_bytes_to_account_id_bytes(eth_address).into()
}

pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenSymbol".into(), "ORB".into());
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties.insert("isEthereum".into(), true.into());
	properties
}

const PLANCK: Balance = 1_000_000_000_000_000_000;
const TOTAL_SUPPLY: Balance = 1_000_000_000 * PLANCK;
const DEV_BALANCE: Balance = 10_000 * PLANCK;

const FAUCET_BALANCE: Balance = 100_000_000 * PLANCK;
const EVM_CHAIN_ID: u64 = 270;
const TESTNET_EVM_CHAIN_ID: u64 = 2700;

pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	let initial_authorities = [authority_keys_from_seed("Alice")];

	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Development")
		.with_id("dev")
		.with_chain_type(ChainType::Development)
		.with_properties(properties())
		.with_genesis_config_preset_name("development")
		.with_genesis_config_patch(serde_json::json!({
			"manualSeal": { "enable": enable_manual_seal },
			"aura": {
				"authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>()
			},
			"grandpa": {
				"authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>()
			}
		}))
		.build()
}

pub fn local_testnet_config() -> ChainSpec {
	let initial_authorities = [
		authority_keys_from_seed("Alice"),
		authority_keys_from_seed("Bob"),
	];

	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Local Testnet")
		.with_id("local_testnet")
		.with_chain_type(ChainType::Local)
		.with_properties(properties())
		.with_genesis_config_preset_name("orbinum_local_testnet_runtime_preset")
		.with_genesis_config_patch(serde_json::json!({
			"aura": {
				"authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>()
			},
			"grandpa": {
				"authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>()
			}
		}))
		.build()
}

pub fn orbinum_testnet_config() -> ChainSpec {
	let sudo_key = AccountId::from(hex!(
		"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
	));
	let treasury = ethereum_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")); // PLACEHOLDER — Alith

	let faucet = ethereum_account_id(hex!("0000000000000000000000000000000000000001")); // PLACEHOLDER

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
			],
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			TESTNET_EVM_CHAIN_ID,
			false,
		))
		.build()
}

pub fn orbinum_mainnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Orbinum Mainnet")
		.with_id("orbinum_mainnet")
		.with_chain_type(ChainType::Live)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			AccountId::from([0u8; 32]),
			vec![],
			vec![],
			EVM_CHAIN_ID,
			false,
		))
		.build()
}

fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, Balance)>,
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
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

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"balances": {
			"balances": endowed_accounts
		},
		"aura": { "authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>() },
		"grandpa": { "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>() },
		"evmChainId": { "chainId": chain_id },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal }
	})
}
