use crate::{
	AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, EthereumConfig, ManualSealConfig,
	RuntimeGenesisConfig, SudoConfig,
};
use hex_literal::hex;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{H160, U256};
use sp_genesis_builder::PresetId;
use sp_std::prelude::*;

use orbinum_zk_verifier::infrastructure::storage::verification_keys;
use pallet_zk_verifier::CircuitId;

use sp_core::hashing::blake2_256;

/// Map Ethereum address (20 bytes) to AccountId32 using blake2_256 hash
/// This matches the HashedAddressMapping implementation in lib.rs
fn ethereum_to_account_id(eth_address: [u8; 20]) -> AccountId {
	let hash_result = blake2_256(&eth_address);
	AccountId::from(hash_result)
}

/// Generate a chain spec for use with the development service.
pub fn development() -> serde_json::Value {
	testnet_genesis(
		// Sudo account (Alice)
		AccountId::from(hex!(
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
		)),
		// Pre-funded accounts (sr25519 test accounts + Ethereum mapped)
		vec![
			// Substrate sr25519 accounts (for test extrinsics)
			AccountId::from(hex!(
				"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
			)), // Alice
			AccountId::from(hex!(
				"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
			)), // Bob
			AccountId::from(hex!(
				"90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22"
			)), // Charlie
			// Ethereum mapped accounts (for EVM compatibility)
			ethereum_to_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")), // Alith
			ethereum_to_account_id(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")), // Baltathar
			ethereum_to_account_id(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")), // Charleth
		],
		vec![],
		42,    // chain id
		false, // disable manual seal
	)
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = sp_std::collections::btree_map::BTreeMap::new();
		map.insert(
			// H160 address of Alice dev account
			// Derived from SS58 (42 prefix) address
			// SS58: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
			// hex: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
			// Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
			H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
			fp_evm::GenesisAccount {
				balance: U256::MAX,
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address of CI test runner account
			H160::from(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b")),
			fp_evm::GenesisAccount {
				balance: U256::MAX,
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address for benchmark usage
			H160::from(hex!("1000000000000000000000000000000000000001")),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::from(1_000_000_000_000_000_000_000_000u128),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	let config = RuntimeGenesisConfig {
		system: Default::default(),
		aura: Default::default(),
		base_fee: Default::default(),
		grandpa: Default::default(),
		balances: BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1 << 110))
				.collect(),
			..Default::default()
		},
		ethereum: EthereumConfig {
			..Default::default()
		},
		evm: EVMConfig {
			accounts: evm_accounts.into_iter().collect(),
			..Default::default()
		},
		evm_chain_id: EVMChainIdConfig {
			chain_id,
			..Default::default()
		},
		manual_seal: ManualSealConfig {
			enable: enable_manual_seal,
			..Default::default()
		},
		sudo: SudoConfig {
			key: Some(sudo_key),
		},
		transaction_payment: Default::default(),
		zk_verifier: pallet_zk_verifier::GenesisConfig {
			verification_keys: vec![
				(
					CircuitId::TRANSFER,
					verification_keys::get_transfer_vk_bytes(),
				),
				(
					CircuitId::UNSHIELD,
					verification_keys::get_unshield_vk_bytes(),
				),
				(
					CircuitId::DISCLOSURE,
					verification_keys::get_disclosure_vk_bytes(),
				),
			],
			..Default::default()
		},
		shielded_pool: Default::default(),
	};

	serde_json::to_value(&config).expect("Could not build genesis config.")
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_str() {
		sp_genesis_builder::DEV_RUNTIME_PRESET => development(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}
