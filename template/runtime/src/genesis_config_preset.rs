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

/// Map an Ethereum H160 address to its Substrate AccountId32 using the
/// Frontier Unified Account scheme: `[0x00; 12] ++ H160_bytes`.
///
/// This matches `TruncatedAddressMapping` in lib.rs so that
/// `eth_getBalance` and `system.account` read from the same pallet-balances entry.
fn ethereum_to_account_id(eth_address: [u8; 20]) -> AccountId {
	let mut bytes = [0u8; 32];
	bytes[12..].copy_from_slice(&eth_address);
	AccountId::from(bytes)
}

// ── Token supply constants ────────────────────────────────────────────────────
/// 1 ORB = 1_000_000_000_000 planck (12 decimals)
const PLANCK: u128 = 1_000_000_000_000;
/// Total project supply: 1,000,000,000 ORB
const TOTAL_SUPPLY: u128 = 1_000_000_000 * PLANCK;
/// Development/test account allocation: 10,000 ORB
const DEV_BALANCE: u128 = 10_000 * PLANCK;
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a chain spec for use with the development service.
pub fn development() -> serde_json::Value {
	testnet_genesis(
		// Sudo account (Alice)
		AccountId::from(hex!(
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
		)),
		// (account, balance) pairs
		// Alith holds the full project supply; dev accounts get 10,000 ORB each.
		vec![
			// ── Primary account (MetaMask / Alith) — total project supply ──────
			(
				ethereum_to_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
				TOTAL_SUPPLY,
			), // Alith
			// ── Substrate sr25519 dev accounts ──────────────────────────────────
			(
				AccountId::from(hex!(
					"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
				)),
				DEV_BALANCE,
			), // Alice
			(
				AccountId::from(hex!(
					"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
				)),
				DEV_BALANCE,
			), // Bob
			(
				AccountId::from(hex!(
					"90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22"
				)),
				DEV_BALANCE,
			), // Charlie
			// ── Ethereum dev accounts (Frontier unified mapping) ─────────────────
			(
				ethereum_to_account_id(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
				DEV_BALANCE,
			), // Baltathar
			(
				ethereum_to_account_id(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")),
				DEV_BALANCE,
			), // Charleth
			(
				ethereum_to_account_id(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")),
				DEV_BALANCE,
			), // Dorothy
			(
				ethereum_to_account_id(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")),
				DEV_BALANCE,
			), // Ethan
			(
				ethereum_to_account_id(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d")),
				DEV_BALANCE,
			), // Faith
			// CI test runner
			(
				ethereum_to_account_id(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b")),
				DEV_BALANCE,
			),
		],
		vec![],
		42,    // chain id
		false, // disable manual seal
	)
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, u128)>,
	_initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = sp_std::collections::btree_map::BTreeMap::new();
		// Benchmark helper account (code required, balance is minimal)
		map.insert(
			H160::from(hex!("1000000000000000000000000000000000000001")),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::zero(),
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
			balances: endowed_accounts.clone(),
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
