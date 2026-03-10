mod development;
mod local;
mod mainnet;
mod testnet;

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

/// Map an Ethereum H160 address to its Substrate AccountId32 using
/// the runtime helper (H160_bytes ++ [0xEE; 12]).
///
/// This matches `EeSuffixAddressMapping` in lib.rs so that
/// `eth_getBalance` and `system.account` read from the same pallet-balances entry.
pub(super) fn ethereum_to_account_id(eth_address: [u8; 20]) -> crate::AccountId {
	crate::evm_bytes_to_account_id_bytes(eth_address).into()
}

// ── Token supply constants ────────────────────────────────────────────────────
/// 1 ORB = 1_000_000_000_000_000_000 wei (18 decimals, Ethereum-compatible)
pub(super) const PLANCK: u128 = 1_000_000_000_000_000_000;
/// Total project supply: 1,000,000,000 ORB
pub(super) const TOTAL_SUPPLY: u128 = 1_000_000_000 * PLANCK;
/// Development/test account allocation: 10,000 ORB
pub(super) const DEV_BALANCE: u128 = 10_000 * PLANCK;
// ──────────────────────────────────────────────────────────────────────────────

pub(super) const DEV_PRESET_ID: &str = sp_genesis_builder::DEV_RUNTIME_PRESET;
pub(super) const LOCAL_PRESET_ID: &str = "orbinum_local_testnet_runtime_preset";
pub(super) const TESTNET_PRESET_ID: &str = "orbinum_testnet_runtime_preset";
pub(super) const MAINNET_PRESET_ID: &str = "orbinum_mainnet_runtime_preset";

/// Configure initial storage state for FRAME modules.
pub(super) fn build_genesis(
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
		zk_verifier: Default::default(),
		shielded_pool: Default::default(),
	};

	serde_json::to_value(&config).expect("Could not build genesis config.")
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_str() {
		DEV_PRESET_ID => development::development(),
		LOCAL_PRESET_ID => local::local_testnet(),
		TESTNET_PRESET_ID => testnet::testnet(),
		MAINNET_PRESET_ID => mainnet::mainnet(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}
