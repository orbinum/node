mod development;
mod mainnet;
mod testnet;

use crate::{
	AccountId, AuraConfig, BalancesConfig, BaseFeeConfig, EVMChainIdConfig, EVMConfig,
	EthereumConfig, GrandpaConfig, ManualSealConfig, RuntimeGenesisConfig, SessionConfig,
	SudoConfig, ValidatorSetConfig,
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
/// Faucet allocation at genesis: 100,000,000 ORB
pub(super) const FAUCET_BALANCE: u128 = 100_000_000 * PLANCK;
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
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
	base_fee_per_gas: u64,
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

	// Derive validator AccountIds from their Aura (sr25519) public key bytes.
	// The validator's on-chain identity IS their sr25519 key — the same 32 bytes
	// serve as both AccountId32 and AuraId.
	let validator_accounts: Vec<AccountId> = initial_authorities
		.iter()
		.map(|(aura_id, _)| {
			let raw: [u8; 32] = <[u8; 32]>::try_from(aura_id.as_ref()).expect("AuraId is 32 bytes");
			AccountId::from(raw)
		})
		.collect();

	// Session genesis: (stash_account, validator_id, session_keys).
	// Both account and validator_id are the same AccountId for simplicity.
	let session_keys: Vec<(AccountId, AccountId, crate::opaque::SessionKeys)> = validator_accounts
		.iter()
		.zip(initial_authorities.iter())
		.map(|(account, (aura_id, grandpa_id))| {
			(
				account.clone(),
				account.clone(),
				crate::opaque::SessionKeys {
					aura: aura_id.clone(),
					grandpa: grandpa_id.clone(),
				},
			)
		})
		.collect();

	let config = RuntimeGenesisConfig {
		system: Default::default(),
		// Aura and GRANDPA authorities are initialised by pallet-session via
		// `on_genesis_session`. Setting empty vecs here is intentional.
		aura: AuraConfig {
			authorities: vec![],
		},
		base_fee: BaseFeeConfig {
			base_fee_per_gas: U256::from(base_fee_per_gas),
			..Default::default()
		},
		grandpa: GrandpaConfig {
			authorities: vec![],
			..Default::default()
		},
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
		// pallet-session: initialise with the approved validator session keys.
		session: SessionConfig {
			keys: session_keys,
			..Default::default()
		},
		// pallet-validator-set: track the approved AccountId set (sudo can add/remove).
		validator_set: ValidatorSetConfig {
			initial_validators: validator_accounts,
		},
	};

	serde_json::to_value(&config).expect("Could not build genesis config.")
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_str() {
		DEV_PRESET_ID | LOCAL_PRESET_ID => development::development(),
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
