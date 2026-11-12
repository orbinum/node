//! The genesis every preset is built from: one validator account per initial
//! authority, bonded and admitted, with its session keys.

use crate::{
	evm::precompiles::{FrontierPrecompiles, PRECOMPILE_CODE},
	opaque::SessionKeys,
	staking::params::{MAX_VALIDATOR_CANDIDATES, POOL_MIN_JOIN_BOND, SLASH_REWARD_FRACTION},
	AccountId, AhClientConfig, AuraConfig, BalancesConfig, BaseFeeConfig, EVMChainIdConfig,
	EVMConfig, EthereumConfig, GrandpaConfig, ManualSealConfig, NominationPoolsConfig, Runtime,
	RuntimeGenesisConfig, SessionConfig, StakingConfig, SudoConfig, ValidatorSetConfig,
};
use alloc::{collections::btree_map::BTreeMap, vec, vec::Vec};
use hex_literal::hex;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{H160, U256};

/// What a preset chooses; everything else is the same on every chain.
pub(super) struct GenesisParams {
	pub sudo_key: AccountId,
	pub endowed_accounts: Vec<(AccountId, u128)>,
	/// Each authority: its validator account, which bonds and owns the keys,
	/// and its session keys. The account should not be the Aura key's bytes:
	/// that key sits in the node's keystore, and whoever reads it could then
	/// move the bond and redirect the rewards.
	pub initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
	pub staking: StakingGenesis,
	pub evm: EvmGenesis,
	pub enable_manual_seal: bool,
}

/// Staking at genesis. Every initial authority's validator account bonds
/// `self_bond` and offers itself as a validator; each needs at least that much
/// in `endowed_accounts`.
pub(super) struct StakingGenesis {
	pub self_bond: u128,
	pub min_validator_bond: u128,
	pub min_nominator_bond: u128,
	pub pool_min_create_bond: u128,
}

/// The EVM at genesis.
pub(super) struct EvmGenesis {
	pub chain_id: u64,
	pub base_fee_per_gas: u64,
	/// Development only: an account with code at `0x1000…0001`, as EVM
	/// benchmarks and tests expect.
	pub benchmark_account: bool,
}

/// The full genesis config for `params`, as JSON.
pub(super) fn build_genesis(params: GenesisParams) -> serde_json::Value {
	let GenesisParams {
		sudo_key,
		endowed_accounts,
		initial_authorities,
		staking,
		evm,
		enable_manual_seal,
	} = params;
	let EvmGenesis {
		chain_id,
		base_fee_per_gas,
		benchmark_account,
	} = evm;
	let evm_accounts = {
		let mut map = BTreeMap::new();
		if benchmark_account {
			map.insert(
				H160::from(hex!("1000000000000000000000000000000000000001")),
				fp_evm::GenesisAccount {
					nonce: U256::from(1),
					balance: U256::zero(),
					storage: Default::default(),
					code: vec![0x00],
				},
			);
		}
		for address in FrontierPrecompiles::<Runtime>::addresses_with_code() {
			map.insert(
				address,
				fp_evm::GenesisAccount {
					nonce: U256::zero(),
					balance: U256::zero(),
					storage: Default::default(),
					code: PRECOMPILE_CODE.to_vec(),
				},
			);
		}
		map
	};

	let validator_accounts: Vec<AccountId> = initial_authorities
		.iter()
		.map(|(account, _, _)| account.clone())
		.collect();

	// (account, validator id, keys): the validator id is the account itself.
	let session_keys: Vec<(AccountId, AccountId, SessionKeys)> = initial_authorities
		.into_iter()
		.map(|(account, aura, grandpa)| (account.clone(), account, SessionKeys { aura, grandpa }))
		.collect();

	let config = RuntimeGenesisConfig {
		system: Default::default(),
		// Empty: pallet-session sets the Aura and GRANDPA authorities from its keys.
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
			balances: endowed_accounts,
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
		era_pruning: Default::default(),
		zk_verifier: Default::default(),
		shielded_pool: Default::default(),
		session: SessionConfig {
			keys: session_keys,
			..Default::default()
		},
		staking: StakingConfig {
			validator_count: validator_accounts.len() as u32,
			stakers: validator_accounts
				.iter()
				.map(|v| {
					(
						v.clone(),
						staking.self_bond,
						pallet_staking_async::StakerStatus::Validator,
					)
				})
				.collect(),
			// Era 0 runs on the genesis keys with no exposures; the first election
			// is planned near its end, as for every era.
			force_era: pallet_staking_async::Forcing::NotForcing,
			slash_reward_fraction: SLASH_REWARD_FRACTION,
			min_validator_bond: staking.min_validator_bond,
			min_nominator_bond: staking.min_nominator_bond,
			max_validator_count: Some(MAX_VALIDATOR_CANDIDATES),
			// Uncapped: the minimum bond is the anti-spam; governance may cap
			// it on-chain (`set_staking_configs`).
			max_nominator_count: None,
			..Default::default()
		},
		// Pools and members uncapped: the minimum bonds are the anti-spam;
		// governance may cap them, and pool commission, on-chain (`set_configs`).
		nomination_pools: NominationPoolsConfig {
			min_join_bond: POOL_MIN_JOIN_BOND,
			min_create_bond: staking.pool_min_create_bond,
			max_pools: None,
			max_members_per_pool: None,
			max_members: None,
			global_max_commission: None,
		},
		// The session side reports to staking from the first session.
		ah_client: AhClientConfig {
			operating_mode: pallet_staking_async_ah_client::OperatingMode::Active,
			..Default::default()
		},
		// The approved accounts, admitted as candidates.
		validator_set: ValidatorSetConfig {
			initial_validators: validator_accounts,
		},
	};

	serde_json::to_value(&config).expect("Could not build genesis config.")
}
