// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The testnet preset: its sudo key, treasury, faucet and three validators.

use super::{
	builder::{build_genesis, EvmGenesis, GenesisParams, StakingGenesis},
	DEV_BALANCE, FAUCET_BALANCE, TOTAL_SUPPLY,
};
use crate::{
	evm_h160_to_account_id,
	staking::params::{
		TEST_MIN_NOMINATOR_BOND, TEST_MIN_VALIDATOR_BOND, TEST_POOL_MIN_CREATE_BOND,
	},
	AccountId,
};
use alloc::vec;
use hex_literal::hex;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{ed25519, sr25519, H160};

fn aura_id(bytes: [u8; 32]) -> AuraId {
	sr25519::Public::from_raw(bytes).into()
}

fn grandpa_id(bytes: [u8; 32]) -> GrandpaId {
	ed25519::Public::from_raw(bytes).into()
}

/// The original testnet's validators: (Aura key, GRANDPA key). Each validator's
/// account is its Aura key's bytes, as the testnet started; a network launched
/// from scratch should give each a separate account (`GenesisParams`).
const VALIDATORS: [([u8; 32], [u8; 32]); 3] = [
	(
		hex!("b873599c026d0066aebe213d7984e7f84a6e3425d39f5fafcf681528a555ce47"),
		hex!("c8f990b25f78f7aa7a25c00a62f9d62ca5f45ed7fc83a419b75e5131130f2346"),
	),
	(
		hex!("641a682160d6298090cf1b1998dc3dad0c3df962fd29728fa1f7d3253c260362"),
		hex!("edd77017b97db02805b19060ca28aca163e52fa0d299fd2864447247f6c3229d"),
	),
	(
		hex!("0e24a46982207bc39fb1aa11724e127784b0b155330680583170a50fcd2bd052"),
		hex!("75a964ae2ac4b5df490c57949ef030f5857b4b84b611ff48ea880d1637eca18c"),
	),
];

pub fn testnet() -> serde_json::Value {
	let sudo_key = AccountId::from(hex!(
		"76eb8fe6dbed156f72f4f6c62c2430375fb51a46f09c2d86ffe1e2153e3d5524"
	));
	let treasury = evm_h160_to_account_id(H160(hex!("0bFEF65000b390F5E00e551451e5ce00a9c9930c")));
	let faucet = evm_h160_to_account_id(H160(hex!("0d4313eAa69c90c45DB96f2828Ff0D5e3BFE6BD5")));

	let mut endowed_accounts = vec![
		(treasury, TOTAL_SUPPLY - FAUCET_BALANCE),
		(faucet, FAUCET_BALANCE),
		(sudo_key.clone(), DEV_BALANCE),
	];
	endowed_accounts.extend(
		VALIDATORS
			.iter()
			.map(|(aura, _)| (AccountId::from(*aura), DEV_BALANCE)),
	);
	build_genesis(GenesisParams {
		sudo_key,
		endowed_accounts,
		initial_authorities: VALIDATORS
			.iter()
			.map(|(aura, grandpa)| (AccountId::from(*aura), aura_id(*aura), grandpa_id(*grandpa)))
			.collect(),
		staking: StakingGenesis {
			self_bond: TEST_MIN_VALIDATOR_BOND,
			min_validator_bond: TEST_MIN_VALIDATOR_BOND,
			min_nominator_bond: TEST_MIN_NOMINATOR_BOND,
			pool_min_create_bond: TEST_POOL_MIN_CREATE_BOND,
		},
		evm: EvmGenesis {
			chain_id: 2700,
			// 1 gwei; EIP-1559 raises it with demand.
			base_fee_per_gas: 1_000_000_000,
			benchmark_account: false,
		},
		enable_manual_seal: false,
	})
}
