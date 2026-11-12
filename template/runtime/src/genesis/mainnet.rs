// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The mainnet preset, not configured yet.

use super::builder::{build_genesis, EvmGenesis, GenesisParams, StakingGenesis};
use crate::{
	staking::params::{
		MAINNET_MIN_NOMINATOR_BOND, MAINNET_MIN_VALIDATOR_BOND, MAINNET_POOL_MIN_CREATE_BOND,
	},
	AccountId,
};
use alloc::vec;

/// Mainnet's genesis. Not configured yet: a zero sudo key and no authorities.
/// `get_preset` refuses it until `MAINNET_CONFIGURED` is set, with the real
/// sudo key, authorities and endowments here.
pub fn mainnet() -> serde_json::Value {
	build_genesis(GenesisParams {
		sudo_key: AccountId::from([0u8; 32]),
		endowed_accounts: vec![],
		initial_authorities: vec![],
		staking: StakingGenesis {
			self_bond: MAINNET_MIN_VALIDATOR_BOND,
			min_validator_bond: MAINNET_MIN_VALIDATOR_BOND,
			min_nominator_bond: MAINNET_MIN_NOMINATOR_BOND,
			pool_min_create_bond: MAINNET_POOL_MIN_CREATE_BOND,
		},
		evm: EvmGenesis {
			chain_id: 270,
			// 1 gwei; EIP-1559 raises it with demand.
			base_fee_per_gas: 1_000_000_000,
			benchmark_account: false,
		},
		enable_manual_seal: false,
	})
}
