//! The development and local presets: Alice as sudo, the dev accounts funded, and the
//! validators from the node's chain spec patch.

use super::{
	builder::{build_genesis, EvmGenesis, GenesisParams, StakingGenesis},
	DEV_BALANCE, TOTAL_SUPPLY,
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
use sp_core::H160;

pub fn development() -> serde_json::Value {
	build_genesis(GenesisParams {
		sudo_key: AccountId::from(hex!(
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
		)),
		endowed_accounts: vec![
			(
				evm_h160_to_account_id(H160(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"))),
				TOTAL_SUPPLY,
			),
			(
				AccountId::from(hex!(
					"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
				)),
				DEV_BALANCE,
			),
			(
				AccountId::from(hex!(
					"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
				)),
				DEV_BALANCE,
			),
			(
				AccountId::from(hex!(
					"90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22"
				)),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b"))),
				DEV_BALANCE,
			),
			(
				evm_h160_to_account_id(H160(hex!("e04cc55ebee1cbce552f250e85c57b70b2e2625b"))),
				DEV_BALANCE,
			),
		],
		// Validators and their bonds come from the node's chain spec patch.
		initial_authorities: vec![],
		staking: StakingGenesis {
			self_bond: TEST_MIN_VALIDATOR_BOND,
			min_validator_bond: TEST_MIN_VALIDATOR_BOND,
			min_nominator_bond: TEST_MIN_NOMINATOR_BOND,
			pool_min_create_bond: TEST_POOL_MIN_CREATE_BOND,
		},
		evm: EvmGenesis {
			chain_id: 42,
			// 1 gwei: cheap, yet visible in wallets.
			base_fee_per_gas: 1_000_000_000,
			benchmark_account: true,
		},
		enable_manual_seal: false,
	})
}

/// The development genesis for upstream's staking and pool benchmarks, which size
/// stakes from the existential deposit and need three pools: no minimum staking bonds,
/// pool bonds of a millionth (create) and a billionth (join) of an ORB, up to 16 pools,
/// and one ORB per dev account. Their stakes then keep the issuance within `u64`,
/// where a `runtime-benchmarks` build makes vote weight equal stake
/// (`staking::vote::DecimalCurrencyToVote`), as the pool benchmarks assume, while a
/// pool's bond stays above the voter list's lowest bag.
#[cfg(feature = "runtime-benchmarks")]
pub fn benchmark() -> serde_json::Value {
	let mut genesis = development();
	genesis["staking"]["minValidatorBond"] = 0.into();
	genesis["staking"]["minNominatorBond"] = 0.into();
	let orb = crate::primitives::constants::ORB;
	genesis["nominationPools"]["minCreateBond"] =
		serde_json::to_value(orb / 1_000_000).expect("u128 to json");
	genesis["nominationPools"]["minJoinBond"] =
		serde_json::to_value(orb / 1_000_000_000).expect("u128 to json");
	genesis["nominationPools"]["maxPools"] = 16.into();
	let one = serde_json::to_value(orb).expect("u128 to json");
	if let Some(balances) = genesis["balances"]["balances"].as_array_mut() {
		for entry in balances {
			entry[1] = one.clone();
		}
	}
	genesis
}
