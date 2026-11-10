// Copyright 2025 Security Research Labs GmbH
//
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Runs one fuzzed EVM transaction on the development genesis and checks the
//! runtime's invariants after it.

mod grammar;

pub use grammar::{assemble, Action, FuzzData, Instruction, Opcode, Push};

use frame_system::Account;
use orbinum_runtime::{Balance, Balances, Block, Runtime};
use pallet_balances::{Freezes, Holds, TotalIssuance};
use pallet_evm::{AccountCodes, FeeCalculator, FixedGasWeightMapping, GasWeightMapping, Runner};
use sp_core::{storage::Storage, H160, U256};
use sp_genesis_builder::runtime_decl_for_genesis_builder::GenesisBuilderV1;
use sp_state_machine::BasicExternalities;

pub const GAS_LIMIT: u64 = 1_000_000;

/// The sender: Alith, funded by the development preset.
pub const SENDER: H160 = H160(hex_literal::hex!(
	"f24ff3a9cf04c71dbc94d0b566f7a27b94566cac"
));

/// Where [`Action::Call`] installs its code; not a precompile.
pub const CONTRACT: H160 = H160([0xC0; 20]);

/// Every precompile: Ethereum's (0x01–0x09), Frontier's extras (0x400–0x403) and
/// Orbinum's (0x801–0x802).
pub const PRECOMPILES: [u64; 15] = [
	1, 2, 3, 4, 5, 6, 7, 8, 9, 1024, 1025, 1026, 1027, 2049, 2050,
];

/// The development preset's genesis storage, built once and cloned per input.
pub fn genesis() -> Storage {
	let mut ext = BasicExternalities::default();
	ext.execute_with(|| {
		let id = Some(sp_genesis_builder::DEV_RUNTIME_PRESET.into());
		let preset =
			<Runtime as GenesisBuilderV1<Block>>::get_preset(&id).expect("development preset");
		<Runtime as GenesisBuilderV1<Block>>::build_state(preset)
			.expect("development preset builds");
	});
	ext.into_storages()
}

/// Runs `data` on `genesis`; panics if an invariant breaks. Returns whether the
/// EVM accepted the transaction.
pub fn run(genesis: &Storage, data: FuzzData) -> bool {
	BasicExternalities::new(genesis.clone()).execute_with(|| execute(data))
}

fn execute(data: FuzzData) -> bool {
	type EvmRunner = <Runtime as pallet_evm::Config>::Runner;

	let initial_issuance = TotalIssuance::<Runtime>::get();
	let mut weight_limit = FixedGasWeightMapping::<Runtime>::gas_to_weight(GAS_LIMIT, true);
	if data.check_proof_size {
		*weight_limit.proof_size_mut() /= 2;
	}
	let value = U256::from(data.value);
	let max_fee = Some(<Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price().0);
	let config = <Runtime as pallet_evm::Config>::config();

	let call = |target: H160, input: Vec<u8>| {
		EvmRunner::call(
			SENDER,
			target,
			input,
			value,
			GAS_LIMIT,
			max_fee,
			None,
			None,
			Vec::new(),
			Vec::new(),
			true,
			true,
			Some(weight_limit),
			Some(0),
			config,
		)
		.map(|info| (info.used_gas, info.weight_info))
	};
	let result = match data.action {
		Action::Call { code, input } => {
			AccountCodes::<Runtime>::insert(CONTRACT, assemble(&code));
			call(CONTRACT, input)
		}
		Action::Precompile { index, input } => {
			let address = PRECOMPILES[usize::from(index) % PRECOMPILES.len()];
			call(H160::from_low_u64_be(address), input)
		}
		Action::Create { init } => EvmRunner::create(
			SENDER,
			assemble(&init),
			value,
			GAS_LIMIT,
			max_fee,
			None,
			None,
			Vec::new(),
			Vec::new(),
			true,
			true,
			Some(weight_limit),
			Some(0),
			config,
		)
		.map(|info| (info.used_gas, info.weight_info)),
	};

	let accepted = result.is_ok();
	if let Ok((used_gas, weight_info)) = result {
		assert!(
			used_gas.standard <= U256::from(GAS_LIMIT),
			"used gas over the limit"
		);
		// Fees are charged on the effective gas.
		assert!(
			used_gas.effective <= U256::from(GAS_LIMIT),
			"effective gas over the limit"
		);
		let weight_info = weight_info.expect("weight is metered");
		let ref_time = weight_info.ref_time_usage.expect("ref time is metered");
		let ref_time_limit = weight_info.ref_time_limit.expect("ref time is limited");
		assert!(ref_time <= ref_time_limit, "ref time over the limit");
		let proof_size = weight_info.proof_size_usage.expect("proof size is metered");
		assert!(
			proof_size <= weight_limit.proof_size(),
			"proof size over the limit"
		);
	}
	check_balances(initial_issuance);
	accepted
}

/// pallet-balances' invariants on every account, and total issuance never grows.
fn check_balances(initial_issuance: Balance) {
	let mut counted: Balance = 0;
	for (account, info) in Account::<Runtime>::iter() {
		assert!(
			info.consumers == 0 || info.providers > 0,
			"consumers without providers"
		);
		counted += info.data.free + info.data.reserved;
		let max_lock = Balances::locks(&account).iter().map(|l| l.amount).max();
		let max_freeze = Freezes::<Runtime>::get(&account)
			.iter()
			.map(|f| f.amount)
			.max();
		assert_eq!(
			max_lock.max(max_freeze).unwrap_or_default(),
			info.data.frozen,
			"frozen is the largest lock or freeze"
		);
		let holds: Balance = Holds::<Runtime>::get(&account)
			.iter()
			.map(|h| h.amount)
			.sum();
		assert!(
			holds <= info.data.reserved,
			"holds ({holds}) over reserved ({})",
			info.data.reserved
		);
	}
	let issuance = TotalIssuance::<Runtime>::get();
	assert_eq!(issuance, counted, "total issuance is the sum of balances");
	assert!(issuance <= initial_issuance, "total issuance grew");
}

#[cfg(test)]
mod tests {
	use super::*;
	use arbitrary::{Arbitrary, Unstructured};
	use pallet_evm::{IsPrecompileResult, PrecompileSet};

	fn is_precompile(address: H160) -> bool {
		let set = <Runtime as pallet_evm::Config>::PrecompilesValue::get();
		matches!(
			set.is_precompile(address, 0),
			IsPrecompileResult::Answer {
				is_precompile: true,
				..
			}
		)
	}

	#[test]
	fn addresses_match_the_runtime() {
		for address in PRECOMPILES {
			assert!(
				is_precompile(H160::from_low_u64_be(address)),
				"{address} is a precompile"
			);
		}
		assert!(!is_precompile(CONTRACT));
		assert!(!is_precompile(SENDER));
	}

	/// Runs the harness on a few hundred deterministic inputs.
	#[test]
	fn smoke() {
		let genesis = genesis();
		let mut state = 0x5EED_u64;
		let mut next = || {
			// splitmix64
			state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
			let mut z = state;
			z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
			z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
			z ^ (z >> 31)
		};
		let (mut runs, mut accepted) = ([0; 3], 0);
		for _ in 0..300 {
			let bytes: Vec<u8> = (0..64).flat_map(|_| next().to_le_bytes()).collect();
			let Ok(data) = FuzzData::arbitrary(&mut Unstructured::new(&bytes)) else {
				continue;
			};
			runs[match data.action {
				Action::Call { .. } => 0,
				Action::Create { .. } => 1,
				Action::Precompile { .. } => 2,
			}] += 1;
			accepted += usize::from(run(&genesis, data));
		}
		assert!(runs.iter().all(|&n| n > 0), "every action ran: {runs:?}");
		assert!(accepted > 0, "the EVM accepted some transactions");
	}
}
