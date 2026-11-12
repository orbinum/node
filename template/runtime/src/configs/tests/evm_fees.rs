// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! EVM fees go where Substrate fees go: the base fee to the era's fee pool, the
//! priority tip to the block author, or to governance without one. Nothing burns.

use crate::{
	configs::evm::EvmFeeRouter, economy::EraFeePoolAccount, evm_h160_to_account_id,
	test_utils::with_ext, Balances,
};
use frame_support::traits::{
	fungible::{Inspect, Mutate},
	tokens::imbalance::Imbalance,
};
use pallet_evm::OnChargeEVMTransaction;
use sp_core::H160;

// Benchmark builds give every block a stand-in author.
#[cfg(not(feature = "runtime-benchmarks"))]
#[test]
fn an_evm_tip_goes_to_the_validator_or_governance_without_one() {
	use crate::{
		economy::GovernanceAccount,
		test_utils::authorship::{digest, validator_set},
		Runtime,
	};
	use frame_support::traits::fungible::Balanced;
	with_ext(|| {
		let set = validator_set();
		// No pre-digest: no author, so the tip goes to governance. Nothing burns.
		EvmFeeRouter::pay_priority_fee(Some(Balances::issue(6)));
		assert_eq!(Balances::balance(&GovernanceAccount::get()), 6);

		frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(1));
		EvmFeeRouter::pay_priority_fee(Some(Balances::issue(25)));
		assert_eq!(Balances::balance(&set.bob), 25);
	});
}

#[test]
fn an_evm_base_fee_goes_to_the_era_fee_pool() {
	with_ext(|| {
		let sender = H160::repeat_byte(0x11);
		let account = evm_h160_to_account_id(sender);
		Balances::mint_into(&account, 1_000).unwrap();
		let issuance = Balances::total_issuance();

		let withdrawn = EvmFeeRouter::withdraw_fee(&sender, 100.into()).unwrap();
		let tip = EvmFeeRouter::correct_and_deposit_fee(&sender, 100.into(), 80.into(), withdrawn);

		assert_eq!(Balances::balance(&EraFeePoolAccount::get()), 80);
		assert_eq!(tip.as_ref().map(|t| t.peek()), Some(20));
		EvmFeeRouter::pay_priority_fee(tip);
		assert_eq!(Balances::total_issuance(), issuance);
	});
}
