//! Where value goes, through the whole runtime: the keyless accounts are distinct, a
//! transaction's fee and tip are routed apart, and an era's payout drains the fee pool.

use crate::{
	configs::{
		ismp::IsmpTreasuryAccount,
		privacy::ShieldedPoolPalletId,
		staking::{DelegatedStakingPalletId, PoolsPalletId, StakingPotId},
	},
	economy::{
		accounts::{AutoPayoutAccount, EraFeePoolAccount, EraPruningAccount, GovernanceAccount},
		fees::ToAuthor,
		rewards::{DrainAccount, EraRewardSource, Inflation, RewardSources},
		schedule::{era_issuance, TokenomicsSchedule},
		DealWithFees,
	},
	primitives::constants::DAY_MS,
	test_utils::with_ext,
	AccountId, Balance, Balances, NominationPools,
};
use frame_support::{
	parameter_types,
	traits::{
		fungible::{Balanced, Credit, Inspect, Mutate},
		Get, OnUnbalanced,
	},
};
use sp_runtime::traits::AccountIdConversion;
use sp_staking::{EraIndex, EraPayout};

// Accounts

#[test]
fn accounts_are_distinct() {
	let pool: AccountId = ShieldedPoolPalletId::get().into_account_truncating();
	let (bonded, reward) = NominationPools::api_pool_accounts(1);
	let all = [
		GovernanceAccount::get(),
		EraFeePoolAccount::get(),
		AutoPayoutAccount::get(),
		EraPruningAccount::get(),
		pool,
		IsmpTreasuryAccount::get(),
		StakingPotId::get().into_account_truncating(),
		PoolsPalletId::get().into_account_truncating(),
		DelegatedStakingPalletId::get().into_account_truncating(),
		bonded,
		reward,
	];
	for (i, a) in all.iter().enumerate() {
		for b in &all[i + 1..] {
			assert_ne!(a, b);
		}
	}
}

// Fees and tips

fn issue(amount: u128) -> Credit<AccountId, Balances> {
	<Balances as Balanced<AccountId>>::issue(amount)
}

fn balance(who: &AccountId) -> u128 {
	<Balances as Inspect<AccountId>>::balance(who)
}

// Benchmark builds give every block a stand-in author.
#[cfg(not(feature = "runtime-benchmarks"))]
#[test]
fn fee_to_pool_tip_to_fallback_without_author() {
	with_ext(|| {
		let (fee, tip) = (issue(100), issue(7));
		// `issue` already counted both in the total; routing must not change it.
		let before = <Balances as Inspect<AccountId>>::total_issuance();
		<DealWithFees as OnUnbalanced<_>>::on_unbalanceds([fee, tip].into_iter());

		assert_eq!(balance(&EraFeePoolAccount::get()), 100);
		// No block author outside a block: the tip goes to governance.
		assert_eq!(balance(&GovernanceAccount::get()), 7);
		// Nothing burned: everything issued is still somewhere.
		assert_eq!(<Balances as Inspect<AccountId>>::total_issuance(), before);
	});
}

#[test]
fn tip_goes_to_author_when_there_is_one() {
	struct Author;
	impl Get<Option<AccountId>> for Author {
		fn get() -> Option<AccountId> {
			Some(AccountId::from([7; 32]))
		}
	}
	with_ext(|| {
		<ToAuthor<Balances, Author, GovernanceAccount> as OnUnbalanced<_>>::on_unbalanced(issue(7));
		assert_eq!(balance(&AccountId::from([7; 32])), 7);
		assert_eq!(balance(&GovernanceAccount::get()), 0);
	});
}

#[test]
fn lone_credit_is_a_fee() {
	with_ext(|| {
		<DealWithFees as OnUnbalanced<_>>::on_unbalanced(issue(5));
		assert_eq!(balance(&EraFeePoolAccount::get()), 5);
	});
}

// Era rewards

parameter_types! {
	pub const EraZero: EraIndex = 0;
}

type FeePool = DrainAccount<EraFeePoolAccount, Balances>;
type Payout = RewardSources<(Inflation<TokenomicsSchedule>, FeePool), EraZero>;

fn pool() -> Balance {
	<Balances as Inspect<AccountId>>::balance(&EraFeePoolAccount::get())
}

fn issuance() -> Balance {
	<Balances as Inspect<AccountId>>::total_issuance()
}

#[test]
fn drain_takes_the_pool_once() {
	with_ext(|| {
		Balances::mint_into(&EraFeePoolAccount::get(), 1_000).unwrap();
		let before = issuance();

		assert_eq!(FeePool::take(0, DAY_MS), 1_000);
		assert_eq!(pool(), 0);
		// Burned now, re-minted by staking when stakers claim.
		assert_eq!(issuance(), before - 1_000);

		assert_eq!(FeePool::take(0, DAY_MS), 0);
	});
}

#[test]
fn payout_sums_inflation_and_fees() {
	with_ext(|| {
		Balances::mint_into(&EraFeePoolAccount::get(), 1_000).unwrap();
		let inflation = era_issuance::<TokenomicsSchedule>(0, DAY_MS);

		assert_eq!(Payout::era_payout(1, 0, DAY_MS), (inflation + 1_000, 0));
		assert_eq!(pool(), 0);
	});
}

#[test]
fn an_era_without_stake_pays_and_takes_nothing() {
	with_ext(|| {
		Balances::mint_into(&EraFeePoolAccount::get(), 1_000).unwrap();
		assert_eq!(Payout::era_payout(0, 0, DAY_MS), (0, 0));
		assert_eq!(pool(), 1_000);
	});
}
