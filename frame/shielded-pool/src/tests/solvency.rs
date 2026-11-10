//! The ledger-solvency invariant: a donation to the pool account leaves it
//! intact; a ledger above the physical balance breaks it.

use crate::{
	PoolBalancePerAsset,
	mock::{Balances, ShieldedPool, Test, new_test_ext},
};
use frame_support::traits::{Currency, Hooks};

#[test]
fn a_donation_to_the_pool_account_keeps_it_solvent() {
	new_test_ext().execute_with(|| {
		let pool = ShieldedPool::pool_account_id();
		PoolBalancePerAsset::<Test>::insert(0u32, 100u128);
		let _ = Balances::deposit_creating(&pool, 100);
		assert!(<ShieldedPool as Hooks<u64>>::try_state(1).is_ok());

		let _ = Balances::deposit_creating(&pool, 1);
		assert!(<ShieldedPool as Hooks<u64>>::try_state(1).is_ok());

		PoolBalancePerAsset::<Test>::insert(0u32, 102u128);
		assert!(<ShieldedPool as Hooks<u64>>::try_state(1).is_err());
	});
}
