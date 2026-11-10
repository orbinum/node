//! Per-asset pool ledger.
//!
//! Tracks what the pool holds for each asset. Only the native asset is backed by
//! `Currency`; the ledger must stay equal to the pool account's physical balance,
//! an invariant the pallet asserts under `try_state`.

use crate::pallet::{BalanceOf, Config, PoolBalancePerAsset};
use sp_runtime::traits::Saturating;

// PoolBalanceRepository

pub struct PoolBalanceRepository;

impl PoolBalanceRepository {
	pub fn get_asset_balance<T: Config>(asset_id: u32) -> BalanceOf<T> {
		PoolBalancePerAsset::<T>::get(asset_id)
	}
	pub fn set_asset_balance<T: Config>(asset_id: u32, balance: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::insert(asset_id, balance);
	}
	pub fn increase_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			*balance = balance.saturating_add(amount);
		});
	}
	pub fn decrease_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			// The unshield guard (`>= amount + fee`) makes `balance >= amount` always
			// hold here; `defensive!` trips in tests/try-runtime if that invariant is
			// ever broken, while `saturating_sub` keeps production safe.
			frame_support::defensive_assert!(*balance >= amount);
			*balance = balance.saturating_sub(amount);
		});
	}
}
