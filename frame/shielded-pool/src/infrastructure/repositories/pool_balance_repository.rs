//! Pool Balance Repository - Encapsulates pool balance storage access

use crate::pallet::{BalanceOf, Config, PoolBalance, PoolBalancePerAsset};
use sp_runtime::traits::Saturating;

/// Repository for pool balance operations
pub struct PoolBalanceRepository;

impl PoolBalanceRepository {
	/// Get total pool balance (native asset)
	pub fn get_total_balance<T: Config>() -> BalanceOf<T> {
		PoolBalance::<T>::get()
	}

	/// Set total pool balance (native asset)
	pub fn set_total_balance<T: Config>(balance: BalanceOf<T>) {
		PoolBalance::<T>::put(balance);
	}

	/// Get balance for a specific asset
	pub fn get_asset_balance<T: Config>(asset_id: u32) -> BalanceOf<T> {
		PoolBalancePerAsset::<T>::get(asset_id)
	}

	/// Set balance for a specific asset
	pub fn set_asset_balance<T: Config>(asset_id: u32, balance: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::insert(asset_id, balance);
	}

	/// Increase pool balance for an asset
	pub fn increase_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			*balance = balance.saturating_add(amount);
		});
	}

	/// Decrease pool balance for an asset
	pub fn decrease_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			*balance = balance.saturating_sub(amount);
		});
	}
}
