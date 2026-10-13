//! Spend fees: crediting them to the block author and paying them out.
//!
//! A spend's fee never leaves the pool when the spend executes: it is recorded
//! in `PendingFees` for the validator that authored the block, and leaves the
//! pool only when that validator claims it.

use crate::{
	operations::assets::AssetOperation,
	pallet::{BalanceOf, Config, Error, Event, Pallet, PendingFees},
	storage::PoolBalanceRepository,
};
use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use sp_runtime::{SaturatedConversion, traits::Zero};

/// Credit `fee` to the block author's pending fees. Both spends route through
/// here so they cannot drift apart.
///
/// The caller must have resolved `asset_id` already: this writes a
/// `PendingFees` entry unconditionally.
pub fn credit_fee<T: Config>(asset_id: u32, fee: u128) -> Result<(), Error<T>> {
	let validator = T::BlockAuthor::get().ok_or(Error::<T>::FeeRecipientUnavailable)?;
	PendingFees::<T>::mutate(&validator, asset_id, |pending| {
		*pending = pending.saturating_add(fee)
	});
	Pallet::<T>::deposit_event(Event::FeeCredited {
		validator,
		asset_id,
		amount: fee,
	});
	Ok(())
}

pub struct FeeOperation;

impl FeeOperation {
	/// Pay `amount` of `validator`'s pending fees out of the pool to it.
	///
	/// No proof: the transfer is public and bounded by the validator's own
	/// pending balance. The fee tokens stayed in the pool when they were
	/// credited, so the ledger drops by `amount` now.
	pub fn claim<T: Config>(
		validator: T::AccountId,
		asset_id: u32,
		amount: BalanceOf<T>,
	) -> DispatchResult {
		// An unverified asset is frozen: no outflow at all, fees included.
		AssetOperation::ensure_movable::<T>(asset_id)?;
		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);
		ensure!(
			PoolBalanceRepository::get_asset_balance::<T>(asset_id) >= amount,
			Error::<T>::InsufficientPoolBalance
		);

		let amount_u128: u128 = amount.saturated_into();
		let pending = PendingFees::<T>::get(&validator, asset_id);
		ensure!(pending >= amount_u128, Error::<T>::InsufficientPendingFees);
		let rest = pending - amount_u128;
		if rest.is_zero() {
			PendingFees::<T>::remove(&validator, asset_id);
		} else {
			PendingFees::<T>::insert(&validator, asset_id, rest);
		}

		T::Currency::transfer(
			&Pallet::<T>::pool_account_id(),
			&validator,
			amount,
			ExistenceRequirement::AllowDeath,
		)?;
		PoolBalanceRepository::decrease_balance::<T>(asset_id, amount);

		Pallet::<T>::deposit_event(Event::FeesClaimed {
			validator,
			asset_id,
			amount: amount_u128,
		});
		Ok(())
	}
}
