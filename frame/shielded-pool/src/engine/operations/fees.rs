// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Spend fees: crediting them to the block author and paying them out.
//!
//! A spend's fee never leaves the pool when the spend executes: it is recorded
//! in `PendingFees` for the validator that authored the block, and leaves the
//! pool only when that validator claims it.

use crate::{
	operations::assets::AssetOperation,
	pallet::{BalanceOf, Config, Error, Event, Pallet, PendingFees},
	storage::{AssetRepository, PoolBalanceRepository},
	types::{AssetBackend, BoundActions},
};
use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use sp_runtime::{SaturatedConversion, traits::Zero};

/// Credit `fee` to the block author's pending fees. Every spend routes through
/// here so they cannot drift apart.
///
/// A fee in a pallet-backed asset is redeemed at once for the author
/// (`BoundActions::redeem_fees`), as `claim_fees` would: its units leave the
/// pool's ledger and its issuing pallet pays the author, so they never linger
/// in the asset's supply. If the pallet cannot redeem it now (dust, a full
/// queue), it is credited to `PendingFees` like any other fee.
///
/// The caller must have resolved `asset_id` already.
pub fn credit_fee<T: Config>(asset_id: u32, fee: u128) -> Result<(), Error<T>> {
	let validator = T::BlockAuthor::get().ok_or(Error::<T>::FeeRecipientUnavailable)?;
	let pallet_backed = AssetRepository::get_asset::<T>(asset_id)
		.is_some_and(|asset| matches!(asset.backend, AssetBackend::Pallet(_)));
	if pallet_backed {
		let redeemed =
			frame_support::storage::with_transaction(|| match <T::BoundActions as BoundActions<
				T::AccountId,
			>>::redeem_fees(
				&validator, asset_id, fee
			) {
				Ok(()) => frame_support::storage::TransactionOutcome::Commit(Ok(())),
				Err(error) => frame_support::storage::TransactionOutcome::Rollback(Err(error)),
			});
		if redeemed.is_ok() {
			PoolBalanceRepository::decrease_balance::<T>(asset_id, fee.saturated_into());
			Pallet::<T>::deposit_event(Event::FeesClaimed {
				validator,
				asset_id,
				amount: fee,
			});
			return Ok(());
		}
	}
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

/// The smallest fee a spend of `asset_id` pays, in units of that asset: the
/// native `MinSpendFee`, or what the pallet issuing the asset sets.
pub fn min_fee<T: Config>(asset_id: u32) -> Result<u128, Error<T>> {
	let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
	match asset.backend {
		AssetBackend::Native => Ok(T::MinSpendFee::get()),
		AssetBackend::Pallet(_) => {
			<T::BoundActions as BoundActions<T::AccountId>>::min_fee(asset_id)
				.ok_or(Error::<T>::AssetNotSupported)
		}
	}
}

/// The pool priority of a spend paying `fee` of `asset_id`: its value in native
/// units, so a fee in a pallet-backed asset buys no more priority than the same
/// value in ORB. A fee in an asset with no floor buys none.
pub fn priority<T: Config>(asset_id: u32, fee: u128) -> u64 {
	let native = match AssetRepository::get_asset::<T>(asset_id).map(|asset| asset.backend) {
		Some(AssetBackend::Native) => fee,
		Some(AssetBackend::Pallet(_)) => min_fee::<T>(asset_id)
			.ok()
			.and_then(|floor| {
				sp_runtime::helpers_128bit::multiply_by_rational_with_rounding(
					fee,
					T::MinSpendFee::get(),
					floor.max(1),
					sp_runtime::Rounding::Down,
				)
			})
			.unwrap_or_default(),
		None => 0,
	};
	native.saturated_into()
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
		let backend = AssetRepository::get_asset::<T>(asset_id)
			.ok_or(Error::<T>::InvalidAssetId)?
			.backend;
		if backend == AssetBackend::Native {
			// An unverified asset is frozen: no outflow at all, fees included.
			AssetOperation::ensure_movable::<T>(asset_id)?;
		}
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

		match backend {
			AssetBackend::Native => T::Currency::transfer(
				&Pallet::<T>::pool_account_id(),
				&validator,
				amount,
				ExistenceRequirement::AllowDeath,
			)?,
			// The issuing pallet pays their value; the units are burned here.
			AssetBackend::Pallet(_) => {
				<T::BoundActions as BoundActions<T::AccountId>>::redeem_fees(
					&validator,
					asset_id,
					amount_u128,
				)?
			}
		}
		PoolBalanceRepository::decrease_balance::<T>(asset_id, amount);

		Pallet::<T>::deposit_event(Event::FeesClaimed {
			validator,
			asset_id,
			amount: amount_u128,
		});
		Ok(())
	}
}
