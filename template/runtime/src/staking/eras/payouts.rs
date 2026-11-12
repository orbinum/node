// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Staking as `pallet-auto-payout` pays it: the eras that closed, their
//! validators' pages, and paying a page exactly as `payout_stakers_by_page` would.

use crate::{
	economy::AutoPayoutAccount,
	staking::{
		params::{HISTORY_DEPTH, MAX_EXPOSURE_PAGE_SIZE},
		HeavyBlocks, HEAVY_BLOCK_READS,
	},
	AccountId, BlockNumber, Runtime, RuntimeCall, RuntimeOrigin,
};
use alloc::vec::Vec;
use frame_support::{
	dispatch::{DispatchClass, GetDispatchInfo},
	storage::with_storage_layer,
	traits::{Contains, Get},
	weights::Weight,
};
use pallet_auto_payout::{EraIndex, EraPayouts, Page, PayoutOutcome, ValidatorPages};
use pallet_staking_async::WeightInfo;
use sp_runtime::{
	traits::{Dispatchable, Zero},
	DispatchError,
};

/// Part of `frame_system::Config::BaseCallFilter`: a `staking.bond` paying its
/// rewards to the deprecated `Controller` destination is refused, as
/// `set_payee` refuses it; staking would pay the stash with a defensive error
/// on every page.
pub struct NoControllerPayee;

impl Contains<RuntimeCall> for NoControllerPayee {
	fn contains(call: &RuntimeCall) -> bool {
		#[allow(deprecated)]
		let controller = matches!(
			call,
			RuntimeCall::Staking(pallet_staking_async::Call::bond {
				payee: pallet_staking_async::RewardDestination::Controller,
				..
			})
		);
		!controller
	}
}

pub struct StakingPayouts;

impl EraPayouts<AccountId, BlockNumber> for StakingPayouts {
	fn active_era() -> Option<EraIndex> {
		pallet_staking_async::ActiveEra::<Runtime>::get().map(|era| era.index)
	}

	fn planned_era() -> Option<EraIndex> {
		pallet_staking_async::CurrentEra::<Runtime>::get()
	}

	fn history_depth() -> u32 {
		HISTORY_DEPTH
	}

	fn page_size() -> u32 {
		MAX_EXPOSURE_PAGE_SIZE
	}

	/// The era's exposures, as staking pages them: a validator without
	/// nominators still has one page for its own stake.
	fn era_validators(era: EraIndex, max: u32) -> Vec<ValidatorPages<AccountId>> {
		pallet_staking_async::ErasStakersOverview::<Runtime>::iter_prefix(era)
			.take(max as usize)
			.filter_map(|(stash, overview)| {
				let pages = if overview.page_count == 0 && !overview.own.is_zero() {
					1
				} else {
					overview.page_count
				};
				(pages > 0).then_some(ValidatorPages {
					stash,
					pages,
					nominators: overview.nominator_count,
				})
			})
			.collect()
	}

	fn page_weight(nominators: u32) -> Weight {
		<Runtime as pallet_staking_async::Config>::WeightInfo::payout_stakers_alive_staked(
			nominators,
		)
	}

	/// Dispatches `payout_stakers_by_page` in its own storage layer: staking
	/// writes the ledger before it finds a page already claimed, and a refusal
	/// must leave nothing behind. It goes through the runtime's call filter, as a
	/// manual claim would: a filter or safe mode that stops payouts stops these too.
	fn pay(era: EraIndex, validator: &AccountId, page: Page) -> (PayoutOutcome, Weight) {
		let call: RuntimeCall = pallet_staking_async::Call::<Runtime>::payout_stakers_by_page {
			validator_stash: validator.clone(),
			era,
			page,
		}
		.into();
		let declared = call.get_dispatch_info().call_weight;
		let origin = RuntimeOrigin::signed(AutoPayoutAccount::get());
		match with_storage_layer(|| call.dispatch(origin)) {
			Ok(info) => (PayoutOutcome::Paid, info.actual_weight.unwrap_or(declared)),
			Err(e) => {
				let (outcome, reads) = classify(era, e.error);
				// A filtered call never ran: staking reports no weight for it.
				let weight = if matches!(outcome, PayoutOutcome::Blocked) {
					Weight::zero()
				} else {
					e.post_info.actual_weight.unwrap_or(declared)
				};
				(outcome, weight.saturating_add(db_reads(reads)))
			}
		}
	}

	/// [`HeavyBlocks`]. Its reads are registered here: the pallet charges
	/// nothing for this call.
	fn is_heavy_block(now: BlockNumber) -> bool {
		frame_system::Pallet::<Runtime>::register_extra_weight_unchecked(
			<Runtime as frame_system::Config>::DbWeight::get().reads(HEAVY_BLOCK_READS),
			DispatchClass::Mandatory,
		);
		HeavyBlocks::contains(&now)
	}
}

fn db_reads(reads: u64) -> Weight {
	<Runtime as frame_system::Config>::DbWeight::get().reads(reads)
}

/// How far a refusal of a page of `era` reaches, and the storage reads telling
/// it took: staking checks the era, then the page, then the validator's ledger,
/// so some refusals hold for every later page (or the whole era) and are better
/// skipped at once than paid for page by page.
///
/// Staking answers `InvalidEraToReward` both for an era out of its history or
/// without a reward, and for a validator without an exposure in the era: only
/// the first drops the era.
pub(crate) fn classify(era: EraIndex, error: DispatchError) -> (PayoutOutcome, u64) {
	use pallet_staking_async::Error;
	let is = |e: Error<Runtime>| error == DispatchError::from(e);
	if error == frame_system::Error::<Runtime>::CallFiltered.into() {
		(PayoutOutcome::Blocked, 0)
	} else if is(Error::AlreadyClaimed) {
		(PayoutOutcome::AlreadyPaid, 0)
	} else if is(Error::InvalidEraToReward) {
		if era_is_payable(era) {
			(PayoutOutcome::ValidatorUnpayable(error), ERA_CHECK_READS)
		} else {
			(PayoutOutcome::EraUnpayable(error), ERA_CHECK_READS)
		}
	} else if is(Error::NotStash) || is(Error::NotController) || is(Error::InvalidPage) {
		(PayoutOutcome::ValidatorUnpayable(error), 0)
	} else {
		(PayoutOutcome::Failed(error), 0)
	}
}

/// Storage reads [`era_is_payable`] makes, at most.
const ERA_CHECK_READS: u64 = 2;

/// Whether staking still pays `era`: within its planned era's history, with a
/// reward. The era-level half of `payout_stakers_by_page`'s checks.
fn era_is_payable(era: EraIndex) -> bool {
	let Some(planned) = pallet_staking_async::CurrentEra::<Runtime>::get() else {
		return false;
	};
	let depth = <Runtime as pallet_staking_async::Config>::HistoryDepth::get();
	era <= planned
		&& era >= planned.saturating_sub(depth)
		&& pallet_staking_async::ErasValidatorReward::<Runtime>::contains_key(era)
}
