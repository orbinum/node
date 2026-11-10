//! Paying pages within a block's budget: starting queued eras, paying each page
//! through staking and acting on how far a refusal reaches.

use crate::{
	Config, Current, EraState, EraStateOf, Event, Pallet, Queue,
	types::{EraPayouts, PayoutOutcome},
};
use frame_support::{pallet_prelude::*, traits::Get, weights::Weight};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Saturating;

impl<T: Config> Pallet<T> {
	/// Pays pages, starting queued eras as needed, while the next step fits
	/// `budget`. Returns the weight used, never more than `budget`.
	pub(super) fn spend(
		now: BlockNumberFor<T>,
		budget: Weight,
		mut current: Option<EraStateOf<T>>,
	) -> Weight {
		let db = Self::db();
		let Some(mut left) = budget.checked_sub(&db.writes(2)) else {
			return Weight::zero();
		};
		let page_size = T::Payouts::page_size();
		let mut queue = None;
		let mut oldest = None;
		let mut changed = false;

		loop {
			let Some(state) = current.as_mut() else {
				let queue = match queue.as_mut() {
					Some(queue) => queue,
					None => {
						if left.any_lt(db.reads(1)) {
							break;
						}
						left.saturating_reduce(db.reads(1));
						queue.insert(Queue::<T>::get())
					}
				};
				let Some(&era) = queue.first() else {
					break;
				};
				let first_payable = match oldest {
					Some(era) => era,
					None => {
						if left.any_lt(db.reads(1)) {
							break;
						}
						left.saturating_reduce(db.reads(1));
						*oldest.insert(T::Payouts::planned_era().map_or(0, Self::oldest_payable))
					}
				};
				// Planning the next era took the oldest one out of staking's history.
				if era < first_payable {
					queue.remove(0);
					Self::deposit_event(Event::EraExpired { era });
					changed = true;
					continue;
				}
				let start = Self::start_era_weight();
				if left.any_lt(start) {
					break;
				}
				left.saturating_reduce(start);
				queue.remove(0);
				let validators = BoundedVec::truncate_from(T::Payouts::era_validators(
					era,
					T::MaxValidators::get(),
				));
				let state = EraState::new(era, validators, now, page_size, T::Payouts::page_weight);
				Self::deposit_event(Event::EraStarted {
					era,
					validators: state.validators.len() as u32,
					pages: state.pages(),
				});
				current = Some(state);
				changed = true;
				continue;
			};

			let Some((stash, page, nominators)) = state
				.next()
				.map(|(v, page)| (v.stash.clone(), page, v.nominators_on(page, page_size)))
			else {
				Self::deposit_event(Event::EraPaid {
					era: state.era,
					blocks: now.saturating_sub(state.started),
				});
				current = None;
				changed = true;
				continue;
			};

			let estimate = T::Payouts::page_weight(nominators);
			if left.any_lt(estimate) {
				break;
			}
			let era = state.era;
			let (outcome, actual) = T::Payouts::pay(era, &stash, page);
			// Charged its estimate, whatever staking reports: its refund counts only
			// the nominators it paid, not those it read and paid nothing (payee
			// `None`), so the actual weight can understate the work. A call the
			// filter stopped did no work.
			let charge = if matches!(outcome, PayoutOutcome::Blocked) {
				actual.min(estimate)
			} else {
				estimate
			};
			left.saturating_reduce(charge);
			match outcome {
				// Governance stopped the call: it is not the page's fault, so it stays
				// next, and the rest of the block's budget waits with it.
				PayoutOutcome::Blocked => break,
				PayoutOutcome::Paid | PayoutOutcome::AlreadyPaid => {
					state.advance(estimate.ref_time())
				}
				PayoutOutcome::Failed(error) => {
					state.advance(estimate.ref_time());
					Self::deposit_event(Event::PayoutSkipped {
						era,
						validator: stash,
						page,
						error,
					});
				}
				// One event for the validator: its later pages would fail the same way.
				PayoutOutcome::ValidatorUnpayable(error) => {
					state.skip_validator(page_size, T::Payouts::page_weight);
					Self::deposit_event(Event::PayoutSkipped {
						era,
						validator: stash,
						page,
						error,
					});
				}
				PayoutOutcome::EraUnpayable(_) => {
					Self::deposit_event(Event::EraExpired { era });
					current = None;
				}
			}
			changed = true;
		}

		if changed {
			match &current {
				Some(state) => Current::<T>::put(state),
				None => Current::<T>::kill(),
			}
			if let Some(queue) = queue {
				Queue::<T>::put(queue);
			}
		}
		budget.saturating_sub(left)
	}
}
