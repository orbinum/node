// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the pallet needs from staking, behind one trait so the pacing and the
//! queue can be tested without a staking pallet, and what paying a page returns.

use frame_support::{pallet_prelude::*, weights::Weight};
use scale_info::TypeInfo;
use sp_runtime::DispatchError;

/// An era's index, as staking counts them.
pub type EraIndex = u32;

/// A page of an era's exposure of one validator: its nominators, in chunks of
/// [`EraPayouts::page_size`].
pub type Page = u32;

/// One elected validator of an era and how many pages its payout takes.
#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
pub struct ValidatorPages<AccountId> {
	pub stash: AccountId,
	/// Pages to pay; at least 1 when the validator has its own stake exposed.
	pub pages: Page,
	/// Nominators backing it in the era, across all its pages.
	pub nominators: u32,
}

impl<AccountId> ValidatorPages<AccountId> {
	/// Nominators on `page`: full pages first, the remainder on the last.
	pub fn nominators_on(&self, page: Page, page_size: u32) -> u32 {
		let before = page.saturating_mul(page_size);
		self.nominators.saturating_sub(before).min(page_size)
	}

	/// Ref-time of pages `from..pages`, priced with `page_weight`. Pages come in
	/// three kinds (full, the remainder, none), so it calls `page_weight` at most
	/// three times, however many pages there are.
	pub fn work(&self, from: Page, page_size: u32, page_weight: impl Fn(u32) -> Weight) -> u64 {
		let count = self.pages.saturating_sub(from);
		if count == 0 {
			return 0;
		}
		let (full_pages, remainder) = match page_size {
			0 => (0, 0),
			size => (self.nominators / size, self.nominators % size),
		};
		let full = full_pages.saturating_sub(from).min(count);
		let partial = u32::from(remainder > 0 && full_pages >= from && full_pages < self.pages);
		let empty = count - full - partial;
		let cost = |pages: u32, nominators: u32| {
			if pages == 0 {
				0
			} else {
				page_weight(nominators)
					.ref_time()
					.saturating_mul(u64::from(pages))
			}
		};
		cost(full, page_size)
			.saturating_add(cost(partial, remainder))
			.saturating_add(cost(empty, 0))
	}
}

/// How paying one page went.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PayoutOutcome {
	/// The validator and the page's nominators were paid.
	Paid,
	/// Someone claimed the page first (`payout_stakers` is permissionless).
	AlreadyPaid,
	/// Staking refused the page; it is skipped.
	Failed(DispatchError),
	/// Staking refused the page for a reason the validator's later pages share
	/// (it is no longer a stash, or the page is past its exposure): they are all
	/// skipped, instead of each costing a refused call.
	ValidatorUnpayable(DispatchError),
	/// Staking no longer pays the era (it left the claimable range): the era is
	/// dropped, instead of each of its pages costing a refused call.
	EraUnpayable(DispatchError),
	/// The runtime does not allow the call right now (a call filter or safe
	/// mode): nothing more is paid this block, and the page is tried again later.
	Blocked,
}

/// Staking, as the pallet uses it.
///
/// Weight contract: [`EraPayouts::active_era`] and [`EraPayouts::planned_era`]
/// cost one storage read each, [`EraPayouts::era_validators`] at most `max + 1`,
/// and [`EraPayouts::is_heavy_block`] none; the pallet charges those bounds.
pub trait EraPayouts<AccountId, BlockNumber> {
	/// The era staking is in; the eras before it are payable.
	fn active_era() -> Option<EraIndex>;

	/// The latest era staking planned: the active one, or the next once its
	/// election starts. Staking pays eras from `planned - history_depth` on.
	fn planned_era() -> Option<EraIndex>;

	/// Eras staking keeps payable before pruning them.
	fn history_depth() -> u32;

	/// Nominators per page of an exposure.
	fn page_size() -> u32;

	/// The validators elected in `era`, at most `max`, in a fixed order.
	fn era_validators(era: EraIndex, max: u32) -> alloc::vec::Vec<ValidatorPages<AccountId>>;

	/// Weight of paying a page of `nominators`, as staking prices it.
	fn page_weight(nominators: u32) -> Weight;

	/// Pays one page of `validator`'s exposure in `era`. Returns how it went and
	/// the weight it took, never more than [`EraPayouts::page_weight`] of its
	/// nominators. Must leave no state behind when it fails.
	fn pay(era: EraIndex, validator: &AccountId, page: Page) -> (PayoutOutcome, Weight);

	/// Blocks the runtime already loads (session rotation, the election's
	/// work), where the pallet pays nothing.
	fn is_heavy_block(now: BlockNumber) -> bool;
}
