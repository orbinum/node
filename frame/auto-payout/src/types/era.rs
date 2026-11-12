// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The era being paid: its validators, where payment stands and how much work
//! it has left.

use super::staking::{EraIndex, Page, ValidatorPages};
use frame_support::{
	CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound, pallet_prelude::*, weights::Weight,
};
use scale_info::TypeInfo;

#[derive(
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	CloneNoBound,
	PartialEqNoBound,
	EqNoBound,
	DebugNoBound
)]
#[scale_info(skip_type_params(MaxValidators))]
#[codec(mel_bound(AccountId: MaxEncodedLen, BlockNumber: MaxEncodedLen))]
pub struct EraState<AccountId, BlockNumber, MaxValidators: Get<u32>>
where
	AccountId: Clone + PartialEq + Eq + core::fmt::Debug,
	BlockNumber: Clone + PartialEq + Eq + core::fmt::Debug,
{
	pub era: EraIndex,
	pub validators: BoundedVec<ValidatorPages<AccountId>, MaxValidators>,
	/// The next page to pay: `validators[validator]`, page `page`.
	pub validator: u32,
	pub page: Page,
	/// Ref-time of every page, as priced when the era started.
	pub work: u64,
	/// Ref-time of the pages paid or skipped so far.
	pub done: u64,
	/// When payment of the era started.
	pub started: BlockNumber,
	/// Whether `BehindSchedule` was reported for it.
	pub reported_behind: bool,
}

impl<AccountId, BlockNumber, MaxValidators> EraState<AccountId, BlockNumber, MaxValidators>
where
	AccountId: Clone + PartialEq + Eq + core::fmt::Debug,
	BlockNumber: Clone + PartialEq + Eq + core::fmt::Debug,
	MaxValidators: Get<u32>,
{
	/// Starts `era` with `validators`, pricing their pages with `page_weight`
	/// (a few calls per validator, see [`ValidatorPages::work`]). Validators with
	/// no page are dropped.
	pub fn new(
		era: EraIndex,
		validators: BoundedVec<ValidatorPages<AccountId>, MaxValidators>,
		started: BlockNumber,
		page_size: u32,
		page_weight: impl Fn(u32) -> Weight,
	) -> Self {
		let mut validators = validators;
		validators.retain(|v| v.pages > 0);
		let work = validators.iter().fold(0u64, |sum, v| {
			sum.saturating_add(v.work(0, page_size, &page_weight))
		});
		Self {
			era,
			validators,
			validator: 0,
			page: 0,
			work,
			done: 0,
			started,
			reported_behind: false,
		}
	}

	/// The next page to pay, or `None` once every page is done.
	pub fn next(&self) -> Option<(&ValidatorPages<AccountId>, Page)> {
		self.validators
			.get(self.validator as usize)
			.map(|v| (v, self.page))
	}

	/// Marks the next page done, with `cost` ref-time of progress.
	pub fn advance(&mut self, cost: u64) {
		self.done = self.done.saturating_add(cost).min(self.work);
		let pages = self.next().map_or(0, |(v, _)| v.pages);
		if self.page.saturating_add(1) < pages {
			self.page += 1;
		} else {
			self.validator = self.validator.saturating_add(1);
			self.page = 0;
		}
	}

	/// Marks the next validator's remaining pages done, priced with `page_weight`
	/// as when the era started, and moves to the following validator.
	pub fn skip_validator(&mut self, page_size: u32, page_weight: impl Fn(u32) -> Weight) {
		if let Some((v, page)) = self.next() {
			let rest = v.work(page, page_size, page_weight);
			self.done = self.done.saturating_add(rest).min(self.work);
		}
		self.validator = self.validator.saturating_add(1);
		self.page = 0;
	}

	pub fn is_done(&self) -> bool {
		self.next().is_none()
	}

	/// Pages in the era.
	pub fn pages(&self) -> u32 {
		self.validators
			.iter()
			.fold(0u32, |sum, v| sum.saturating_add(v.pages))
	}
}
