// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The validators' commission ceiling: staking's `MaxCommission`, set by
//! governance (`staking.set_max_commission`) and 100 % (none) by default.
//!
//! Staking checks it only when a validator sets its prefs. [`clamp_to_ceiling`]
//! runs before staking reads each session report and lowers every candidate
//! above the ceiling to it, as staking's `force_apply_min_commission` does for
//! one, so the next era plan already uses the clamped commission.
//!
//! A floor (`MinCommission`) above the ceiling, which root's
//! `set_staking_configs` allows, refuses every new commission; the clamp still
//! lowers candidates to the ceiling, below that floor, since the ceiling is what
//! the snapshot filter enforces: they stay electable until governance fixes
//! the pair.

use crate::{AccountId, Runtime};
use alloc::vec::Vec;
use frame_support::weights::Weight;
use pallet_staking_async::{self as staking, ValidatorPrefs};
use sp_runtime::Perbill;

/// Clamps every candidate whose commission is above `MaxCommission` to it and
/// emits `ValidatorPrefsSet` for each. Reads at most the `MaxTargets` candidates
/// the election reads (the candidacy check keeps them within it; only root's
/// `sudo_as` gets past it), so the session report's weight stays bounded
/// whatever `MaxValidatorsCount` is. Returns the weight used: the ceiling's
/// read and, below 100 %, a read per candidate and a read and a write per
/// clamped one.
pub fn clamp_to_ceiling() -> Weight {
	let db = <Runtime as frame_system::Config>::DbWeight::get();
	let max = staking::MaxCommission::<Runtime>::get();
	if max == Perbill::one() {
		return db.reads(1);
	}
	let bound = <Runtime as pallet_paged_election::Config>::MaxTargets::get();
	let mut candidates = 0u64;
	let mut above: Vec<(AccountId, ValidatorPrefs)> = Vec::new();
	for (stash, prefs) in staking::Validators::<Runtime>::iter() {
		if candidates == u64::from(bound) {
			log::error!(
				target: "runtime::staking",
				"more than {bound} validator candidates; the commission clamp reads {bound}",
			);
			break;
		}
		candidates += 1;
		if prefs.commission > max {
			above.push((stash, prefs));
		}
	}
	let clamped = above.len() as u64;
	for (stash, mut prefs) in above {
		prefs.commission = max;
		staking::Validators::<Runtime>::insert(&stash, &prefs);
		frame_system::Pallet::<Runtime>::deposit_event(
			staking::Event::<Runtime>::ValidatorPrefsSet { stash, prefs },
		);
	}
	if clamped > 0 {
		log::info!(
			target: "runtime::staking",
			"{clamped} validator(s) clamped to the commission ceiling {max:?}",
		);
	}
	// The ceiling, each candidate, and the iteration's last read (no next key,
	// or the first candidate past the bound). `Validators` is counted: each
	// insert also reads whether the key exists.
	db.reads_writes(
		candidates.saturating_add(2).saturating_add(clamped),
		clamped,
	)
}
