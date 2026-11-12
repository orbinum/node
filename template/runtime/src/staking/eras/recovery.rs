// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Recovery from an era plan that can no longer start.
//!
//! Staking plans era `n + 1` by starting an election. The elected set goes to
//! rc-client, then to ah-client, then into a session, and the era starts when a
//! session report says the set is active. If the election fails (every page
//! fetch errors) or its set is dropped on the way (smaller than ah-client's
//! `MinimumValidatorSetSize`, or undeliverable), no report ever activates era
//! `n + 1`. Staking then waits for it forever: `CurrentEra` stays at `n + 1` and
//! no election starts again.
//!
//! [`reset_stalled_plan`] runs before staking reads each session report. When
//! an era is planned and nothing holds its set (the election running or waiting
//! to be fetched, rc-client, ah-client or the session about to activate it), it
//! removes whatever the failed election stored for the planned era, then resets
//! the plan: `CurrentEra` back to the active era and staking's election
//! bookkeeping cleared (including the voter cursor of a snapshot cut short and
//! the page it was fetching). It emits `PagedElection::EraPlanReset`. The report
//! it precedes finds the planning deadline past, so staking plans the era again
//! and a new election starts in the same block.
//!
//! Staking fetching pages holds nothing once the election is gone: it fetches
//! only while the election reports ready, so a page left to fetch from an idle
//! election would wait forever.
//!
//! A set dropped after staking stored it leaves up to an era's exposures (some
//! 25 000 pages), more than a block can remove. Each report removes at most
//! [`CLEAR_PER_REPORT`] items; what is left is removed from `on_idle`
//! (`staking::pruning::StalledPlan`), and the report after that resets the plan.
//!
//! Meanwhile the current validators keep their seats and the active era runs
//! on, its exposures intact. Governance can hold retries with
//! `staking.force_no_eras`.

use super::pruning;
use crate::{AccountId, Runtime};
use frame_election_provider_support::{ElectionProvider, SortedListProvider};
use frame_support::weights::Weight;
use pallet_staking_async as staking;
use pallet_staking_async_ah_client as ah_client;
use pallet_staking_async_rc_client as rc_client;

type Election = <Runtime as staking::Config>::ElectionProvider;
type VoterList = <Runtime as staking::Config>::VoterList;

/// Storage reads [`stalled_plan`] makes, at most: staking's `ActiveEra` and
/// `CurrentEra`, the election's phase (`ElectionProvider::status`), rc-client's
/// `OutgoingValidatorSet`, and ah-client's `ValidatorSet`,
/// `IncompleteValidatorSetReport` and `NextSessionChangesValidators`.
/// [`reset_stalled_plan`] reads nothing more before it writes. Counted by hand
/// until a benchmark replaces it.
const CHECK_READS: u64 = 7;

/// Most items of a stalled plan's data one session report removes: ~0.13 s
/// at RocksDB's weights, on top of the report's own work.
pub const CLEAR_PER_REPORT: u32 = 1_000;

/// The active and planned eras when the era staking planned can no longer
/// start: one is planned, the report does not activate it, and nothing on its
/// way holds a set for it. Staking's next page to fetch (`NextElectionPage`)
/// holds nothing once the election is idle.
fn stalled_plan(
	report: &rc_client::SessionReport<AccountId>,
) -> Option<(sp_staking::EraIndex, sp_staking::EraIndex)> {
	let active = staking::ActiveEra::<Runtime>::get().map_or(0, |era| era.index);
	let planned = staking::CurrentEra::<Runtime>::get().unwrap_or(active);
	let stalled = planned > active
		&& report.activation_timestamp.is_none()
		&& Election::status().is_err()
		&& !rc_client::OutgoingValidatorSet::<Runtime>::exists()
		&& !ah_client::ValidatorSet::<Runtime>::exists()
		&& !ah_client::IncompleteValidatorSetReport::<Runtime>::exists()
		&& !ah_client::NextSessionChangesValidators::<Runtime>::exists();
	stalled.then_some((active, planned))
}

/// Whether the plan is stalled ([`stalled_plan`]).
#[cfg(test)]
pub fn plan_is_stalled(report: &rc_client::SessionReport<AccountId>) -> bool {
	stalled_plan(report).is_some()
}

/// Resets a stalled era plan once its data is removed (see the module docs).
/// Returns the weight used, at most [`CLEAR_PER_REPORT`] items' removal over
/// the reads and the reset's writes.
pub fn reset_stalled_plan(report: &rc_client::SessionReport<AccountId>) -> Weight {
	let db = <Runtime as frame_system::Config>::DbWeight::get();
	let mut weight = db.reads(CHECK_READS);
	let Some((active, planned)) = stalled_plan(report) else {
		return weight;
	};

	let (used, cleared) = pruning::Pallet::<Runtime>::clear_plan(planned, CLEAR_PER_REPORT);
	weight.saturating_accrue(used.saturating_add(db.writes(1)));
	if !cleared {
		log::warn!(
			target: "runtime::staking",
			"era {planned} will not start; removing its data before planning it again",
		);
		pruning::StalledPlan::<Runtime>::put(planned);
		return weight;
	}
	pruning::StalledPlan::<Runtime>::kill();
	log::warn!(
		target: "runtime::staking",
		"era {planned} will not start: its election failed or its set was dropped; planning it again",
	);

	staking::CurrentEra::<Runtime>::put(active);
	staking::NextElectionPage::<Runtime>::kill();
	staking::ElectableStashes::<Runtime>::kill();
	staking::VoterSnapshotStatus::<Runtime>::kill();
	VoterList::unlock();
	staking::ErasTotalStake::<Runtime>::remove(planned);
	staking::ErasSumValidatorIncentiveWeight::<Runtime>::remove(planned);
	weight.saturating_accrue(db.writes(7));

	frame_system::Pallet::<Runtime>::deposit_event(
		pallet_paged_election::Event::<Runtime>::EraPlanReset { era: planned },
	);
	weight
}
