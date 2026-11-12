// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The election (`pallet-paged-election`) and the voter list it reads voters from.

use super::staking::{MaxActiveValidators, MaxElectingVoters};
use crate::{
	configs::governance::StakingAdmin,
	staking::{
		bags,
		params::{
			ELECTION_PAGES, ELECTION_ROUND_BUDGET, MAX_VALIDATOR_CANDIDATES,
			VOTER_SNAPSHOT_PER_BLOCK,
		},
	},
	Runtime, RuntimeEvent, Staking,
};
use frame_election_provider_support::VoteWeight;
use frame_support::{parameter_types, traits::ConstU32};
use sp_runtime::Perbill;

// Election

parameter_types! {
	pub const ElectionPages: u32 = ELECTION_PAGES;
	pub const VoterSnapshotPerBlock: u32 = VOTER_SNAPSHOT_PER_BLOCK;
	pub const MaxElectionTargets: u32 = MAX_VALIDATOR_CANDIDATES;
	pub const ElectionRoundBudget: Perbill = ELECTION_ROUND_BUDGET;
}

impl pallet_paged_election::Config for Runtime {
	type DataProvider = Staking;
	type Pages = ElectionPages;
	type VoterSnapshotPerBlock = VoterSnapshotPerBlock;
	type MaxTargets = MaxElectionTargets;
	type MaxWinnersPerPage = MaxActiveValidators;
	type MaxBackersPerWinner = VoterSnapshotPerBlock;
	type MaxBackersPerWinnerFinal = MaxElectingVoters;
	type RoundBudget = ElectionRoundBudget;
	/// Aborts a stuck election; the plan is then reset and planned again.
	type AdminOrigin = StakingAdmin;
	type WeightInfo = pallet_paged_election::weights::SubstrateWeight<Runtime>;
}

// Voter list

parameter_types! {
	pub const BagThresholds: &'static [VoteWeight] = &bags::THRESHOLDS;
}

impl pallet_bags_list::Config<pallet_bags_list::Instance1> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ScoreProvider = Staking;
	type WeightInfo = crate::weights::pallet_bags_list::SubstrateWeight<Runtime>;
	type BagThresholds = BagThresholds;
	/// Staked rewards change scores without touching the bond; re-bag a few
	/// accounts per block so the snapshot's order stays close to stake.
	type MaxAutoRebagPerBlock = ConstU32<10>;
	type Score = VoteWeight;
}
